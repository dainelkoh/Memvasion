#include <ntifs.h>
#include <ntddk.h>

// IOCTL Code
#define IOCTL_ENUMERATE_VAD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Constants
#define VAD_ROOT_OFFSET 0x628 // Offset for VadRoot in _EPROCESS on Windows 10 1709

// MMVAD_SHORT structure (partial)
typedef struct _MMVAD_SHORT {
	struct _MMVAD_SHORT* LeftChild;  // Pointer to left child in VAD tree
	struct _MMVAD_SHORT* RightChild; // Pointer to right child in VAD tree
	ULONG64 StartingVpn;             // Starting virtual page number
	ULONG64 EndingVpn;               // Ending virtual page number
	ULONG64 Flags;                   // Protection flags (optional: MMVAD_FLAGS)
} MMVAD_SHORT, *PMMVAD_SHORT;

typedef struct _HARDWARE_PTE
{
	ULONG64 Valid : 1;
	ULONG64 Write : 1;
	ULONG64 Owner : 1;
	ULONG64 WriteThrough : 1;
	ULONG64 CacheDisable : 1;
	ULONG64 Accessed : 1;
	ULONG64 Dirty : 1;
	ULONG64 LargePage : 1;
	ULONG64 Global : 1;
	ULONG64 CopyOnWrite : 1;
	ULONG64 Prototype : 1;
	ULONG64 reserved0 : 1;
	ULONG64 PageFrameNumber : 36;
	ULONG64 reserved1 : 4;
	ULONG64 SoftwareWsIndex : 11;
	ULONG64 NoExecute : 1;
} HARDWARE_PTE, *PHARDWARE_PTE;


// Prototypes
void EnumerateVadTree(PEPROCESS targetProcess);
void TraverseVad(PMMVAD_SHORT vadNode, ULONG_PTR cr3);
PHARDWARE_PTE WalkPageTables(ULONG_PTR cr3, ULONG64 virtualAddress);
NTSTATUS DeviceIoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);
void UnloadDriver(PDRIVER_OBJECT DriverObject);

// Define symbolic link and device names
#define DEVICE_NAME L"\\Device\\MemoryDriver"
#define SYMBOLIC_LINK_NAME L"\\DosDevices\\MemoryDriver"

// Driver Entry
extern "C"
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DbgPrint("DriverEntry: MemoryDriver is loading...\n");

	// Create device object
	UNICODE_STRING deviceName;
	RtlInitUnicodeString(&deviceName, DEVICE_NAME);
	PDEVICE_OBJECT deviceObject = nullptr;
	NTSTATUS status = IoCreateDevice(
		DriverObject,
		0,
		&deviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&deviceObject
	);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("DriverEntry: Failed to create device object (0x%X)\n", status);
		return status;
	}

	// Create symbolic link
	UNICODE_STRING symbolicLinkName;
	RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_LINK_NAME);
	status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("DriverEntry: Failed to create symbolic link (0x%X)\n", status);
		IoDeleteDevice(deviceObject);
		return status;
	}

	DbgPrint("DriverEntry: Device object and symbolic link created successfully.\n");

	// Set up dispatch routines
	DriverObject->MajorFunction[IRP_MJ_CREATE] = [](PDEVICE_OBJECT, PIRP Irp) -> NTSTATUS {
		DbgPrint("IrpCreateCloseHandler: Received create request.\n");
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	};

	DriverObject->MajorFunction[IRP_MJ_CLOSE] = [](PDEVICE_OBJECT, PIRP Irp) -> NTSTATUS {
		DbgPrint("IrpCreateCloseHandler: Received close request.\n");
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	};

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControlHandler;

	DriverObject->DriverUnload = UnloadDriver;

	DbgPrint("DriverEntry: Driver loaded successfully.\n");
	return STATUS_SUCCESS;
}

// Unload Routine
void UnloadDriver(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING symbolicLinkName;
	RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_LINK_NAME);

	IoDeleteSymbolicLink(&symbolicLinkName);
	IoDeleteDevice(DriverObject->DeviceObject);

	DbgPrint("UnloadDriver: MemoryDriver has been unloaded.\n");
}

// IOCTL Handler
NTSTATUS DeviceIoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;

	ULONG inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;

	if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_ENUMERATE_VAD)
	{
		if (inputLength < sizeof(ULONG))
		{
			DbgPrint("Input buffer too small.\n");
			status = STATUS_BUFFER_TOO_SMALL;
		}
		else
		{
			ULONG pid = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
			PEPROCESS targetProcess;
			status = PsLookupProcessByProcessId((HANDLE)pid, &targetProcess);
			if (NT_SUCCESS(status))
			{
				EnumerateVadTree(targetProcess);
				ObDereferenceObject(targetProcess);
			}
			else
			{
				DbgPrint("Failed to lookup process.\n");
			}
		}
	}
	else
	{
		DbgPrint("Unknown IOCTL code.\n");
		status = STATUS_INVALID_DEVICE_REQUEST;
	}

	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}


// Retrieve CR3 register
ULONG_PTR GetCr3(PEPROCESS process) {
	return *(ULONG_PTR*)((PUCHAR)process + 0x28); // Offset for DirectoryTableBase in _KPROCESS
}

// Walk page tables and resolve physical address
PHARDWARE_PTE WalkPageTables(ULONG_PTR cr3, ULONG64 virtualAddress) {
	ULONG64 pml4Index = (virtualAddress >> 39) & 0x1FF;
	ULONG64 pdptIndex = (virtualAddress >> 30) & 0x1FF;
	ULONG64 pdIndex = (virtualAddress >> 21) & 0x1FF;
	ULONG64 ptIndex = (virtualAddress >> 12) & 0x1FF;

	PHARDWARE_PTE pml4 = (PHARDWARE_PTE)(cr3 + (pml4Index * sizeof(HARDWARE_PTE)));
	if (!pml4->Valid) return NULL;

	PHARDWARE_PTE pdpt = (PHARDWARE_PTE)((pml4->PageFrameNumber << PAGE_SHIFT) + (pdptIndex * sizeof(HARDWARE_PTE)));
	if (!pdpt->Valid) return NULL;

	PHARDWARE_PTE pd = (PHARDWARE_PTE)((pdpt->PageFrameNumber << PAGE_SHIFT) + (pdIndex * sizeof(HARDWARE_PTE)));
	if (!pd->Valid) return NULL;

	PHARDWARE_PTE pt = (PHARDWARE_PTE)((pd->PageFrameNumber << PAGE_SHIFT) + (ptIndex * sizeof(HARDWARE_PTE)));
	if (!pt->Valid) return NULL;

	return pt;
}

// Enumerate VAD Tree
void EnumerateVadTree(PEPROCESS targetProcess) {
	PMMVAD_SHORT vadRoot = *(PMMVAD_SHORT*)((PUCHAR)targetProcess + VAD_ROOT_OFFSET);
	if (!vadRoot || !MmIsAddressValid(vadRoot)) {
		DbgPrint("Invalid or missing VAD root for process: %p\n", targetProcess);
		return;
	}

	ULONG_PTR cr3 = GetCr3(targetProcess);
	if (!cr3) {
		DbgPrint("Failed to retrieve CR3 for process: %p\n", targetProcess);
		return;
	}

	DbgPrint("Starting VAD tree traversal for process: %p\n", targetProcess);

	KAPC_STATE apcState;
	KeStackAttachProcess(targetProcess, &apcState);

	__try {
		TraverseVad(vadRoot, cr3);
	}
	__finally {
		KeUnstackDetachProcess(&apcState);
	}

	DbgPrint("VAD tree traversal complete.\n");
}

// Traverse VAD Tree and resolve physical addresses
void TraverseVad(PMMVAD_SHORT vadNode, ULONG_PTR cr3) {
	if (!vadNode || !MmIsAddressValid(vadNode)) return;

	if (vadNode->LeftChild)
		TraverseVad(vadNode->LeftChild, cr3);

	ULONG64 startAddress = vadNode->StartingVpn << PAGE_SHIFT;
	ULONG64 endAddress = (vadNode->EndingVpn << PAGE_SHIFT) | (PAGE_SIZE - 1);

	for (ULONG64 address = startAddress; address <= endAddress; address += PAGE_SIZE) {
		PHARDWARE_PTE pte = WalkPageTables(cr3, address);
		if (pte) {
			DbgPrint("Resolved Virtual Address: 0x%llX to PTE: 0x%p\n", address, pte);
		}
		else {
			DbgPrint("Invalid PTE for Virtual Address: 0x%llX\n", address);
		}
	}

	if (vadNode->RightChild)
		TraverseVad(vadNode->RightChild, cr3);
}