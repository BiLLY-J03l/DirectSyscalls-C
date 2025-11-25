#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
	
	if (argc < 2) {
		printf("[x] Usage %s <PID>\n", argv[0]);
		return -1;
	}
	
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS,TRUE,(DWORD) atoi(argv[1]));

	if (hProc == NULL) { printf("[x] OpenProcess Failed, err -> %d", GetLastError()); return -1; }
	return 0;

}