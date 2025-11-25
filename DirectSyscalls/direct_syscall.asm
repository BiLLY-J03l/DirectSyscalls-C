.data 
extern dwNtOpenProcessSSN:DWORD
extern dwNtAllocateVirtualMemorySSN:DWORD
extern dwNtWriteVirtualMemorySSN:DWORD
extern dwNtProtectVirtualMemorySSN:DWORD
extern dwNtCreateThreadExSSN:DWORD
extern dwNtWaitForSingleObjectSSN:DWORD
extern dwNtFreeVirtualMemorySSN:DWORD
extern dwNtCloseSSN:DWORD

.code
NtOpenProcess proc 
		mov r10, rcx
		mov eax, dwNtOpenProcessSSN
		syscall                         
		ret                             
NtOpenProcess endp

NtAllocateVirtualMemory proc    
		mov r10, rcx
		mov eax, dwNtAllocateVirtualMemorySSN      
		syscall                        
		ret                             
NtAllocateVirtualMemory endp

NtWriteVirtualMemory proc 
		mov r10, rcx
		mov eax, dwNtWriteVirtualMemorySSN      
		syscall                        
		ret                             
NtWriteVirtualMemory endp 

NtProtectVirtualMemory proc
		mov r10, rcx
		mov eax, dwNtProtectVirtualMemorySSN       
		syscall
		ret                             
NtProtectVirtualMemory endp

NtCreateThreadEx proc 
		mov r10, rcx
		mov eax, dwNtCreateThreadExSSN      
		syscall                        
		ret                             
NtCreateThreadEx endp 

NtWaitForSingleObject proc 
		mov r10, rcx
		mov eax, dwNtWaitForSingleObjectSSN      
		syscall                        
		ret                             
NtWaitForSingleObject endp 

NtFreeVirtualMemory proc
		mov r10, rcx
		mov eax, dwNtFreeVirtualMemorySSN      
		syscall
		ret                             
NtFreeVirtualMemory endp

NtClose proc 
		mov r10, rcx
		mov eax, dwNtCloseSSN      
		syscall                        
		ret                             
NtClose endp 
end