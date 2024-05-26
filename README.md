# Self-Deletion of Executable Files in Windows using Native API

https://github.com/pyramidyon/Native-Self-File-Melting/assets/88564775/46cd1062-46d3-48d1-906c-7b0dbb2bd08b

This program leverages Windows Native API functions to achieve the self-deletion of the executable file from which it runs. 
By manipulating file system operations directly through the OS's lower-level interfaces, 
this method ensures a more robust and secure deletion compared to standard file deletion techniques.

### Why? 
Windows locks the executable file of a running process and in the use case of malware we want too increase stealth and avoid faster detection rates.

### Proof of Concept
- Retrieves the executable's file path directly from the Process Environment Block (PEB)
- Manages memory with using NtAllocateVirtualMemory and NtFreeVirtualMemory, for real mal devs replace with ...;)
- Executes file deletion by first renaming the file stream, then marking the file for deletion using direct system calls to manipulate file states.

