#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib,"ntdll.lib")

/*
    Self-Deletion of Executable Files in Windows Using Native API (@pyramidyon)

    Compatibility:
    - The used Native API functions have been supported since early versions of Windows NT, ensuring broad compatibility with Windows environments from Windows 98 onwards.

    Future Enhancements:
    - Consider integrating Rtl Heap Memory functions for potentially more efficient memory management.
    - Explore the use of custom implementations for string and memory handling functions to avoid dependencies on the standard library, potentially reducing the program's footprint and enhancing its performance.
*/

#define NtCurrentProcess() ((HANDLE) -1)

PPEB GetPeb()
{
#if defined(_WIN64)
    return (PPEB)__readgsqword(0x60);
#elif defined(_WIN32)
    return (PPEB)__readfsdword(0x30);
#endif
}

PWCHAR CopyStringW(PWCHAR dest, LPCWSTR src)
{
    if (dest == NULL || src == NULL) return NULL;  // Null pointer safety check

    PWCHAR p = dest;
    while ((*p++ = *src++) != '\0');  // Copy string including the null terminator

    return dest;
}

VOID GetModuleFileNameFromPeb(PWCHAR buffer, DWORD bufferSize)
{
    PPEB peb = GetPeb();
    if (peb != NULL && peb->ProcessParameters != NULL)
    {
        UNICODE_STRING* dosPath = &peb->ProcessParameters->ImagePathName;
        if (dosPath->Buffer != NULL)
        {
            CopyStringW(buffer, dosPath->Buffer);
            buffer[bufferSize - 1] = L'\0'; // Ensure null-termination
        }
    }
}

int main(void)
{
    printf("\n[+] Beginning self-deletion process\n");

    // Define variables for file path, file deletion info, handle, rename info, and stream name
    WCHAR szPath[MAX_PATH * 2] = { 0 };
    FILE_DISPOSITION_INFO Delete = { 0 };
    HANDLE hFile = INVALID_HANDLE_VALUE;
    PFILE_RENAME_INFO pRename = NULL;
    const wchar_t* NewStream = L":google";
    SIZE_T sRename = sizeof(FILE_RENAME_INFO) + (wcslen(NewStream) + 1) * sizeof(wchar_t); // Calculate structure size

    // Allocate memory for FILE_RENAME_INFO structure using NtAllocateVirtualMemory
    PULONG pRenameSize = (PULONG)&sRename; // Cast SIZE_T* to PULONG for size parameter
    NTSTATUS status = NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&pRename, 0, pRenameSize, MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        printf("Error: Failed to allocate memory for rename info: 0x%lx\n", status);
        return FALSE;
    }

    // Clean up some structures
    ZeroMemory(szPath, sizeof(szPath));
    ZeroMemory(&Delete, sizeof(FILE_DISPOSITION_INFO));

    // Mark the file for deletion
    Delete.DeleteFile = TRUE;

    // Get the path of the current executable using custom function
    GetModuleFileNameFromPeb(szPath, MAX_PATH);
    if (szPath[0] == L'\0') {
        printf("Error: Failed to retrieve module file name\n");
        NtFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&pRename, pRenameSize, MEM_RELEASE);
        return FALSE;
    }

    printf("[+] Module file name: %ls\n", szPath);

    // Add "\\?\" prefix to the path for extended length support
    WCHAR szExtendedPath[MAX_PATH * 2] = { 0 };
    swprintf(szExtendedPath, MAX_PATH * 2, L"\\??\\%s", szPath);

    printf("[+] Extended path: %ls\n", szExtendedPath);

    // Initialize object attributes and Unicode string for file path
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING unicodeString;
    IO_STATUS_BLOCK ioStatusBlock;

    RtlInitUnicodeString(&unicodeString, szExtendedPath); // Initialize UNICODE_STRING with extended path
    InitializeObjectAttributes(&objAttr, &unicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL); // Initialize object attributes

    // Open a handle to the current file using NtCreateFile
    status = NtCreateFile(&hFile, DELETE | SYNCHRONIZE, &objAttr, &ioStatusBlock,
        NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE, NULL, 0);

    if (!NT_SUCCESS(status)) {
        printf("Error: Failed to open file for deletion: 0x%lx\n", status);
        NtFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&pRename, pRenameSize, MEM_RELEASE);
        return FALSE;
    }

    // Set the file name in FILE_RENAME_INFO for renaming the stream
    pRename->ReplaceIfExists = FALSE;
    pRename->RootDirectory = NULL;
    pRename->FileNameLength = wcslen(NewStream) * sizeof(wchar_t);
    wcscpy_s(pRename->FileName, wcslen(NewStream) + 1, NewStream);

    // Rename the data stream using NtSetInformationFile
    status = NtSetInformationFile(hFile, &ioStatusBlock, pRename, (ULONG)sRename, 10/* FileRenameInformation */);
    if (!NT_SUCCESS(status)) {
        printf("Error: Failed to rename file stream: 0x%lx\n", status);
        NtClose(hFile);
        NtFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&pRename, pRenameSize, MEM_RELEASE);
        return FALSE;
    }

    printf("[+] File stream renamed successfully\n");

    // Close the file handle before marking for deletion
    NtClose(hFile);

    // Reopen the file for deletion
    status = NtCreateFile(&hFile, DELETE | SYNCHRONIZE, &objAttr, &ioStatusBlock,
        NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE, NULL, 0);

    if (!NT_SUCCESS(status)) {
        printf("Error: Failed to reopen file for deletion: 0x%lx\n", status);
        NtFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&pRename, pRenameSize, MEM_RELEASE);
        return FALSE;
    }

    // Mark the file for deletion using NtSetInformationFile
    status = NtSetInformationFile(hFile, &ioStatusBlock, &Delete, sizeof(Delete), 13/* FileDispositionInformation*/);
    if (!NT_SUCCESS(status)) {
        printf("Error: Failed to mark file for deletion: 0x%lx\n", status);
        NtClose(hFile);
        NtFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&pRename, pRenameSize, MEM_RELEASE);
        return FALSE;
    }

    printf("[+] Deleted binary file\n");

    // Close the file handle
    NtClose(hFile);

    // Free allocated memory using NtFreeVirtualMemory
    NtFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&pRename, pRenameSize, MEM_RELEASE);
    getchar();
    return TRUE;
}
