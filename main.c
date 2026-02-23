#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <zlib.h>

// Hash
uLong calculate_hash(BYTE *section, size_t section_size) {
    uLong crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, section, section_size);
    return crc;
}

int main() {
    // Target file name
    char file[] = "game.exe";

    // Get process list (snapshot the process list at kernel)
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    PROCESSENTRY32 pe;
    // We defined the dwSize because of alignment rules.
    pe.dwSize = sizeof(PROCESSENTRY32);
    // Process32First starts the iterator and Process32Next is increases the iterator.
    Process32First(snapshot, &pe);

    DWORD Pid;
    
    // This loop looks the list until find our program pid
    do {
        
        if (memcmp(pe.szExeFile,file,sizeof(file)) == 0) {
            printf("Found: %s \nPid: %i \n",pe.szExeFile,pe.th32ProcessID);
            fflush(stdout);
            Pid = pe.th32ProcessID;
            break;
        }
    } 
    while (Process32Next(snapshot, &pe)); 

    if (Pid == 0) {
        printf("Not found");
        return 1;
    } 
    
    // We found pid, Lets get the module.
    HANDLE modSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,Pid);
    MODULEENTRY32 pePid;
    // Alignment rules..
    pePid.dwSize = sizeof(MODULEENTRY32);

    // Same as Process32First, starts iterator but there is no list, only our program (because we used TH32CS_SNAPMODULE, and took snaphost of our module).
    // Needed for get the base address because we want .text section, after we get base address, we can reach every section.
    Module32First(modSnap,&pePid);
    printf("Base addr: %x \n",pePid.modBaseAddr);
    printf("Total size: %i \n",pePid.modBaseSize);

    printf("-- [Starting to read process memory] -- \n");

    // Lets get "handle" of our program with permissions.
    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, 0, Pid);    

    // And start to parse the PE file to get .text section.
    // if you dont know pe file structure, 
    // take a glance to this blog https://0xrick.github.io/win-internals/pe2/ 
    IMAGE_DOS_HEADER dosHeader;
    const SIZE_T bufferSize = sizeof(dosHeader);
    char buffer[bufferSize];
    SIZE_T bytesRead = 0;

    LPCVOID baseAddr = (LPVOID)pePid.modBaseAddr;
    
    // Read the dosHeader and checked.
    BOOL reading = ReadProcessMemory(process,baseAddr,buffer,bufferSize,&bytesRead);
    if (reading && (buffer[0] == 0x4d & buffer[1] == 0x5a)) {
        printf("[DBG] Pass step 1 \n");
    }
    

    // Now we can get offset of ntHeaders.
    IMAGE_NT_HEADERS ntHeaders;
    const SIZE_T bufferSizeNT = sizeof(ntHeaders);
    char bufferNT[bufferSizeNT];
    SIZE_T bytesReadNT = 0;

    // e_lfanew is part of dosHeader and holds the NTheader offset.
    DWORD e_lfanew = *(DWORD*)(buffer + 0x3c);
    // calculated real address.
    LPCVOID NTbaseAddr = (LPCVOID)(pePid.modBaseAddr + e_lfanew);

    // Read and structured with winapi (IMAGE_NT_HEADERS).
    BOOL readingNT = ReadProcessMemory(process, NTbaseAddr, &ntHeaders, bufferSizeNT, &bytesReadNT);
    // We got the number of sections.
    WORD sectionCount = ntHeaders.FileHeader.NumberOfSections;

    // And we start iterate to find .text section.
    for (size_t i = 0; i < sectionCount; i++)
    {
        // Element of nt headers.
        IMAGE_SECTION_HEADER SectionHeaders;
        
        LPCVOID SectionsbaseAddr = (LPCVOID)((NTbaseAddr + sizeof(IMAGE_NT_HEADERS)) + i * sizeof(IMAGE_SECTION_HEADER));
        SIZE_T bytesSections = 0;
        BOOL readingST = ReadProcessMemory(process, SectionsbaseAddr, &SectionHeaders, sizeof(IMAGE_SECTION_HEADER), &bytesSections);

        // Checked its .text or not.
        if (memcmp(SectionHeaders.Name,".text",6) == 0) {
            // Get .text virtual size 
            int size = SectionHeaders.Misc.VirtualSize;
            
            BYTE dotTXT[size];
            SIZE_T readed = 0;

            LPCVOID textAddr = (LPCVOID)(pePid.modBaseAddr + SectionHeaders.VirtualAddress);
            BOOL dottxtsection = ReadProcessMemory(process, textAddr, dotTXT, size, &readed);
            // Readed the .text section and hashed.
            uLong hash = calculate_hash(dotTXT, readed);
            printf("Base hash: 0x%08lX\n", hash);

            printf("Everything good. \n");

            // Started to check hash every second its same or not.
            while(1) {
                BYTE t_dotTXT[size];
                SIZE_T t_readed = 0;

                BOOL dottxtsection = ReadProcessMemory(process, textAddr, t_dotTXT, size, &readed);
                uLong t_hash = calculate_hash(t_dotTXT, readed);
                
                if (hash != t_hash) {
                    MessageBoxA(NULL, "Program patched!", "Alert", MB_OK | MB_ICONWARNING);
                    TerminateProcess(process, 1);
                    break;
                } 
                Sleep(1000);
            }
            break;
        }
    }
    return 0;
}