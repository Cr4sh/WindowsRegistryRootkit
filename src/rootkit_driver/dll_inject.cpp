#include "stdafx.h"
#include "dll_inject_shellcode.h"

ULONG SDT_NtProtectVirtualMemory = 0;
int m_KTHREAD_ApcState = -1;

KEVENT m_ApcEvent;
//--------------------------------------------------------------------------------------
#ifdef _X86_

__declspec(naked) NTSTATUS NTAPI _ZwProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection)
{
    __asm
    {
        cmp     SDT_NtProtectVirtualMemory, 0
        jz      _failed
        mov     eax, SDT_NtProtectVirtualMemory
        lea     edx, [esp + 4]
        int     0x2e
        retn    0x14

_failed:
        mov     eax, 0xc00000001
        retn    0x14
    }
}

#endif // _X86_
//--------------------------------------------------------------------------------------
ULONG GetShellcodeSize(PVOID Data)
{
    ULONG Size = 0;
    PULONG Ptr = (PULONG)Data;

    // get size of shellcode
    while (*Ptr != ENDM)
    {
        Size += 1;

        // check for end marker
        Ptr = (PULONG)((ULONG)Ptr + 1);        
    }

    return Size;
}
//--------------------------------------------------------------------------------------
void InjectKernelApcRoutine(
    struct _KAPC *Apc, 
    PKNORMAL_ROUTINE *NormalRoutine, 
    PVOID *NormalContext, 
    PVOID *SystemArgument1, 
    PVOID *SystemArgument2) 
{
    DbgMsg(__FUNCTION__"()\n");
    KeSetEvent(&m_ApcEvent, 0, FALSE);
}
//--------------------------------------------------------------------------------------
BOOLEAN InjectFindProcess(PWSTR ProcessName, ULONG ProcessId, PKTHREAD *pThread, PEPROCESS *pProcess)
{
    BOOLEAN bRet = FALSE;
    UNICODE_STRING usProcessName;

    if (ProcessName)
    {
        RtlInitUnicodeString(&usProcessName, ProcessName);
    }    

    *pThread = NULL;
    *pProcess = NULL;

    PSYSTEM_PROCESSES_INFORMATION pProcessesInfo = (PSYSTEM_PROCESSES_INFORMATION)
        RuntimeGetSystemInformation(SystemProcessInformation);
    if (pProcessesInfo)
    {
        PSYSTEM_PROCESSES_INFORMATION pInfo = pProcessesInfo;

        // iterate processes list
        while (pInfo)
        {
            if (pInfo->ProcessName.Buffer &&
                pInfo->ThreadCount > 0)
            {
                // match by process name or ID
                if ((ProcessName != NULL && RtlEqualUnicodeString(&pInfo->ProcessName, &usProcessName, TRUE)) ||
                    (ProcessId != 0 && pInfo->ProcessId == ProcessId))
                {
                    DbgMsg(
                        __FUNCTION__"(): \"%wZ\", PID = %d\n", 
                        &pInfo->ProcessName, pInfo->ProcessId
                    );

                    NTSTATUS ns = PsLookupThreadByThreadId(
                        pInfo->Threads[0].ClientId.UniqueThread, 
                        (PETHREAD *)pThread
                    );
                    if (!NT_SUCCESS(ns))
                    {
                        DbgMsg("PsLookupProcessByProcessId() ERROR; status: 0x%.8x\n", ns);
                    }

                    ns = PsLookupProcessByProcessId(
                        (HANDLE)pInfo->ProcessId, 
                        pProcess
                    );
                    if (!NT_SUCCESS(ns))
                    {
                        DbgMsg("PsLookupProcessByProcessId() ERROR; status: 0x%.8x\n", ns);
                    }

                    if (*pThread && *pProcess)
                    {
                        bRet = TRUE;
                        break;
                    }
                    else
                    {
                        if (*pThread)
                        {
                            ObDereferenceObject(*pThread);
                            *pThread = NULL;
                        }

                        if (*pProcess)
                        {
                            ObDereferenceObject(*pProcess);
                            *pProcess = NULL;
                        }
                    }
                }
            }

            if (pInfo->NextEntryDelta == 0)
            {
                // end of the list
                break;
            }

            pInfo = (PSYSTEM_PROCESSES_INFORMATION)((PUCHAR)pInfo + pInfo->NextEntryDelta);
        }

        ExFreePool(pProcessesInfo);
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOLEAN ImjectMapDllImage(HANDLE hProcess, PVOID Data, ULONG DataSize, PVOID *pRetImage)
{
    PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)RVATOVA(
        Data,
        ((PIMAGE_DOS_HEADER)Data)->e_lfanew
    );

    PVOID Image = NULL;
    ULONG ImageSize = pHeaders->OptionalHeader.SizeOfImage;

    // allocate memory for image
    NTSTATUS ns = ZwAllocateVirtualMemory(
        hProcess,
        (PVOID *)&Image,
        0,
        &ImageSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (NT_SUCCESS(ns))
    {
        DbgMsg(__FUNCTION__"(): Memory for image allocated at "IFMT"\n", Image);

        __try
        {
            // copy headers
            RtlZeroMemory(Image, ImageSize);
            RtlCopyMemory(Image, Data, pHeaders->OptionalHeader.SizeOfHeaders);

            // copy sections
            PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)
                ((PUCHAR)&pHeaders->OptionalHeader + 
                pHeaders->FileHeader.SizeOfOptionalHeader);

            for (ULONG i = 0; i < pHeaders->FileHeader.NumberOfSections; i++)
            {
                RtlCopyMemory(
                    RVATOVA(Image, pSection->VirtualAddress), 
                    RVATOVA(Data, pSection->PointerToRawData),
                    min(pSection->SizeOfRawData, pSection->Misc.VirtualSize)
                );

                pSection++;
            }            

            // parse image base relocations
            if (RuntimeProcessRelocs(Image, Image))
            {
                *pRetImage = Image;
                return TRUE;
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            DbgMsg(__FUNCTION__"() EXCEPTION\n");
        } 

        ZwFreeVirtualMemory(hProcess, &Image, 0, MEM_RELEASE);
    }
    else
    {
        DbgMsg("ZwAllocateVirtualMemory() fails; status: 0x%.8x\n", ns);
    }

    return NULL;
}
//--------------------------------------------------------------------------------------
BOOLEAN InjectIntoProcess(PEPROCESS Process, PKTHREAD Thread, PVOID Data, ULONG DataSize)
{

#ifdef USE_PARANOID_CHEKS

    if (m_KTHREAD_ApcState < 0)
    {
        DbgMsg(__FUNCTION__"() ERROR: Some offsets are not initialized\n");
        return FALSE;
    }

#endif // USE_PARANOID_CHEKS

    BOOLEAN bRet = FALSE;
    HANDLE hProcess = NULL;

    // get handle to the target process
    NTSTATUS ns = ObOpenObjectByPointer(
        Process,
        OBJ_KERNEL_HANDLE,
        NULL,
        0,
        NULL,
        KernelMode,
        &hProcess
    );
    if (NT_SUCCESS(ns))
    {
        PROCESS_BASIC_INFORMATION ProcessInfo;                               

        // get address of PEB
        ns = ZwQueryInformationProcess(
            hProcess,
            ProcessBasicInformation,
            &ProcessInfo,
            sizeof(ProcessInfo),
            NULL
        );
        if (!NT_SUCCESS(ns))
        {
            DbgMsg("ZwQueryInformationProcess() fails; status: 0x%.8x\n", ns);
            goto close;
        }                       

        // attach to the process address space
        KAPC_STATE ApcState;
        KeStackAttachProcess(Process, &ApcState);

        // get process image base from peb
        PVOID ProcessImageBase = *(PVOID *)((PUCHAR)ProcessInfo.PebBaseAddress + PEB_IMAGE_BASE_OFFEST);

        // map DLL image into the target process
        PVOID Image = NULL;
        if (ImjectMapDllImage(hProcess, Data, DataSize, &Image))
        {
            __try
            {
                PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)RVATOVA(
                    Image,
                    ((PIMAGE_DOS_HEADER)Data)->e_lfanew
                );

                PVOID ImageEntryPoint = RVATOVA(Image, pHeaders->OptionalHeader.AddressOfEntryPoint);

                DbgMsg(__FUNCTION__"(): Image entry point is at "IFMT"\n", ImageEntryPoint);

                PINJ_THREAD_STRUCT InjectStruct = NULL;
                ULONG ShellCodeSize = GetShellcodeSize(inj_shellcode);
                ULONG InjectStructSize = sizeof(INJ_THREAD_STRUCT) + ShellCodeSize;

                // allocate memory for callgate
                NTSTATUS ns = ZwAllocateVirtualMemory(
                    hProcess,
                    (PVOID *)&InjectStruct,
                    0,
                    &InjectStructSize,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE
                );
                if (NT_SUCCESS(ns))
                {
                    DbgMsg("Callgate allocated at "IFMT"\n", InjectStruct);

                    RtlFillMemory(InjectStruct, InjectStructSize, 0x90);

                    #define DLL_PROCESS_ATTACH 0x01

                    #define REL_OP(_to_, _from_)                                   \
                                                                                    \
                        (ULONG)((PUCHAR)&InjectStruct->##_to_ -                     \
                                (PUCHAR)&InjectStruct->##_from_) - sizeof(ULONG)

#ifdef _X86_                        
                    InjectStruct->u0_0x68 = 0x68; /* PUSH Image */
                    InjectStruct->Image = (ULONG)Image;

                    InjectStruct->u1_0xE8 = 0xE8; /* CALL ProcessModuleImports */
                    InjectStruct->ShellCodeAddr = REL_OP(ShellCode, ShellCodeAddr);
                    
                    InjectStruct->u2_0xC085 = 0xC085; /* TEST EAX, EAX */

                    InjectStruct->u3_0x840F = 0x840F; /* JZ Exit */
                    InjectStruct->ExitAddr = REL_OP(u8_0xC2, ExitAddr);

                    InjectStruct->u4_0x68 = 0x68; /* PUSH 0 */
                    InjectStruct->param_Reserved = 0;
                    
                    InjectStruct->u5_0x68 = 0x68; /* PUSH DLL_PROCESS_ATTACH */
                    InjectStruct->param_Reason = DLL_PROCESS_ATTACH;
                    
                    InjectStruct->u6_0x68 = 0x68; /* PUSH ModuleInstance */
                    InjectStruct->ModuleInstance = (ULONG)Image;
                    
                    InjectStruct->u7_0xE8 = 0xe8; /* CALL ImageEntryPoint */
                    InjectStruct->ImageEntryPoint = (ULONG)((PUCHAR)ImageEntryPoint - (PUCHAR)&InjectStruct->ImageEntryPoint) - sizeof(ULONG);
                                          
                    InjectStruct->u8_0xC2 = 0xc2; /* RET 3 */
                    InjectStruct->param_local_size = 3;
#else // _X86_

#error __FUNCTION__ is x86 only

#endif // _X86_
                    // copy shellcode, that processing module imports
                    RtlCopyMemory(&InjectStruct->ShellCode, inj_shellcode, ShellCodeSize);                                                

                    KAPC Apc;
                    PKAPC_STATE pThreadApcState = (PKAPC_STATE)((PUCHAR)Thread + m_KTHREAD_ApcState);

                    KeInitializeApc(
                        &Apc, 
                        Thread, 
                        OriginalApcEnvironment, 
                        &InjectKernelApcRoutine, 
                        NULL, 
                        (PKNORMAL_ROUTINE)InjectStruct, 
                        UserMode, 
                        NULL
                    );

                    // enable user APC delivering
                    pThreadApcState->UserApcPending = TRUE;

                    // add routine to the APC queue
                    if (KeInsertQueueApc(&Apc, NULL, NULL, 0))
                    {
                        LARGE_INTEGER Timeout;
                        Timeout.QuadPart = TIME_RELATIVE(TIME_SECONDS(1));                

                        // waiting for APC completion
                        ns = KeWaitForSingleObject(&m_ApcEvent, Executive, KernelMode, FALSE, &Timeout);
                        if (ns == STATUS_TIMEOUT)
                        {
                            DbgMsg(__FUNCTION__"(): Error while delivering APC\n");
                        }
                        else if (NT_SUCCESS(ns))
                        {
                            DbgMsg(__FUNCTION__"(): APC delivered!\n");
                            bRet = TRUE;
                        }

                        // sleep for 1 sec.
                        KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
                    }
                    else
                    {
                        DbgMsg("KeInsertQueueApc() ERROR\n");
                    } 
                }
                else
                {
                    DbgMsg("ZwAllocateVirtualMemory() fails; status: 0x%.8x\n", ns);
                }
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DbgMsg(__FUNCTION__"() EXCEPTION\n");
            }              
        }   

        KeUnstackDetachProcess(&ApcState);

close:
        ZwClose(hProcess);
    }
    else
    {
        DbgMsg("ObOpenObjectByPointer() fails; status: 0x%.8x\n", ns);
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOLEAN InjectIntoProcessByName(PWSTR ProcessName, PVOID Data, ULONG DataSize)
{
    BOOLEAN bRet = FALSE;
    PEPROCESS Process = NULL;
    PKTHREAD Thread = NULL;

    // lookup for process by name
    if (InjectFindProcess(ProcessName, 0, &Thread, &Process))
    {
        // perform DLL injection
        bRet = InjectIntoProcess(Process, Thread, Data, DataSize);

        ObDereferenceObject(Process);
        ObDereferenceObject(Thread);
    }
    else
    {
        DbgMsg(__FUNCTION__"() ERROR: Unable to find process \"%ws\"\n", ProcessName);
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOLEAN InjectIntoProcessById(ULONG ProcessId, PVOID Data, ULONG DataSize)
{
    BOOLEAN bRet = FALSE;
    PEPROCESS Process = NULL;
    PKTHREAD Thread = NULL;

    // lookup for process by ID
    if (InjectFindProcess(NULL, ProcessId, &Thread, &Process))
    {
        // perform DLL injection
        bRet = InjectIntoProcess(Process, Thread, Data, DataSize);

        ObDereferenceObject(Process);
        ObDereferenceObject(Thread);
    }
    else
    {
        DbgMsg(__FUNCTION__"() ERROR: Unable to find process PID=%d\n", ProcessId);
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOLEAN InjectInitialize(void)
{    
    RTL_OSVERSIONINFOEXW VersionInformation;
    VersionInformation.dwOSVersionInfoSize = sizeof(VersionInformation);

    if (!NT_SUCCESS(RtlGetVersion((PRTL_OSVERSIONINFOW)&VersionInformation)))
    {
        return FALSE;
    }

    if (VersionInformation.dwMajorVersion == 5 && 
        VersionInformation.dwMinorVersion == 1)
    {
        // XP
        SDT_NtProtectVirtualMemory = 0x0089;

#ifdef _X86_

        m_KTHREAD_ApcState = 0x34;
#endif

    }
    else if (
        VersionInformation.dwMajorVersion == 5 && 
        VersionInformation.dwMinorVersion == 2)
    {
        // Server 2003
        SDT_NtProtectVirtualMemory = 0x008f;

#ifdef _X86_

        m_KTHREAD_ApcState = 0x28;
#endif
        if (VersionInformation.wServicePackMajor == 0 &&
            VersionInformation.wServicePackMinor == 0)
        {
            // Service Pack 0, special case
#ifdef _X86_

            m_KTHREAD_ApcState = 0x34;
#endif
        }
    }
    else if (
        VersionInformation.dwMajorVersion == 6 && 
        VersionInformation.dwMinorVersion == 0)
    {
        // Vista
        if (VersionInformation.wServicePackMajor == 0 &&
            VersionInformation.wServicePackMinor == 0)
        {
            // Service Pack 0, special case
            SDT_NtProtectVirtualMemory = 0x00cf;
        }
        else
        {
            SDT_NtProtectVirtualMemory = 0x00d2;
        }

#ifdef _X86_

        m_KTHREAD_ApcState = 0x38;
#endif

    }
    else if (
        VersionInformation.dwMajorVersion == 6 && 
        VersionInformation.dwMinorVersion == 1)
    {
        // 7
        SDT_NtProtectVirtualMemory = 0x00d7;

#ifdef _X86_

        m_KTHREAD_ApcState = 0x40;
#endif

    }
    else
    {
        DbgMsg(__FUNCTION__"() ERROR: Unknown NT version\n");
        return FALSE;
    }

    DbgMsg("NtProtectVirtualMemory() SDT number is 0x%x\n", SDT_NtProtectVirtualMemory);   

    KeInitializeEvent(&m_ApcEvent, SynchronizationEvent, FALSE);

    return TRUE;
}
//--------------------------------------------------------------------------------------
// EoF
