#include "stdafx.h"

// NDIS version: 6.0
#define NDIS60 1

extern "C"
{
#include <ndis.h>
}


#include "bogusproto.h"

#pragma alloc_text(INIT, NdisHookProtocolFind)
#pragma alloc_text(INIT, NdisHookProtocolEnumOpened)
#pragma alloc_text(INIT, NdisHookOpenGetMiniport)
#pragma alloc_text(INIT, NdisHookAllocJump)
#pragma alloc_text(INIT, NdisHookSet)

// field offsets for NDIS structures
int NDIS_PROTOCOL_BLOCK_Name                            = -1,
    NDIS_PROTOCOL_BLOCK_OpenQueue                       = -1,
    NDIS_PROTOCOL_BLOCK_NextProtocol                    = -1,
    NDIS_OPEN_BLOCK_ProtocolNextOpen                    = -1,        
    NDIS_OPEN_BLOCK_MiniportHandle                      = -1,    
    NDIS_MINIPORT_BLOCK_InterruptEx                     = -1,
    NDIS_MINIPORT_BLOCK_IndicateNetBufferListsHandler   = -1,
    NDIS_INTERRUPT_BLOCK_MiniportDpc                    = -1;

NDIS_HOOK_BUFFER_HANDLER m_Handler = NULL;
//--------------------------------------------------------------------------------------
BOOLEAN NdisHookInitialize(NDIS_HOOK_BUFFER_HANDLER Handler)
{
    UINT NdisVersion = NdisGetVersion();
    if (NdisVersion != 0x60014)
    {
        DbgMsg(__FUNCTION__"() ERROR: NDIS version 0x%x is not supported\n", NdisVersion);
        return FALSE;
    }

    m_Handler = Handler;

#ifdef _X86_

    NDIS_PROTOCOL_BLOCK_OpenQueue                       = 0x00c;
    NDIS_PROTOCOL_BLOCK_NextProtocol                    = 0x008;
    NDIS_PROTOCOL_BLOCK_Name                            = 0x024;
    NDIS_OPEN_BLOCK_ProtocolNextOpen                    = 0x0dc;
    NDIS_OPEN_BLOCK_MiniportHandle                      = 0x008;
    NDIS_MINIPORT_BLOCK_InterruptEx                     = 0x1c0;
    NDIS_MINIPORT_BLOCK_IndicateNetBufferListsHandler   = 0x19c;
    NDIS_INTERRUPT_BLOCK_MiniportDpc                    = 0x010;

#endif

    return TRUE;
}
//--------------------------------------------------------------------------------------
PVOID NdisHookProtocolFind(PVOID hBogusProtocol, PUNICODE_STRING usProtocol)
{    

#ifdef USE_PARANOID_CHEKS

    if (NDIS_PROTOCOL_BLOCK_Name         < 0 ||
        NDIS_PROTOCOL_BLOCK_NextProtocol < 0)
    {
        DbgMsg(__FUNCTION__"() ERROR: Some offsets are not initialized\n");
        return NULL;
    }

#endif // USE_PARANOID_CHEKS

    PUCHAR Protocol = (PUCHAR)hBogusProtocol;

    // enumerate registered NDIS protocols
    while (Protocol)
    {
        PUNICODE_STRING ProtocolName = (PUNICODE_STRING)(Protocol + NDIS_PROTOCOL_BLOCK_Name);

        // find TCPIP protocol
        if (RtlEqualUnicodeString(ProtocolName, usProtocol, TRUE))
        {            
            return Protocol;
        }

        Protocol = *(PUCHAR *)(Protocol + NDIS_PROTOCOL_BLOCK_NextProtocol);
    }        

    return NULL;
}
//--------------------------------------------------------------------------------------
PVOID NdisHookProtocolEnumOpened(PVOID Protocol, PVOID OpenBlock)
{

#ifdef USE_PARANOID_CHEKS

    if (NDIS_PROTOCOL_BLOCK_OpenQueue    < 0 ||        
        NDIS_OPEN_BLOCK_ProtocolNextOpen < 0)
    {
        DbgMsg(__FUNCTION__"() ERROR: Some offsets are not initialized\n");
        return NULL;
    }

#endif // USE_PARANOID_CHEKS

    if (OpenBlock)
    {
        return *(PVOID *)((PUCHAR)OpenBlock + NDIS_OPEN_BLOCK_ProtocolNextOpen);        
    }
    else
    {
        return *(PVOID *)((PUCHAR)Protocol + NDIS_PROTOCOL_BLOCK_OpenQueue);
    }

    return NULL;
}
//--------------------------------------------------------------------------------------
PVOID NdisHookOpenGetMiniport(PVOID OpenBlock)
{

#ifdef USE_PARANOID_CHEKS

    if (NDIS_OPEN_BLOCK_MiniportHandle < 0)
    {
        DbgMsg(__FUNCTION__"() ERROR: Some offsets are not initialized\n");
        return NULL;
    }

#endif // USE_PARANOID_CHEKS

    return *(PVOID *)((PUCHAR)OpenBlock + NDIS_OPEN_BLOCK_MiniportHandle);
}
//--------------------------------------------------------------------------------------
NDIS_STATUS CopyNBLToBuffer(PNET_BUFFER_LIST NetBufferList, PVOID *pDest, PULONG pBytesCopied) 
{
    NDIS_STATUS Status = NDIS_STATUS_SUCCESS;
    PNET_BUFFER CurrentNetBuffer;

    __try
    {
        *pBytesCopied = 0;

        for (CurrentNetBuffer = NET_BUFFER_LIST_FIRST_NB(NetBufferList);
            CurrentNetBuffer != NULL;
            CurrentNetBuffer = NET_BUFFER_NEXT_NB(CurrentNetBuffer))
        {
            PMDL CurrentMdl = NET_BUFFER_CURRENT_MDL(CurrentNetBuffer);
            PUCHAR pSrc = (PUCHAR)MmGetSystemAddressForMdlSafe(CurrentMdl, NormalPagePriority);
            if (pSrc == NULL)
            {
                if (*pDest && *pBytesCopied > 0)
                {
                    ExFreePool(*pDest);
                }

                Status = NDIS_STATUS_RESOURCES;
                __leave;
            }

            // For the first MDL with data, we need to skip the free space
            pSrc += NET_BUFFER_CURRENT_MDL_OFFSET(CurrentNetBuffer);

            LONG CurrLength = MmGetMdlByteCount(CurrentMdl) - NET_BUFFER_CURRENT_MDL_OFFSET(CurrentNetBuffer);
            if (CurrLength > 0)
            {
                ULONG CopyLegth = *pBytesCopied + CurrLength;
                PUCHAR CopyBuff = (PUCHAR)ExAllocatePool(NonPagedPool, CopyLegth);
                if (CopyBuff)
                {
                    if (*pDest && *pBytesCopied > 0)
                    {
                        RtlCopyMemory(CopyBuff, *pDest, *pBytesCopied);
                        ExFreePool(*pDest);
                    }

                    // Copy the data.
                    NdisMoveMemory(CopyBuff + *pBytesCopied, pSrc, CurrLength);
                    *pDest = CopyBuff;
                }                
                else
                {
                    if (*pDest && *pBytesCopied > 0)
                    {
                        ExFreePool(*pDest);
                    }

                    Status = NDIS_STATUS_RESOURCES;
                    __leave;
                }

                *pBytesCopied += CurrLength;
                pDest += CurrLength;
            }

            CurrentMdl = NDIS_MDL_LINKAGE(CurrentMdl);
            while (CurrentMdl)
            {
                pSrc = (PUCHAR)MmGetSystemAddressForMdlSafe(CurrentMdl, NormalPagePriority);
                if (!pSrc)
                {
                    if (*pDest && *pBytesCopied > 0)
                    {
                        ExFreePool(*pDest);
                    }

                    Status = NDIS_STATUS_RESOURCES;
                    __leave;
                }

                CurrLength = MmGetMdlByteCount(CurrentMdl);

                if (CurrLength > 0)
                {
                    ULONG CopyLegth = *pBytesCopied + CurrLength;
                    PUCHAR CopyBuff = (PUCHAR)ExAllocatePool(NonPagedPool, CopyLegth);
                    if (CopyBuff)
                    {
                        if (*pDest && *pBytesCopied > 0)
                        {
                            RtlCopyMemory(CopyBuff, *pDest, *pBytesCopied);
                            ExFreePool(*pDest);
                        }

                        // Copy the data.
                        NdisMoveMemory(CopyBuff + *pBytesCopied, pSrc, CurrLength);
                        *pDest = CopyBuff;
                    }                
                    else
                    {
                        if (*pDest && *pBytesCopied > 0)
                        {
                            ExFreePool(*pDest);
                        }

                        Status = NDIS_STATUS_RESOURCES;
                        __leave;
                    }

                    *pBytesCopied += CurrLength;
                    pDest += CurrLength;
                }

                CurrentMdl = NDIS_MDL_LINKAGE(CurrentMdl);
            }
        }
    }
    __finally { }

    return Status;
}
//--------------------------------------------------------------------------------------
#ifdef _X86_

#pragma pack(push, 1)
typedef struct _HOOK_STRUCT
{
    UCHAR op1_0x58; /* POP  EAX */
    
    UCHAR op2_0x68; /* PUSH OldHandler */
    PVOID OldHandler;

    UCHAR op3_0x68; /* PUSH OldHandlerContext */
    PVOID OldHandlerContext;

    UCHAR op4_0x50; /* PUSH EAX */
    
    UCHAR op5_0x68; /* PUSH Handler */
    PVOID Handler;

    UCHAR op6_0xc3; /* RET */

} HOOK_STRUCT,
*PHOOK_STRUCT;
#pragma pack(pop)

PVOID NdisHookAlloc(PVOID OldHandler, PVOID OldHandlerContext, PVOID Handler)
{
    // allocate trampoline for hook handler calling
    PHOOK_STRUCT HookStruct = (PHOOK_STRUCT)ExAllocatePool(NonPagedPool, sizeof(HOOK_STRUCT));
    if (HookStruct)
    {
        HookStruct->op1_0x58 = 0x58;
        HookStruct->op2_0x68 = 0x68;
        HookStruct->OldHandler = OldHandler;
        HookStruct->op3_0x68 = 0x68;
        HookStruct->OldHandlerContext = OldHandlerContext;
        HookStruct->op4_0x50 = 0x50;
        HookStruct->op5_0x68 = 0x68;
        HookStruct->Handler = Handler;
        HookStruct->op6_0xc3 = 0xc3;
    }

    return HookStruct;
}

#endif // _X86_
//--------------------------------------------------------------------------------------
#define JUMP_SIZE 6

PVOID NdisHookAllocJump(PVOID Address, PVOID Destination)
{
    PVOID Image = NULL;

    PRTL_PROCESS_MODULES Info = (PRTL_PROCESS_MODULES)RuntimeGetSystemInformation(SystemModuleInformation);
    if (Info)
    {
        for (ULONG i = 0; i < Info->NumberOfModules; i++)
        {
            // find image by address inside it
            if (Address > Info->Modules[i].ImageBase &&
                Address < (PUCHAR)Info->Modules[i].ImageBase + Info->Modules[i].ImageSize)
            {
                Image = Info->Modules[i].ImageBase;
                break;
            }
        }

        ExFreePool(Info);
    }

    if (Image == NULL)
    {
        // unknown address
        return Destination;
    }

    PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)
        ((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)
        (pHeaders->FileHeader.SizeOfOptionalHeader + 
        (PUCHAR)&pHeaders->OptionalHeader);

    UCHAR ZeroBytes[JUMP_SIZE];
    RtlZeroMemory(ZeroBytes, sizeof(ZeroBytes));

    // find the '.text' section
    for (ULONG i = 0; i < pHeaders->FileHeader.NumberOfSections; i++, pSection++)
    {            
        if (!strcmp((char *)&pSection->Name, ".text") &&
            (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            !(pSection->Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
        {
            // calculate the real size of section 
            ULONG RealSize = MY_ALIGN_UP(pSection->Misc.VirtualSize, pHeaders->OptionalHeader.SectionAlignment);
            ULONG PaddingSize = RealSize - pSection->Misc.VirtualSize;
            if (PaddingSize > JUMP_SIZE)
            {
                // find section padding
                PUCHAR Padding = RVATOVA(Image, pSection->VirtualAddress + pSection->Misc.VirtualSize);

                for (ULONG p = PaddingSize - JUMP_SIZE; p != 0; p--)
                {
                    PUCHAR Ptr = Padding + p;

                    // check for zero bytes
                    if (RtlCompareMemory(Ptr, ZeroBytes, JUMP_SIZE) == JUMP_SIZE)
                    {                        
                        ClearWp();
#ifdef _X86_
                        // allocate jump
                        *(Ptr + 0) = 0x68; /* PUSH Destination */
                        *(PVOID *)(Ptr + 1) = Destination;
                        *(Ptr + 1 + sizeof(PVOID)) = 0xc3; /* RET */
#else // _X86_

#error __FUNCTION__ is x86 only

#endif // _X86_
                        SetWp();

                        return Ptr;
                    }
                }
            }
        }
    }

    return Destination;
}
//--------------------------------------------------------------------------------------
typedef void (NTAPI * func_IndicateNetBufferListsHandler)(
    NDIS_HANDLE MiniportAdapterHandle,
    PNET_BUFFER_LIST NetBufferLists,
    NDIS_PORT_NUMBER PortNumber,
    ULONG NumberOfNetBufferLists,
    ULONG ReceiveFlags
);

void IndicateNetBufferListsHandler(
    /***/
    PVOID Reserved,
    func_IndicateNetBufferListsHandler OldHandler,
    /***/
    NDIS_HANDLE MiniportAdapterHandle,
    PNET_BUFFER_LIST NetBufferLists,
    NDIS_PORT_NUMBER PortNumber,
    ULONG NumberOfNetBufferLists,
    ULONG ReceiveFlags)
{        
    // iterate NET_BUFFER_LIST
    PNET_BUFFER_LIST BufferList = NetBufferLists;
    while (BufferList)
    {
        PVOID Buff = NULL;
        ULONG BuffSize = 0;

        // get raw buffers data
        if (CopyNBLToBuffer(BufferList, &Buff, &BuffSize) == NDIS_STATUS_SUCCESS)
        {

#ifdef DBG_NDIS_HOOK

            DbgMsg(__FUNCTION__"(): Miniport = "IFMT", Length = %d\n", MiniportAdapterHandle, BuffSize);
#endif
            if (m_Handler)
            {
                // call the data handler
                m_Handler(MiniportAdapterHandle, Buff, BuffSize);
            }

            ExFreePool(Buff);
        }

        BufferList = NET_BUFFER_LIST_NEXT_NBL(BufferList);
    }    

    // call original function
    OldHandler(
        MiniportAdapterHandle,
        NetBufferLists,
        PortNumber,
        NumberOfNetBufferLists,
        ReceiveFlags        
    );
}

typedef void (NTAPI * func_MiniportInterruptDPC)(
    NDIS_HANDLE MiniportInterruptContext,
    PVOID MiniportDpcContext,
    PVOID ReceiveThrottleParameters,
    PVOID NdisReserved2
);

void MiniportInterruptDPC(
    /***/
    PVOID Miniport,
    func_MiniportInterruptDPC OldHandler,
    /***/
    NDIS_HANDLE MiniportInterruptContext,
    PVOID MiniportDpcContext,
    PVOID ReceiveThrottleParameters,
    PVOID NdisReserved2)
{
    PVOID Handler = *(PVOID *)((PUCHAR)Miniport + NDIS_MINIPORT_BLOCK_IndicateNetBufferListsHandler);

#ifdef DBG_NDIS_HOOK

    DbgMsg(__FUNCTION__"(): Miniport = "IFMT"\n", Miniport);

#endif

    // allocate trampoline for hook handler calling
    PVOID HookStruct = NdisHookAlloc(Handler, NULL, IndicateNetBufferListsHandler);
    if (HookStruct)
    {
        // hook _NDIS_MINIPORT_BLOCK::IndicateNetBufferListsHandler
        *(PVOID *)((PUCHAR)Miniport + NDIS_MINIPORT_BLOCK_IndicateNetBufferListsHandler) = HookStruct;
    }

    // call original function
    OldHandler(
        MiniportInterruptContext,
        MiniportDpcContext,
        ReceiveThrottleParameters,
        NdisReserved2
    );

    if (HookStruct)
    {
        // restore _NDIS_MINIPORT_BLOCK::IndicateNetBufferListsHandler
        *(PVOID *)((PUCHAR)Miniport + NDIS_MINIPORT_BLOCK_IndicateNetBufferListsHandler) = Handler;
        ExFreePool(HookStruct);
    }
}
//--------------------------------------------------------------------------------------
ULONG NdisHookSet(PUCHAR PointerFixup)
{

#ifdef USE_PARANOID_CHEKS

    if (NDIS_MINIPORT_BLOCK_InterruptEx                     < 0 ||        
        NDIS_INTERRUPT_BLOCK_MiniportDpc                    < 0 ||
        NDIS_MINIPORT_BLOCK_IndicateNetBufferListsHandler   < 0)
    {
        DbgMsg(__FUNCTION__"() ERROR: Some offsets are not initialized\n");
        return 0;
    }

#endif // USE_PARANOID_CHEKS

    ULONG Hooked = 0;
    NDIS_HANDLE hBogusProtocol = BogusProtocolRegister();
    if (hBogusProtocol)
    {
        UNICODE_STRING usTcpIp;
        RtlInitUnicodeString(&usTcpIp, L"TCPIP");

        // lookup the 'TCPIP' protocol
        PVOID Protocol = NdisHookProtocolFind(hBogusProtocol, &usTcpIp);
        if (Protocol)
        {
            DbgMsg(__FUNCTION__"(): \"TCPIP\" protocol address is "IFMT"\n", Protocol);

            // enumerate open miniports
            PVOID OpenBlock = NULL;
            while (OpenBlock = NdisHookProtocolEnumOpened(Protocol, OpenBlock))
            {
                // get miniport address
                PVOID Miniport = NdisHookOpenGetMiniport(OpenBlock);
                if (Miniport)
                {
                    DbgMsg(__FUNCTION__"(): Open block = "IFMT", Miniport = "IFMT"\n", OpenBlock, Miniport);

                    // get _NDIS_INTERRUPT_BLOCK address
                    PVOID InterruptEx = *(PVOID *)((PUCHAR)Miniport + NDIS_MINIPORT_BLOCK_InterruptEx);
                    if (InterruptEx == NULL)
                    {
                        continue;
                    }

                    // change _NDIS_INTERRUPT_BLOCK::MiniportDpc routine address
                    PVOID MiniportDpc = *(PVOID *)((PUCHAR)InterruptEx + NDIS_INTERRUPT_BLOCK_MiniportDpc);
                    if (MiniportDpc == NULL)
                    {
                        continue;
                    }

                    // allocate trampoline for hook handler calling
                    PVOID HookStruct = NdisHookAlloc(MiniportDpc, Miniport, RECALCULATE_POINTER(MiniportInterruptDPC));
                    if (HookStruct)
                    {
                        // hook _NDIS_INTERRUPT_BLOCK::MiniportDpc
                        *(PVOID *)((PUCHAR)InterruptEx + NDIS_INTERRUPT_BLOCK_MiniportDpc) = NdisHookAllocJump(MiniportDpc, HookStruct);

                        DbgMsg(__FUNCTION__"(): Hooking MiniportDpc: "IFMT" -> "IFMT"\n", MiniportDpc, HookStruct);

                        Hooked += 1;
                    }
                }
            }
        }
        else
        {
            DbgMsg(__FUNCTION__"() ERROR: Unable to find \"TCPIP\" protocol\n");
        }

        BogusProtocolUnregister();
    }

    return Hooked;
}
//--------------------------------------------------------------------------------------
// EoF
