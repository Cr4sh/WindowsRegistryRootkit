
typedef void (NTAPI * NDIS_HOOK_BUFFER_HANDLER)(PVOID MiniportHandle, PVOID Buffer, ULONG Size);

extern "C"
{
    BOOLEAN NdisHookInitialize(NDIS_HOOK_BUFFER_HANDLER Handler);
    PVOID NdisHookProtocolFind(PVOID hBogusProtocol, PUNICODE_STRING usProtocol);
    PVOID NdisHookProtocolEnumOpened(PVOID Protocol, PVOID OpenBlock);
    PVOID NdisHookOpenGetMiniport(PVOID OpenBlock);
    PVOID NdisHookAlloc(PVOID OldHandler, PVOID OldHandlerContext, PVOID Handler);
    PVOID NdisHookAllocJump(PVOID Address, PVOID Destination);
    ULONG NdisHookSet(PUCHAR PointerFixup);
};
