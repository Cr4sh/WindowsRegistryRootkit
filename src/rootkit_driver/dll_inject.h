

#ifdef _X86_

#define PEB_IMAGE_BASE_OFFEST 0x08

#elif _AMD64_

#define PEB_IMAGE_BASE_OFFEST 0x10

#endif

/**
 * Callgate for execution library with CreateRemoteThread()
 */
#pragma pack(1)
typedef struct _INJ_THREAD_STRUCT
{
    // push ModuleBase
    UCHAR   u0_0x68;
    ULONG   Image;

    // call ProcessModuleImports
    UCHAR   u1_0xE8;
    ULONG   ShellCodeAddr;
    
    // test eax,eax
    USHORT  u2_0xC085;

    // jz exit
    USHORT  u3_0x840F;
    ULONG   ExitAddr;

    // push param_1
    UCHAR   u4_0x68;
    ULONG   param_Reserved;
    
    // push param_2
    UCHAR   u5_0x68;
    ULONG   param_Reason;
    
    // push param_3
    UCHAR   u6_0x68;
    ULONG   ModuleInstance;
    
    // call ImageEntryPoint
    UCHAR   u7_0xE8;
    ULONG   ImageEntryPoint;    

    // retn 3
    UCHAR   u8_0xC2;
    USHORT  param_local_size;

    UCHAR   ShellCode[];

} INJ_THREAD_STRUCT,
*PINJ_THREAD_STRUCT;
#pragma pack()

NTSTATUS NTAPI _ZwProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
);


BOOLEAN InjectInitialize(void);
BOOLEAN InjectIntoProcess(PEPROCESS Process, PKTHREAD Thread, PVOID Data, ULONG DataSize);
BOOLEAN InjectIntoProcessByName(PWSTR ProcessName, PVOID Data, ULONG DataSize);
BOOLEAN InjectIntoProcessById(ULONG ProcessId, PVOID Data, ULONG DataSize);

