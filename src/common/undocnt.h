
/************************************************************/
/*                                                          */ 
/*  Some structures for native API functions                */
/*                                                          */
/************************************************************/

typedef enum _SYSTEM_INFORMATION_CLASS 
{
    SystemBasicInformation,
    SystemProcessorInformation,             // obsolete...delete
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemVerifierAddDriverInformation,
    SystemVerifierRemoveDriverInformation,
    SystemProcessorIdleInformation,
    SystemLegacyDriverInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemVerifierThunkExtend,
    SystemSessionProcessInformation,
    SystemLoadGdiDriverInSystemSpace,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchdogTimerHandler,
    SystemWatchdogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWow64SharedInformation,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum

} SYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION 
{
    HANDLE Section;                 // Not filled in
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[ 256 ];

} RTL_PROCESS_MODULE_INFORMATION, 
*PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES 
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[ 1 ];

} RTL_PROCESS_MODULES, 
*PRTL_PROCESS_MODULES;

typedef enum _SHUTDOWN_ACTION 
{
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff

} SHUTDOWN_ACTION, 
*PSHUTDOWN_ACTION;

typedef struct _DIRECTORY_BASIC_INFORMATION 
{
    UNICODE_STRING ObjectName;
    UNICODE_STRING ObjectTypeName;

} DIRECTORY_BASIC_INFORMATION, 
*PDIRECTORY_BASIC_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO 
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;

} SYSTEM_HANDLE_TABLE_ENTRY_INFO, 
*PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION 
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[ 1 ];

} SYSTEM_HANDLE_INFORMATION, 
*PSYSTEM_HANDLE_INFORMATION;

/************************************************************/
/*                                                          */ 
/*  Prototypes for native and kernel API functions          */
/*                                                          */
/************************************************************/

typedef enum _KPROFILE_SOURCE 
{
    ProfileTime,
    ProfileAlignmentFixup,
    ProfileTotalIssues,
    ProfilePipelineDry,
    ProfileLoadInstructions,
    ProfilePipelineFrozen,
    ProfileBranchInstructions,
    ProfileTotalNonissues,
    ProfileDcacheMisses,
    ProfileIcacheMisses,
    ProfileCacheMisses,
    ProfileBranchMispredictions,
    ProfileStoreInstructions,
    ProfileFpInstructions,
    ProfileIntegerInstructions,
    Profile2Issue,
    Profile3Issue,
    Profile4Issue,
    ProfileSpecialInstructions,
    ProfileTotalCycles,
    ProfileIcacheIssues,
    ProfileDcacheAccesses,
    ProfileMemoryBarrierCycles,
    ProfileLoadLinkedIssues,
    ProfileMaximum

} KPROFILE_SOURCE, 
*PKPROFILE_SOURCE;

typedef NTSTATUS (WINAPI * func_NtQueryIntervalProfile)(
    KPROFILE_SOURCE ProfileSource,
    PULONG Interval
);

typedef NTSTATUS (WINAPI * func_NtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef CCHAR KPROCESSOR_MODE;

typedef enum _MODE 
{
    KernelMode,
    UserMode,
    MaximumMode

} MODE;

typedef NTSTATUS (WINAPI * func_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect 
);

typedef NTSTATUS (WINAPI * func_KeDelayExecutionThread)(
    KPROCESSOR_MODE WaitMode,
    BOOLEAN Alertable,
    PLARGE_INTEGER Interval
);

typedef VOID (WINAPI * func_KeUnstackDetachProcess)(
    PVOID ApcState
);

typedef enum _POOL_TYPE 
{
    NonPagedPool,
    PagedPool

} POOL_TYPE;

typedef PVOID (WINAPI * func_ExAllocatePool)(
    POOL_TYPE PoolType, 
    SIZE_T NumberOfBytes
);

typedef HANDLE (WINAPI * func_PsGetCurrentProcessId)(VOID);
typedef HANDLE (WINAPI * func_PsGetCurrentThreadId)(VOID);
typedef PVOID (WINAPI * func_PsGetCurrentThread)(VOID);

typedef NTSTATUS (WINAPI * func_ZwOpenThread)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

typedef VOID (WINAPI * func_RtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
);

typedef VOID (WINAPI * func_RtlInitAnsiString)(
    PANSI_STRING DestinationString,
    PCSTR SourceString
);

typedef NTSTATUS (WINAPI * func_RtlAnsiStringToUnicodeString)(
    PUNICODE_STRING DestinationString,
    PANSI_STRING SourceString,
    BOOLEAN AllocateDestinationString
);

typedef BOOLEAN (WINAPI * func_RtlEqualUnicodeString)(
    UNICODE_STRING *String1,
    UNICODE_STRING *String2,
    BOOLEAN CaseInSensitive
);

typedef VOID (WINAPI * func_RtlFreeUnicodeString)(
    PUNICODE_STRING UnicodeString
);

typedef NTSTATUS (WINAPI * func_NtOpenFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions
);

typedef VOID (__fastcall * func_IofCompleteRequest)(
    struct _IRP *Irp,
    CCHAR PriorityBoost
);

typedef NTSTATUS (WINAPI * func_PsLookupProcessByProcessId)(
    HANDLE ProcessId,
    PVOID *Process
);
