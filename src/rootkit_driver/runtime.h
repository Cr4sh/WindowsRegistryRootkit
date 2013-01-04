
extern "C"
{
    size_t my_strlen(const char *str);
    int my_strcmp(const char *str_1, const char *str_2);
    char *my_strcpy(char *str_1, const char *str_2);
    char *my_strlwr(char *str);

    wchar_t chrlwr_w(wchar_t chr);
    BOOLEAN EqualUnicodeString_r(PUNICODE_STRING Str1, PUNICODE_STRING Str2, BOOLEAN CaseInSensitive);

    PVOID RuntimeGetSystemInformation(SYSTEM_INFORMATION_CLASS InfoClass);
    PVOID RuntimeGetKernelModuleBase(char *ModuleName);
    PVOID RuntimeGetExportAddress(PVOID Image, char *lpszFunctionName);
    BOOLEAN RuntimeProcessImports(PVOID Image, PVOID KernelAddress);
    BOOLEAN RuntimeProcessRelocs(PVOID Image, PVOID NewBase);

    BOOLEAN RuntimeInitialize(
        PDRIVER_OBJECT DriverObject,
        PUNICODE_STRING RegistryPath
    );
}
