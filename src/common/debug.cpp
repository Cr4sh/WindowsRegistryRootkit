#include "stdafx.h"
//--------------------------------------------------------------------------------------
#ifdef DBG
//--------------------------------------------------------------------------------------
char *GetNameFromFullPath(char *lpszPath)
{
    char *lpszName = lpszPath;

    for (int i = 0; i < lstrlenA(lpszPath); i++)
    {
        if (lpszPath[i] == '\\' || lpszPath[i] == '/')
        {
            lpszName = lpszPath + i + 1;
        }
    }

    return lpszName;
}
//--------------------------------------------------------------------------------------
typedef int (__cdecl * func_sprintf)(LPSTR, LPCSTR, ...);
typedef int (__cdecl * func_vsprintf)(LPSTR, LPCSTR, va_list arglist);
typedef int (__cdecl * func__vscprintf)(const char *format, va_list argptr);

void DbgMsg(char *lpszFile, int Line, char *lpszMsg, ...)
{
    va_list mylist;
    va_start(mylist, lpszMsg);

    func_sprintf f_sprintf = (func_sprintf)GetProcAddress(
        LoadLibraryA("msvcrt.dll"),
        "sprintf"
    );
    if (f_sprintf == NULL)
    {
        return;
    }

    func_vsprintf f_vsprintf = (func_vsprintf)GetProcAddress(
        LoadLibraryA("msvcrt.dll"),
        "vsprintf"
    );
    if (f_vsprintf == NULL)
    {
        return;
    }

    func__vscprintf f__vscprintf = (func__vscprintf)GetProcAddress(
        LoadLibraryA("msvcrt.dll"),
        "_vscprintf"
    );
    if (f__vscprintf == NULL)
    {
        return;
    }

    size_t len = f__vscprintf(lpszMsg, mylist) + 0x100;

    char *lpszBuff = (char *)LocalAlloc(LMEM_FIXED, len);
    if (lpszBuff == NULL)
    {
        va_end(mylist);
        return;
    }

    char *lpszOutBuff = (char *)LocalAlloc(LMEM_FIXED, len);
    if (lpszOutBuff == NULL)
    {
        LocalFree(lpszBuff);
        va_end(mylist);
        return;
    }

    f_vsprintf(lpszBuff, lpszMsg, mylist);	
    va_end(mylist);

    f_sprintf(
        lpszOutBuff, "[%.5d] .\\%s(%d) : %s", 
        GetCurrentProcessId(), GetNameFromFullPath(lpszFile), Line, lpszBuff
    );

    OutputDebugStringA(lpszOutBuff);

    HANDLE hStd = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStd != INVALID_HANDLE_VALUE)
    {
        DWORD dwWritten = 0;
        WriteFile(hStd, lpszBuff, lstrlenA(lpszBuff), &dwWritten, NULL);    
    }

    LocalFree(lpszOutBuff);
    LocalFree(lpszBuff);
}
//--------------------------------------------------------------------------------------
#endif DBG
//--------------------------------------------------------------------------------------
// EoF
