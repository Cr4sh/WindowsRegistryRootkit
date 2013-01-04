#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <conio.h>
#include <windows.h>

#define USE_SHELLCODE_DBGPRINT
#define USE_DEBUG_DRIVER

#include "../common/common.h"
#include "../common/ntdll_defs.h"
#include "../common/undocnt.h"
#include "../common/debug.h"
#include "../common/catchy32.h"

#include "../common/shellcode2_struct.h"

#pragma comment(lib, "../common/catchy32.lib")
