#pragma warning(disable: 4200)

extern "C"
{
#include <stdio.h>
#include <stdarg.h>
#include <ntddk.h>
#include <ntimage.h>

#include "undocnt.h"
}

#include "debug.h"
#include "runtime.h"
#include "ndis_hook.h"
#include "network.h"
#include "rootkit_driver.h"
#include "dll_inject.h"

#include "../common/common.h"
#include "../rootkit_driver_config.h"
