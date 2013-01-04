#include "stdafx.h"
//--------------------------------------------------------------------------------------
SHORT ChecksumEnd(ULONG Sum)
{
    Sum = (Sum >> 16) + (Sum & 0xffff);
    Sum += (Sum >> 16);

    return (USHORT)(~Sum);
}

/*
 * Calculate checksum of a buffer.
 * @param Data Pointer to buffer with data.
 * @param Count Number of bytes in buffer.
 * @param Seed Previously calculated checksum (if any).
 * @return Checksum of buffer.
 */
ULONG ChecksumCompute(PVOID Data, int Count, ULONG Seed)    
{
    register ULONG Sum = Seed;

    while (Count > 1)
    {
        Sum += *(PUSHORT)Data;
        Count -= 2;
        Data = (PVOID)((PUCHAR)Data + 2);
    }

    /* Add left-over byte, if any */
    if (Count > 0)
    {
        Sum += *(PUCHAR)Data;
    }

    return Sum;
}

USHORT Checksum(PVOID Data, int Count)
{
    ULONG Sum = ChecksumCompute(Data, Count, 0);
    return ChecksumEnd(Sum);
}
//--------------------------------------------------------------------------------------
char *inet_ntoa(ULONG Addr)
{
    static char buff[4 * sizeof("123")];
    PUCHAR ucp = (PUCHAR)&Addr;

    sprintf(buff, "%d.%d.%d.%d",
        ucp[0] & 0xff,
        ucp[1] & 0xff,
        ucp[2] & 0xff,
        ucp[3] & 0xff);

    return buff;
}
//--------------------------------------------------------------------------------------
// EoF
