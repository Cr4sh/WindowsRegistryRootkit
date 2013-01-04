
#define NET_MAC_ADDR_LEN 6

#include <pshpack1.h>
typedef struct _NET_ETH_HEADER
{
    UCHAR  Dst[NET_MAC_ADDR_LEN];
    UCHAR  Src[NET_MAC_ADDR_LEN];
    USHORT Type;

} NET_ETH_HEADER,
*PNET_ETH_HEADER;
#include <poppack.h>

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_ARP	0x0806		/* Address Resolution packet	*/

#define ETH_IS_BCAST_ADDR(Addr)                                     \
                                                                    \
    (((Addr)[0] == 0xff) && ((Addr)[1] == 0xff) &&                  \
     ((Addr)[2] == 0xff) && ((Addr)[3] == 0xff) &&                  \
     ((Addr)[4] == 0xff) && ((Addr)[5] == 0xff))


#define ETH_MATCH_ADDR(Addr1, Addr2)                                \
                                                                    \
    (((Addr1)[0] == (Addr2)[0]) && ((Addr1)[1] == (Addr2)[1]) &&    \
     ((Addr1)[2] == (Addr2)[2]) && ((Addr1)[3] == (Addr2)[3]) &&    \
     ((Addr1)[4] == (Addr2)[4]) && ((Addr1)[5] == (Addr2)[5]))


/* Standard well-defined IP protocols.  */ 
enum 
{ 
    IPPROTO_IP =     0,   /* Dummy protocol for TCP               */ 
    IPPROTO_ICMP =   1,   /* Internet Control Message Protocol    */ 
    IPPROTO_IGMP =   2,   /* Internet Group Management Protocol   */ 
    IPPROTO_TCP =    6,   /* Transmission Control Protocol        */ 
    IPPROTO_UDP =   17,   /* User Datagram Protocol               */ 
    IPPROTO_SCTP = 132,   /* Stream Control Transport Protocol    */ 
    IPPROTO_RAW  = 255,   /* Raw IP packets                       */ 
};

#include <pshpack1.h>
typedef struct _NET_IPv4_HEADER
{
    UCHAR  HeaderLength:4, Version:4;
    UCHAR  TypeOfService;
    USHORT TotalLength;
    USHORT Id;
    USHORT FragmentOffset;
    UCHAR  TimeToLive;
    UCHAR  Protocol;
    USHORT Checksum;
    ULONG  Src;
    ULONG  Dst;

} NET_IPv4_HEADER, 
*PNET_IPv4_HEADER;
#include <poppack.h>

// unsigned long to TCP/IP network byte order
#define HTONL(_a_)                  \
                                    \
    ((((_a_) & 0x000000FF) << 24) + \
     (((_a_) & 0x0000FF00) << 8)  + \
     (((_a_) & 0x00FF0000) >> 8)  + \
     (((_a_) & 0xFF000000) >> 24))

// unsigned short to TCP/IP network byte order
#define HTONS(_a_)                  \
                                    \
    (((0x00FF & (_a_)) << 8) +      \
     ((0xFF00 & (_a_)) >> 8))


SHORT ChecksumEnd(ULONG Sum);
ULONG ChecksumCompute(PVOID Data, int Count, ULONG Seed);
USHORT Checksum(PVOID Data, int Count);
char *inet_ntoa(ULONG Addr);
