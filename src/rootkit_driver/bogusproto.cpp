
#include "stdafx.h"

// NDIS version: 5.1
#define NDIS51 1

extern "C"
{
#include <ndis.h>
}

NDIS_HANDLE m_hBogusProtocol = NULL;
//--------------------------------------------------------------------------------------
VOID OnBindAdapter(
    PNDIS_STATUS Status,
    NDIS_HANDLE BindContext,
    PNDIS_STRING DeviceNAme,
    PVOID SystemSpecific1,
    PVOID SystemSpecific2)
{
    /*
        This function is a required driver function to support Plug and Play.
    */

#ifdef DBG_NDIS_PROT

    DbgMsg(__FUNCTION__"() called\n");

#endif
}
//--------------------------------------------------------------------------------------
VOID OnOpenAdapterComplete(
    NDIS_HANDLE ProtocolBindingContext,
    NDIS_STATUS Status,
    NDIS_STATUS OpenErrorStatus)
{
    /*
        This function is a required driver function that completes processing of a binding 
        operation for which NdisOpenAdapter returned NDIS_STATUS_PENDING.
    */

#ifdef DBG_NDIS_PROT

    DbgMsg(__FUNCTION__"() called\n");

#endif
}
//--------------------------------------------------------------------------------------
VOID OnUnbindAdapter(
    PNDIS_STATUS Status,
    NDIS_HANDLE ProtocolBindingContext,
    NDIS_HANDLE UnbindContext)
{
    /*
        This function is a required function to support Plug and Play.
    */

#ifdef DBG_NDIS_PROT

    DbgMsg(__FUNCTION__"() called\n");

#endif
}
//--------------------------------------------------------------------------------------
VOID OnUnload(VOID)
{
#ifdef DBG_NDIS_PROT

    DbgMsg(__FUNCTION__"() called\n");

#endif
}
//--------------------------------------------------------------------------------------
VOID OnCloseAdapterComplete(
    NDIS_HANDLE ProtocolBindingContext,
    NDIS_STATUS Status)
{
    /*
        This function is a required driver function that completes processing for an unbinding 
        operation for which NdisCloseAdapter returned NDIS_STATUS_PENDING.
    */

#ifdef DBG_NDIS_PROT

    DbgMsg(__FUNCTION__"() called\n");

#endif
}
//--------------------------------------------------------------------------------------
VOID OnResetComplete(
    NDIS_HANDLE ProtocolBindingContext,
    NDIS_STATUS Status)
{
    /*
        This function is a required driver function that completes a protocol-initiated reset 
        operation for which NdisReset returned NDIS_STATUS_PENDING.
    */

#ifdef DBG_NDIS_PROT

    DbgMsg(__FUNCTION__"() called\n");

#endif
}
//--------------------------------------------------------------------------------------
VOID OnRequestComplete(
    NDIS_HANDLE ProtocolBindingContext,
    PNDIS_REQUEST NdisRequest,
    NDIS_STATUS Status)
{
    /*
        This function is a required driver function that completes the processing of a 
        protocol-initiated query or set for which NdisRequest returned NDIS_STATUS_PENDING.
    */

#ifdef DBG_NDIS_PROT

    DbgMsg(__FUNCTION__"() called\n");

#endif
}
//--------------------------------------------------------------------------------------
VOID OnStatus(
    NDIS_HANDLE ProtocolBindingContext,
    NDIS_STATUS GeneralStatus,
    PVOID StatusBuffer,
    UINT StatusBufferSize)
{
    /*
        This function is a required driver function that handles status-change notifications 
        raised by an underlying connectionless network adapter driver or by NDIS.
    */

#ifdef DBG_NDIS_PROT

    DbgMsg(__FUNCTION__"() called\n");

#endif
}
//--------------------------------------------------------------------------------------
VOID OnStatusComplete(NDIS_HANDLE ProtocolBindingContext)
{
    /*
        This function is a required driver function that completes a status-change operation 
        initiated when the underlying driver called NdisMIndicateStatus.
    */

#ifdef DBG_NDIS_PROT

    DbgMsg(__FUNCTION__"() called\n");

#endif
}
//--------------------------------------------------------------------------------------
VOID OnSendComplete(
    NDIS_HANDLE ProtocolBindingContext,
    PNDIS_PACKET Packet,
    NDIS_STATUS Status)
{
    /*
        This function is a required driver function that completes the processing of a 
        protocol-initiated send previously passed to NdisSendPackets or NdisSend, which 
        returned NDIS_STATUS_PENDING.
    */

#ifdef DBG_NDIS_PROT

    DbgMsg(__FUNCTION__"() called\n");

#endif
}       
//--------------------------------------------------------------------------------------
VOID OnTransferDataComplete(
    NDIS_HANDLE ProtocolBindingContext,
    PNDIS_PACKET Packet,
    NDIS_STATUS Status,
    UINT BytesTransferred)
{
    /*
        This function is a required driver function if the protocol might bind itself to an 
        underlying connectionless network adapter driver that does not indicate full-packet 
        receives with NdisMIndicateReceivePacket. ProtocolTransferDataComplete completes the 
        processing of a protocol-initiated transfer-data request for which NdisTransferData 
        returned NDIS_STATUS_PENDING.
    */

#ifdef DBG_NDIS_PROT

    DbgMsg(__FUNCTION__"() called\n");

#endif
}
//--------------------------------------------------------------------------------------
NDIS_STATUS OnReceive(
    NDIS_HANDLE ProtocolBindingContext,
    NDIS_HANDLE MacReceiveContext,
    PVOID HeaderBuffer,
    UINT HeaderBufferSize,
    PVOID LookAheadBuffer,
    UINT LookAheadBufferSize,
    UINT PacketSize)
{
    /*
        This function is a required driver function in NDIS protocols that bind themselves 
        to connectionless network adapter drivers. ProtocolReceive determines whether a received 
        network packet is of interest to the protocol's clients and, if so, copies the indicated 
        data and, possibly, calls NdisTransferData to retrieve the rest of the indicated packet.
    */

#ifdef DBG_NDIS_PROT

    DbgMsg(__FUNCTION__"() called\n");

#endif

    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------
VOID OnReceiveComplete(NDIS_HANDLE ProtocolBindingContext)
{
    /*
        This function is a required driver function in any protocol. ProtocolReceiveComplete 
        completes post-processing of one or more preceding receive indications from a network 
        adapter driver.
    */

#ifdef DBG_NDIS_PROT

    DbgMsg(__FUNCTION__"() called\n");

#endif
}
//--------------------------------------------------------------------------------------
INT OnReceivePacket(
    NDIS_HANDLE ProtocolBindingContext,
    PNDIS_PACKET Packet)
{
    /*
        ProtocolReceivePacket is an optional driver function that processes receive indications 
        made by underlying connectionless NIC driver(s) that call either NdisMIndicateReceivePacket 
        with packet arrays because the underlying driver supports multipacket receive indications 
        or with individual packets that have associated out-of-band information. A call to 
        ProtocolReceivePacket can also occur as a result of loopback.
    */

#ifdef DBG_NDIS_PROT

    DbgMsg(__FUNCTION__"() called\n");

#endif

    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------
NDIS_STATUS OnPnPHandler(
    NDIS_HANDLE ProtocolBindingContext,
    PNET_PNP_EVENT pNetPnPEvent)
{
#ifdef DBG_NDIS_PROT

    DbgMsg(__FUNCTION__"() called\n");

#endif
    
    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------
NDIS_STATUS OnPnPNetEventReconfigure(
    ULONG pAdapt,
    PNET_PNP_EVENT pNetPnPEvent)
{
#ifdef DBG_NDIS_PROT

    DbgMsg(__FUNCTION__"() called\n");

#endif
    
    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------
NDIS_STATUS OnPnPNetEventSetPower(
    ULONG pAdapt,
    PNET_PNP_EVENT pNetPnPEvent)
{
#ifdef DBG_NDIS_PROT

    DbgMsg(__FUNCTION__"() called\n");
    
#endif

    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------
NDIS_HANDLE BogusProtocolRegister(void)
{
    if (m_hBogusProtocol)
    {
#ifdef DBG_NDIS_PROT

        // protocol is allready registered
        DbgMsg(__FUNCTION__"(): Protocol is allready registered\n");

#endif
        return m_hBogusProtocol;
    }

    NDIS_STATUS status = STATUS_SUCCESS;    
    NDIS_PROTOCOL_CHARACTERISTICS Protocol;    

    // fill protocol characteristics structure
    NdisZeroMemory(&Protocol, sizeof(Protocol));
    Protocol.Ndis40Chars.MajorNdisVersion = 0x05;
    Protocol.Ndis40Chars.MinorNdisVersion = 0x0;

    Protocol.Ndis40Chars.OpenAdapterCompleteHandler = OnOpenAdapterComplete;
    Protocol.Ndis40Chars.CloseAdapterCompleteHandler = OnCloseAdapterComplete;
    Protocol.Ndis40Chars.SendCompleteHandler = OnSendComplete;
    Protocol.Ndis40Chars.TransferDataCompleteHandler = OnTransferDataComplete;
    Protocol.Ndis40Chars.ResetCompleteHandler = OnResetComplete;
    Protocol.Ndis40Chars.RequestCompleteHandler = OnRequestComplete;
    Protocol.Ndis40Chars.ReceiveHandler = OnReceive;
    Protocol.Ndis40Chars.ReceiveCompleteHandler = OnReceiveComplete;
    Protocol.Ndis40Chars.StatusHandler = OnStatus;
    Protocol.Ndis40Chars.StatusCompleteHandler = OnStatusComplete;
    Protocol.Ndis40Chars.BindAdapterHandler = OnBindAdapter;
    Protocol.Ndis40Chars.UnbindAdapterHandler = OnUnbindAdapter;
    Protocol.Ndis40Chars.UnloadHandler = OnUnload;
    Protocol.Ndis40Chars.ReceivePacketHandler = OnReceivePacket;
    Protocol.Ndis40Chars.PnPEventHandler = OnPnPHandler;

    NDIS_STRING ProtocolName;
    NdisInitUnicodeString(&ProtocolName, L"BogusProto");
    Protocol.Ndis40Chars.Name = ProtocolName;

    // register our bogus protocol
    NdisRegisterProtocol(
        &status, 
        &m_hBogusProtocol, 
        &Protocol, 
        sizeof(Protocol)
    );
    if (status != NDIS_STATUS_SUCCESS)
    {
        DbgMsg("NdisRegisterProtocol() fails; status: 0x%.8x\n", status);
        return NULL;
    }
 
#ifdef DBG_NDIS_PROT

    DbgMsg(__FUNCTION__"(): Protocol registered\n");

#endif

    return m_hBogusProtocol;    
}
//--------------------------------------------------------------------------------------
void BogusProtocolUnregister(void)
{
    if (m_hBogusProtocol)
    {
        NDIS_STATUS status = STATUS_SUCCESS;
        NdisDeregisterProtocol(&status, m_hBogusProtocol);
        m_hBogusProtocol = NULL;
    }    
}
//--------------------------------------------------------------------------------------
// EoF
