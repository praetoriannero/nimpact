import libpcap
import std/bitops

import byte_stream
import ethernet
import pdu

type
    Packet* = object
        bytes*: ptr byte
        header*: PcapPacketHeader
        payload*: ByteStream
        pdu*: PDU

proc newPacket*(packetPtr: ptr byte, header: PcapPacketHeader): Packet =
    result = Packet(
        bytes: packetPtr,
        header: header,
        payload: newByteStream(packetPtr, int(header.len))
    )

proc getPduChain*(pkt: Packet): seq[PduType] =
    var pduPtr: ptr PDU = pkt.pdu.childPDU
    result = newSeq[PduType](0)
    result.add(pkt.pdu.pduType)
    while pduPtr != nil:
        result.add(pduPtr[].pduType)
        pduPtr = pduPtr.childPDU

proc deserialize*(pkt: var Packet) =
    # var preamble: array[8, uint8]
    # pkt.payload.peekMem(preamble[0], preamble.len)
    # if preamble == stpFlag:
    #     return

    pkt.pdu = newEthernetII(pkt.payload)
