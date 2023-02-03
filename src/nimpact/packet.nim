import libpcap
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

proc deserialize*(pkt: var Packet) =
    # var preamble: array[8, uint8]
    # pkt.payload.peekMem(preamble[0], preamble.len)
    # if preamble == stpFlag:
    #     return

    pkt.pdu = newEthernetII(pkt.payload)

# proc findPDU*[T](packet: var Packet): T =
#     packet.buffer.readBytes(result)
#     return result