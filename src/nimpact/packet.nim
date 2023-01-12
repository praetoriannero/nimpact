import libpcap

import byte_stream
import pdu

type
    Packet* = object
        bytes*: ptr byte
        header*: PcapPacketHeader
        payload*: ByteStream
        pdus*: seq[PDU]

proc newPacket*(packetPtr: ptr byte, header: PcapPacketHeader): Packet =
    result = Packet(
        bytes: packetPtr,
        header: header,
        payload: newByteStream(packetPtr, int(header.len)),
        pdus: @[]
    )

# proc findPDU*[T](packet: var Packet): T =
#     packet.buffer.readBytes(result)
#     return result