import std/nativesockets

import byte_stream
import pdu

type
    UDPHeader* = object
        udpSourcePort: uint16
        udpDestPort: uint16
        udpLength: uint16
        udpChecksum: uint16

    UDP* = object of PDU
        header: UDPHeader
        payload*: ByteStream

proc newUDP*(buffer: var ByteStream): UDP =
    buffer.moveMem(result.header)
    result.payload = buffer.newInnerBuffer()

proc sourcePort*(udp: UDP): uint16 =
    return ntohs(udp.header.udpSourcePort)

proc destinationPort*(udp: UDP): uint16 =
    return ntohs(udp.header.udpDestPort)

proc length*(udp: UDP): uint16 =
    return ntohs(udp.header.udpLength)

proc checksum*(udp: UDP): uint16 =
    return ntohs(udp.header.udpChecksum)
