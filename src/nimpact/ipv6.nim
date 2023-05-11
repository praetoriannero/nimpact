import std/nativesockets
# import strformat
# import strutils

import byte_stream
# import ip
import pdu

type
    IPv6Address* = object
        address: array[16, byte]

    HopByHopHeader = object
        nextHeader: uint8
        extensionLen: uint8
        optsPadding1: uint16
        optsPadding2: uint32
        optional: array[8, byte]

    HopByHop* = object of PDU
        header: HopByHopHeader

    RoutingHeader = object
        nextHeader: uint8
        extensionLen: uint8
        routingType: uint8
        segmentsLeft: uint8
        typeSpecificData: uint32
        optional: array[8, byte]

    Routing* = object of PDU
        header: RoutingHeader

    FragmentHeader = object
        nextHeader: uint8
        reserved: uint8
        fragOffset: uint16
        id: uint16

    Fragment* = object of PDU
        header: FragmentHeader

    IPv6Header {.packed.} = object
        version: uint32
        payloadLen: uint16
        nextHeader: uint16
        source: IPv6Address
        dest: IPv6Address

    IPv6* = object of PDU
        header: IPv6Header
        optsBuffer: ByteStream
        opts*: seq[PDU]
        payload*: ByteStream

proc version*(ip6: IPv6): uint8 =
    return uint8(ntohl(ip6.header.version) shr 28)

proc trafficClass*(ip6: IPv6): uint8 =
    return uint8((ntohl(ip6.header.version) shr 20) and 0xFF)

proc flowLabel*(ip6: IPv6): uint32 =
    return ntohl(ip6.header.version) and 0xFFFFF

proc payloadLen*(ip6: IPv6): uint16 =
    return ntohs(ip6.header.payloadLen)

proc nextHeader*(ip6: IPv6): uint8 =
    return uint8(ntohs(ip6.header.nextHeader) shr 8)

proc hopLimit*(ip6: IPv6): uint8 =
    return uint8(ntohs(ip6.header.nextHeader) and 0xFF)

proc src*(ip6: IPv6): IPv6Address =
    return ip6.header.source

proc dst*(ip6: IPv6): IPv6Address =
    return ip6.header.dest

proc newIPv6*(buffer: var ByteStream): IPv6 =
    buffer.moveMem(result.header)

