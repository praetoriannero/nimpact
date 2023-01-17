import std/nativesockets
import strformat
import strutils

import pdu
import byte_stream

type
    IPv6Address* = object
        address: array[16, byte]

    IPv6Option* = object of RootObj

    HopByHopHeader = object
        nextHeader: uint8
        extensionLen: uint8
        optsPadding1: uint16
        optsPadding2: uint32
        optional: array[8, byte]

    HopByHop* = object of IPv6Option
        header: HopByHopHeader

    RoutingHeader = object
        nextHeader: uint8
        extensionLen: uint8
        routingType: uint8
        segmentsLeft: uint8
        typeSpecificData: uint32
        optional: array[8, byte]

    Routing* = object of IPv6Option
        header: RoutingHeader

    FragmentHeader = object
        nextHeader: uint8
        reserved: uint8
        fragOffset: uint16
        id: uint16

    Fragment* = object of IPv6Option
        header: FragmentHeader

    IPv6Header {.packed.} = object
        version: uint32
        payloadLen: uint16
        nextHeader: uint8
        hopLim: uint8
        source: IPv6Address
        dest: IPv6Address

    ExtensionHeader* = enum
        ehHopByHop = 0
        ehRouting = 43
        ehFragment = 44
        ehESP = 50
        ehAH = 51
        ehDestOptions = 60
        ehMobility = 135
        ehHostIdentityProto = 139
        ehShim6 = 140

    IPv6* = object of PDU
        header: IPv6Header
        optsBuffer: ByteStream
        opts*: seq[IPv6Option]
        payload*: ByteStream

proc newIPv6*(buffer: var ByteStream): IPv6 =
    buffer.moveMem(result.header)
