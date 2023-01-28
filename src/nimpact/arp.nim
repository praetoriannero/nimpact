import std/nativesockets
import strformat

import address
import byte_stream
import pdu

type
    ARPHeader {.packed.} = object
        htype: uint16
        ptype: uint16
        lens: uint16
        oper: uint16
        sha: MacAddress
        spa: IPv4Address
        tha: MacAddress
        tpa: IPv4Address

    ARP* = object of PDU
        header: ARPHeader
        payload*: ByteStream
    
proc htype*(arp: ARP): uint16 =
    return ntohs(arp.header.htype)

proc ptype*(arp: ARP): uint16 =
    return ntohs(arp.header.ptype)

proc hlen*(arp: ARP): uint8 =
    return uint8(ntohs(arp.header.lens) shr 8)

proc plen*(arp: ARP): uint8 =
    return uint8(ntohs(arp.header.lens) and 0xF)

proc oper*(arp: ARP): uint16 =
    return ntohs(arp.header.oper)

proc sha*(arp: ARP): MacAddress =
    return arp.header.sha

proc spa*(arp: ARP): IPv4Address =
    return arp.header.spa

proc tha*(arp: ARP): MacAddress =
    return arp.header.tha

proc tpa*(arp: ARP): IPv4Address =
    return arp.header.tpa

proc newARP*(buffer: var ByteStream): ARP =
    buffer.moveMem(result.header, sizeof(result.header))
    result.payload = buffer.newInnerBuffer()
