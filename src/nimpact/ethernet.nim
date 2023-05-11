# import std/json
import std/nativesockets
import strutils
import strformat

import address
import arp
import byte_stream
import pdu
import ip
import ipv6

const
    etUnknown* = 0x0000
    etEDP* = 0x00bb  # Extreme Networks Discovery Protocol
    etPUP* = 0x0200  # PUP protocol
    etIP* = 0x0800  # IP protocol
    etARP* = 0x0806  # address resolution protocol
    etCDP* = 0x2000  # Cisco Discovery Protocol
    etDTP* = 0x2004  # Cisco Dynamic Trunking Protocol
    etTEB* = 0x6558  # Transparent Ethernet Bridging
    etREVARP* = 0x8035  # reverse addr resolution protocol
    et8021Q* = 0x8100  # IEEE 802.1Q VLAN tagging
    etIPX* = 0x8137  # Internetwork Packet Exchange
    etIP6* = 0x86DD  # IPv6 protocol
    etPPP* = 0x880B  # PPP
    etMPLS* = 0x8847  # MPLS
    etMPLS_MCAST* = 0x8848  # MPLS Multicast
    etPPPoE_DISC* = 0x8863  # PPP Over Ethernet Discovery Stage
    etPPPoE* = 0x8864  # PPP Over Ethernet Session Stage
    etPROFINET* = 0x8892  # PROFINET protocol
    etAOE* = 0x88a2  # AoE protocol
    et8021AD* = 0x88a8  # IEEE 802.1ad
    etLLDP* = 0x88CC  # Link Layer Discovery Protocol
    etQINQ1* = 0x9100  # Legacy QinQ
    etQINQ2* = 0x9200  # Legacy QinQ

type
    EthernetHeader {.packed.} = object
        ethDst: MacAddress
        ethSrc: MacAddress
        ethType: uint16

    EthernetII* = object of PDU
        header: EthernetHeader
        payload*: ByteStream

    Dot1qHeader* {.packed.} = object
        dot1qTPID: uint16
        dot1qTCI: uint16
        dot1qType: uint8

    Dot1q* = object of PDU
        header: Dot1qHeader
        payload*: ByteStream

var parseEtherType*: proc(kind: int, payload: var ByteStream): ptr PDU {.inline.}

proc tpid*(dot1q: Dot1q): uint16 =
    result = ntohs(dot1q.header.dot1qTPID)

proc pcp*(dot1q: Dot1q): uint8 =
    result = uint8(ntohs(dot1q.header.dot1qTCI) shr 13)

proc dei*(dot1q: Dot1q): uint8 =
    result = uint8(ntohs(dot1q.header.dot1qTCI) shr 12) and 0x1

proc vid*(dot1q: Dot1q): uint16 =
    result = uint8(ntohs(dot1q.header.dot1qTCI) and 0xFFF)

proc newDot1q*(buffer: var ByteStream): Dot1q =
    buffer.moveMem(result.header)
    result.payload = buffer.newInnerBuffer()
    result.childPDU = parseEtherType(int(result.header.dot1qType), result.payload)

proc newEthernetII*(src: MacAddress, dst: MacAddress, kind: uint16): EthernetII =
    # will eventually add the function body for creating the struct from
    # field values instead of strictly deserializing...
    return result

proc destination*(eth: EthernetII): MacAddress =
    return eth.header.ethDst

proc source*(eth: EthernetII): MacAddress =
    return eth.header.ethSrc

proc kind*(eth: EthernetII): uint16 =
    return ntohs(eth.header.ethType)

proc `$`*(eth: EthernetII): string =
    return &"EthernetII(dst={$eth.destination}, src={$eth.source}, type={eth.kind.toHex})"

proc newEthernetII*(buffer: var ByteStream): EthernetII =
    buffer.moveMem(result.header, sizeof(result.header))
    result.payload = buffer.newInnerBuffer()
    var kind = int(result.kind())
    echo(kind)
    result.childPDU = parseEtherType(kind, result.payload)
    # result.childPDU[].parentPDU = result.addr
    echo(result.childPDU == nil)
    result.pduType = PduType.ptEthernet

parseEtherType = proc (kind: int, payload: var ByteStream): ptr PDU {.inline.} =
    var pdu: PDU
    case kind:
    of etIP:
        pdu = newIPv4(payload)
    of etIP6:
        pdu = newIPv6(payload)
    of etARP:
        pdu = newARP(payload)
    of et8021Q:
        pdu = newDot1q(payload)
    else:
        pdu = newUnknownPDU(payload)

    # var temp = cast[IPv4](pdu)
    # echo(temp.addr.repr)
    echo(pdu.addr.repr)
    # echo(cast[IPv4](pdu).addr.repr)
    result = pdu.addr
    # echo(pdu.addr[])
    # return pdu.addr
