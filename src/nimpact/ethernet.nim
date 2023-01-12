import std/nativesockets
import strutils
import strformat

import byte_stream
import pdu

type
    MacAddress* = array[6, byte]

    EthernetHeader {.packed.} = object
        ethDst: MacAddress
        ethSrc: MacAddress
        ethType: uint16

    EthernetII* = object of PDU
        header: EthernetHeader
        payload*: ByteStream

    EthernetType* = enum
        etUnknown = 0x0000
        etEDP = 0x00bb  # Extreme Networks Discovery Protocol
        etPUP = 0x0200  # PUP protocol
        etIP = 0x0800  # IP protocol
        etARP = 0x0806  # address resolution protocol
        etCDP = 0x2000  # Cisco Discovery Protocol
        etDTP = 0x2004  # Cisco Dynamic Trunking Protocol
        etTEB = 0x6558  # Transparent Ethernet Bridging
        etREVARP = 0x8035  # reverse addr resolution protocol
        et8021Q = 0x8100  # IEEE 802.1Q VLAN tagging
        etIPX = 0x8137  # Internetwork Packet Exchange
        etIP6 = 0x86DD  # IPv6 protocol
        etPPP = 0x880B  # PPP
        etMPLS = 0x8847  # MPLS
        etMPLS_MCAST = 0x8848  # MPLS Multicast
        etPPPoE_DISC = 0x8863  # PPP Over Ethernet Discovery Stage
        etPPPoE = 0x8864  # PPP Over Ethernet Session Stage
        etPROFINET = 0x8892  # PROFINET protocol
        etAOE = 0x88a2  # AoE protocol
        et8021AD = 0x88a8  # IEEE 802.1ad
        etLLDP = 0x88CC  # Link Layer Discovery Protocol
        etQINQ1 = 0x9100  # Legacy QinQ
        etQINQ2 = 0x9200  # Legacy QinQ

# {.push inline.}

proc newEthernetII*(buffer: var ByteStream): EthernetII =
    buffer.moveMem(result.header, sizeof(result.header))
    result.payload = buffer.newInnerBuffer()

proc newEthernetII*(src: MacAddress, dst: MacAddress, kind: uint16): EthernetII =
    return result

proc destination*(eth: EthernetII): MacAddress =
    return eth.header.ethDst

proc source*(eth: EthernetII): MacAddress =
    return eth.header.ethSrc

proc type*(eth: EthernetII): uint16 =
    return ntohs(eth.header.ethType)

# proc pduType*(eth: EthernetII): PDUType =
#     return PDUType.pduEthernetII

proc `$`*(mac: MacAddress): string =
    var tempArray: array[6, string]
    for i in 0..<mac.len:
        tempArray[i] = mac[i].toHex

    return join(tempArray, ":")

proc `$`*(eth: EthernetII): string =
    return &"EthernetII(dst={$eth.destination}, src={$eth.source}, type={eth.type.toHex})"

# {.pop.}
