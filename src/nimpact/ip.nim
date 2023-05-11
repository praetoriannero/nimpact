import std/json
import std/nativesockets
import strformat
import strutils

import address
import pdu
import byte_stream

type
    IPv4Option* = object
        ipOpt: uint8
        ipOptLen: uint8
        ipOptVal: ptr uint8

    IPv4Header {.packed.} = object
        ipVersion: uint16
        ipTotalLen: uint16
        ipId: uint16
        ipOffset: uint16
        ipTtl: uint16
        ipChecksum: uint16
        ipSrc: IPv4Address
        ipDst: IPv4Address

    IPv4* = object of PDU
        header: IPv4Header
        optsBuffer: ByteStream
        opts*: seq[IPv4Option]
        payload*: ByteStream

const
    ipHOPOPTS* = 0  # IPv6 hop-by-hop options
    ipICMP* = 1  # ICMP
    ipIGMP* = 2  # IGMP
    ipGGP* = 3  # gateway-gateway protocol
    ipIPIP* = 4  # IP in IP
    ipST* = 5  # ST datagram mode
    ipTCP* = 6  # TCP
    ipCBT* = 7  # CBT
    ipEGP* = 8  # exterior gateway protocol
    ipIGP* = 9  # interior gateway protocol
    ipBBNRCC* = 10  # BBN RCC monitoring
    ipNVP* = 11  # Network Voice Protocol
    ipPUP* = 12  # PARC universal packet
    ipARGUS* = 13  # ARGUS
    ipEMCON* = 14  # EMCON
    ipXNET* = 15  # Cross Net Debugger
    ipCHAOS* = 16  # Chaos
    ipUDP* = 17  # UDP
    ipMUX* = 18  # multiplexing
    ipDCNMEAS* = 19  # DCN measurement
    ipHMP* = 20  # Host Monitoring Protocol
    ipPRM* = 21  # Packet Radio Measurement
    ipIDP* = 22  # Xerox NS IDP
    ipTRUNK1* = 23  # Trunk-1
    ipTRUNK2* = 24  # Trunk-2
    ipLEAF1* = 25  # Leaf-1
    ipLEAF2* = 26  # Leaf-2
    ipRDP* = 27  # "Reliable Datagram" proto
    ipIRTP* = 28  # Inet Reliable Transaction
    ipTP* = 29  # ISO TP class 4
    ipNETBLT* = 30  # Bulk Data Transfer
    ipMFPNSP* = 31  # MFE Network Services
    ipMERITINP* = 32  # Merit Internodal Protocol
    ipSEP* = 33  # Sequential Exchange proto
    ipPC3* = 34  # Third Party Connect proto
    ipIDPR* = 35  # Interdomain Policy Route
    ipXTP* = 36  # Xpress Transfer Protocol
    ipDDP* = 37  # Datagram Delivery Proto
    ipCMTP* = 38  # IDPR Ctrl Message Trans
    ipTPPP* = 39  # TP++ Transport Protocol
    ipIL* = 40  # IL Transport Protocol
    ipIP6* = 41  # IPv6
    ipSDRP* = 42  # Source Demand Routing
    ipROUTING* = 43  # IPv6 routing header
    ipFRAGMENT* = 44  # IPv6 fragmentation header
    ipRSVP* = 46  # Reservation protocol
    ipGRE* = 47  # General Routing Encap
    ipMHRP* = 48  # Mobile Host Routing
    ipENA* = 49  # ENA
    ipESP* = 50  # Encap Security Payload
    ipAH* = 51  # Authentication Header
    ipINLSP* = 52  # Integated Net Layer Sec
    ipSWIPE* = 53  # SWIPE
    ipNARP* = 54  # NBMA Address Resolution
    ipMOBILE* = 55  # Mobile IP, RFC 2004
    ipTLSP* = 56  # Transport Layer Security
    ipSKIP* = 57  # SKIP
    ipICMP6* = 58  # ICMP for IPv6
    ipNONE* = 59  # IPv6 no next header
    ipDSTOPTS* = 60  # IPv6 destination options
    ipANYHOST* = 61  # any host internal proto
    ipCFTP* = 62  # CFTP
    ipANYNET* = 63  # any local network
    ipEXPAK* = 64  # SATNET and Backroom EXPAK
    ipKRYPTOLAN* = 65  # Kryptolan
    ipRVD* = 66  # MIT Remote Virtual Disk
    ipIPPC* = 67  # Inet Pluribus Packet Core
    ipDISTFS* = 68  # any distributed fs
    ipSATMON* = 69  # SATNET Monitoring
    ipVISA* = 70  # VISA Protocol
    ipIPCV* = 71  # Inet Packet Core Utility
    ipCPNX* = 72  # Comp Proto Net Executive
    ipCPHB* = 73  # Comp Protocol Heart Beat
    ipWSN* = 74  # Wang Span Network
    ipPVP* = 75  # Packet Video Protocol
    ipBRSATMON* = 76  # Backroom SATNET Monitor
    ipSUNND* = 77  # SUN ND Protocol
    ipWBMON* = 78  # WIDEBAND Monitoring
    ipWBEXPAK* = 79  # WIDEBAND EXPAK
    ipEON* = 80  # ISO CNLP
    ipVMTP* = 81  # Versatile Msg Transport
    ipSVMTP* = 82  # Secure VMTP
    ipVINES* = 83  # VINES
    ipTTP* = 84  # TTP
    ipNSFIGP* = 85  # NSFNET-IGP
    ipDGP* = 86  # Dissimilar Gateway Proto
    ipTCF* = 87  # TCF
    ipEIGRP* = 88  # EIGRP
    ipOSPF* = 89  # Open Shortest Path First
    ipSPRITERPC* = 90  # Sprite RPC Protocol
    ipLARP* = 91  # Locus Address Resolution
    ipMTP* = 92  # Multicast Transport Proto
    ipAX25* = 93  # AX.25 Frames
    ipIPIPENCAP* = 94  # yet-another IP encap
    ipMICP* = 95  # Mobile Internet Ctrl
    ipSCCSP* = 96  # Semaphore Comm Sec Proto
    ipETHERIP* = 97  # Ethernet in IPv4
    ipENCAP* = 98  # encapsulation header
    ipANYENC* = 99  # private encryption scheme
    ipGMTP* = 100  # GMTP
    ipIFMP* = 101  # Ipsilon Flow Mgmt Proto
    ipPNNI* = 102  # PNNI over IP
    ipPIM* = 103  # Protocol Indep Multicast
    ipARIS* = 104  # ARIS
    ipSCPS* = 105  # SCPS
    ipQNX* = 106  # QNX
    ipAN* = 107  # Active Networks
    ipIPCOMP* = 108  # IP Payload Compression
    ipSNP* = 109  # Sitara Networks Protocol
    ipCOMPAQPEER* = 110  # Compaq Peer Protocol
    ipIPXIP* = 111  # IPX in IP
    ipVRRP* = 112  # Virtual Router Redundancy
    ipPGM* = 113  # PGM Reliable Transport
    ipANY0HOP* = 114  # 0-hop protocol
    ipL2TP* = 115  # Layer 2 Tunneling Proto
    ipDDX* = 116  # D-II Data Exchange (DDX)
    ipIATP* = 117  # Interactive Agent Xfer
    ipSTP* = 118  # Schedule Transfer Proto
    ipSRP* = 119  # SpectraLink Radio Proto
    ipUTI* = 120  # UTI
    ipSMP* = 121  # Simple Message Protocol
    ipSM* = 122  # SM
    ipPTP* = 123  # Performance Transparency
    ipISIS* = 124  # ISIS over IPv4
    ipFIRE* = 125  # FIRE
    ipCRTP* = 126  # Combat Radio Transport
    ipCRUDP* = 127  # Combat Radio UDP
    ipSSCOPMCE* = 128  # SSCOPMCE
    ipIPLT* = 129  # IPLT
    ipSPS* = 130  # Secure Packet Shield
    ipPIPE* = 131  # Private IP Encap in IP
    ipSCTP* = 132  # Stream Ctrl Transmission
    ipFC* = 133  # Fibre Channel
    ipRSVPIGN* = 134  # RSVP-E2E-IGNORE
    ipMOBHEAD* = 135  # Mobility Header
    ipUDPLITE* = 136  # Lightweight UDP
    ipMPLS* = 137  # Multiprotocol Label Switching
    ipMANET* = 138  # MANET Protocols
    ipHIP* = 139  # Host Identity Protocol
    ipSHIM6* = 140  # Site Multihoming by IPv6
    ipWESP* = 141  # Wrapped Encapsulating Security Protocol
    ipROHC* = 142  # Robust Header Compression
    ipETH* = 143  # IPv6 Segment Routing (Temporary) 
    ipRESERVED* = 255  # Reserved

# {.push inline.}
# proc optKind*(opt: IPv4Option): uint8 =
#     return 

# proc newIPv4Option*(ip: var IPv4): IPv4Option =
    # moveMem(result.addr, buffer.pos, sizeof(result))
    # buffer.moveMem(result.header, sizeof(result.header))
    # buffer.align()

proc ihl*(ip: IPv4): uint8 =
    uint8(ntohs(ip.header.ipVersion)) and 0xF'u8

proc setOptions*(ip: var IPv4) =
    if ip.ihl == 5:
        return

proc version*(ip: IPv4): uint8 =
    uint8(ntohs(ip.header.ipVersion) shr 12)

proc tos*(ip: IPv4): uint8 =
    uint8(ntohs(ip.header.ipVersion) and 0xFF)

proc totalLen*(ip: IPv4): uint16 =
    ntohs(ip.header.ipTotalLen)

proc id*(ip: IPv4): uint16 =
    ntohs(ip.header.ipId)

proc flags*(ip: IPv4): uint8 =
    uint8(ntohl(ip.header.ipOffset) shr 13)

proc df*(ip: IPv4): uint8 =
    (ip.flags() shr 1) and 0x1

proc mf*(ip: IPv4): uint8 =
    ip.flags() and 0x1

proc fragOffset*(ip: IPv4): uint16 =
    ntohs(ip.header.ipOffset) and 0x1FFF

proc ttl*(ip: IPv4): uint8 =
    uint8(ntohs(ip.header.ipTtl) shr 8)

proc protocol*(ip: IPv4): uint8 =
    uint8(ntohs(ip.header.ipTtl) and 0xFF)

proc checksum*(ip: Ipv4): uint16 =
    ntohs(ip.header.ipChecksum)

proc source*(ip: IPv4): IPv4Address =
    ip.header.ipSrc

proc destination*(ip: IPv4): IPv4Address =
    ip.header.ipDst

proc ipv4AsJson*(ip: IPv4): JsonNode =
    result = %*{
        "IPv4": {
            "src": ip.source,
            "dst": ip.destination,
            "version": ip.version,
            "ihl": ip.ihl,
            "tos": ip.tos,
            "total_length": ip.totalLen,
            "id": ip.id,
            "flags": ip.flags.toHex,
            "df": bool(ip.df),
            "mf": bool(ip.mf),
            "fragment_offset": ip.fragOffset,
            "ttl": ip.ttl,
            "protocol": ip.protocol,
            "checksum": ip.checksum,
            # "payload": ip.childPDU[].asJson
        }
    }

proc `$`*(ip: IPv4): string =
    return &"IPv4<src={$ip.source}, dst={$ip.destination}, version={ip.version}>"

proc newIPv4*(buffer: var ByteStream): IPv4 =
    buffer.moveMem(result.header)

    let optSize = int(result.ihl) - 5
    if optSize > 0:
        result.optsBuffer = buffer.newInnerBuffer(optSize)
        buffer.skipBytes(optSize)

    # echo($result)
    # echo(result.addr.repr)
    result.payload = buffer.newInnerBuffer()
    # result.asJson = result.ipv4AsJson()

# {.pop.}
