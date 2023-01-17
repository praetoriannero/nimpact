import std/nativesockets
import strformat
import strutils

import pdu
import byte_stream
# import tcp
# import udp

type
    IPv4Address* = array[4, byte]

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

    ProtocolType* = enum
        HOPOPTS = 0  # IPv6 hop-by-hop options
        ICMP = 1  # ICMP
        IGMP = 2  # IGMP
        GGP = 3  # gateway-gateway protocol
        IPIP = 4  # IP in IP
        ST = 5  # ST datagram mode
        TCP = 6  # TCP
        CBT = 7  # CBT
        EGP = 8  # exterior gateway protocol
        IGP = 9  # interior gateway protocol
        BBNRCC = 10  # BBN RCC monitoring
        NVP = 11  # Network Voice Protocol
        PUP = 12  # PARC universal packet
        ARGUS = 13  # ARGUS
        EMCON = 14  # EMCON
        XNET = 15  # Cross Net Debugger
        CHAOS = 16  # Chaos
        UDP = 17  # UDP
        MUX = 18  # multiplexing
        DCNMEAS = 19  # DCN measurement
        HMP = 20  # Host Monitoring Protocol
        PRM = 21  # Packet Radio Measurement
        IDP = 22  # Xerox NS IDP
        TRUNK1 = 23  # Trunk-1
        TRUNK2 = 24  # Trunk-2
        LEAF1 = 25  # Leaf-1
        LEAF2 = 26  # Leaf-2
        RDP = 27  # "Reliable Datagram" proto
        IRTP = 28  # Inet Reliable Transaction
        TP = 29  # ISO TP class 4
        NETBLT = 30  # Bulk Data Transfer
        MFPNSP = 31  # MFE Network Services
        MERITINP = 32  # Merit Internodal Protocol
        SEP = 33  # Sequential Exchange proto
        PC3 = 34  # Third Party Connect proto
        IDPR = 35  # Interdomain Policy Route
        XTP = 36  # Xpress Transfer Protocol
        DDP = 37  # Datagram Delivery Proto
        CMTP = 38  # IDPR Ctrl Message Trans
        TPPP = 39  # TP++ Transport Protocol
        IL = 40  # IL Transport Protocol
        IP6 = 41  # IPv6
        SDRP = 42  # Source Demand Routing
        ROUTING = 43  # IPv6 routing header
        FRAGMENT = 44  # IPv6 fragmentation header
        RSVP = 46  # Reservation protocol
        GRE = 47  # General Routing Encap
        MHRP = 48  # Mobile Host Routing
        ENA = 49  # ENA
        ESP = 50  # Encap Security Payload
        AH = 51  # Authentication Header
        INLSP = 52  # Integated Net Layer Sec
        SWIPE = 53  # SWIPE
        NARP = 54  # NBMA Address Resolution
        MOBILE = 55  # Mobile IP, RFC 2004
        TLSP = 56  # Transport Layer Security
        SKIP = 57  # SKIP
        ICMP6 = 58  # ICMP for IPv6
        NONE = 59  # IPv6 no next header
        DSTOPTS = 60  # IPv6 destination options
        ANYHOST = 61  # any host internal proto
        CFTP = 62  # CFTP
        ANYNET = 63  # any local network
        EXPAK = 64  # SATNET and Backroom EXPAK
        KRYPTOLAN = 65  # Kryptolan
        RVD = 66  # MIT Remote Virtual Disk
        IPPC = 67  # Inet Pluribus Packet Core
        DISTFS = 68  # any distributed fs
        SATMON = 69  # SATNET Monitoring
        VISA = 70  # VISA Protocol
        IPCV = 71  # Inet Packet Core Utility
        CPNX = 72  # Comp Proto Net Executive
        CPHB = 73  # Comp Protocol Heart Beat
        WSN = 74  # Wang Span Network
        PVP = 75  # Packet Video Protocol
        BRSATMON = 76  # Backroom SATNET Monitor
        SUNND = 77  # SUN ND Protocol
        WBMON = 78  # WIDEBAND Monitoring
        WBEXPAK = 79  # WIDEBAND EXPAK
        EON = 80  # ISO CNLP
        VMTP = 81  # Versatile Msg Transport
        SVMTP = 82  # Secure VMTP
        VINES = 83  # VINES
        TTP = 84  # TTP
        NSFIGP = 85  # NSFNET-IGP
        DGP = 86  # Dissimilar Gateway Proto
        TCF = 87  # TCF
        EIGRP = 88  # EIGRP
        OSPF = 89  # Open Shortest Path First
        SPRITERPC = 90  # Sprite RPC Protocol
        LARP = 91  # Locus Address Resolution
        MTP = 92  # Multicast Transport Proto
        AX25 = 93  # AX.25 Frames
        IPIPENCAP = 94  # yet-another IP encap
        MICP = 95  # Mobile Internet Ctrl
        SCCSP = 96  # Semaphore Comm Sec Proto
        ETHERIP = 97  # Ethernet in IPv4
        ENCAP = 98  # encapsulation header
        ANYENC = 99  # private encryption scheme
        GMTP = 100  # GMTP
        IFMP = 101  # Ipsilon Flow Mgmt Proto
        PNNI = 102  # PNNI over IP
        PIM = 103  # Protocol Indep Multicast
        ARIS = 104  # ARIS
        SCPS = 105  # SCPS
        QNX = 106  # QNX
        AN = 107  # Active Networks
        IPCOMP = 108  # IP Payload Compression
        SNP = 109  # Sitara Networks Protocol
        COMPAQPEER = 110  # Compaq Peer Protocol
        IPXIP = 111  # IPX in IP
        VRRP = 112  # Virtual Router Redundancy
        PGM = 113  # PGM Reliable Transport
        ANY0HOP = 114  # 0-hop protocol
        L2TP = 115  # Layer 2 Tunneling Proto
        DDX = 116  # D-II Data Exchange (DDX)
        IATP = 117  # Interactive Agent Xfer
        STP = 118  # Schedule Transfer Proto
        SRP = 119  # SpectraLink Radio Proto
        UTI = 120  # UTI
        SMP = 121  # Simple Message Protocol
        SM = 122  # SM
        PTP = 123  # Performance Transparency
        ISIS = 124  # ISIS over IPv4
        FIRE = 125  # FIRE
        CRTP = 126  # Combat Radio Transport
        CRUDP = 127  # Combat Radio UDP
        SSCOPMCE = 128  # SSCOPMCE
        IPLT = 129  # IPLT
        SPS = 130  # Secure Packet Shield
        PIPE = 131  # Private IP Encap in IP
        SCTP = 132  # Stream Ctrl Transmission
        FC = 133  # Fibre Channel
        RSVPIGN = 134  # RSVP-E2E-IGNORE
        MOBHEAD = 135  # Mobility Header
        UDPLITE = 136  # Lightweight UDP
        MPLS = 137  # Multiprotocol Label Switching
        MANET = 138  # MANET Protocols
        HIP = 139  # Host Identity Protocol
        SHIM6 = 140  # Site Multihoming by IPv6
        WESP = 141  # Wrapped Encapsulating Security Protocol
        ROHC = 142  # Robust Header Compression
        ETH = 143  # IPv6 Segment Routing (Temporary) 
        RESERVED = 255  # Reserved

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

proc newIPv4*(buffer: var ByteStream): IPv4 =
    buffer.moveMem(result.header)

    let optSize = int(result.ihl) - 5
    if optSize > 0:
        result.optsBuffer = buffer.newInnerBuffer(optSize)
        buffer.skipBytes(optSize)

    result.payload = buffer.newInnerBuffer()

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

# proc pduType*(ip: IPv4): PDUType =
#     return PDUType.pduIPv4

proc `$`*(ip: IPv4Address): string =
    var tempArray: array[4, string]
    for i in 0..<ip.len:
        tempArray[i] = intToStr(int(ip[i]))

    result = join(tempArray, ".")

proc `$`*(ip: IPv4): string =
    return &"IPv4<src={$ip.source}, dst={$ip.destination}, version={ip.version}>"

# {.pop.}
