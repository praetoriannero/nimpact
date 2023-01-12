import std/nativesockets

import byte_stream
import pdu

const
    EndOfOpts* = 0x0'u8
    NoOp* = 0x1'u8
    MaxSegSize* = 0x2'u8
    WindowScale* = 0x3'u8
    SAckPermitted* = 0x4'u8
    SAck* = 0x5'u8
    Timestamp* = 0x8'u8

type
    TCPOption* {.packed.} = object
        kind: uint8
        len: uint8
        val: seq[byte]

    TCPHeader {.packed.} = object
        tcpSrcPort: uint16
        tcpDstPort: uint16
        tcpSeqNum: uint32
        tcpAckNum: uint32
        tcpOffset: uint16
        tcpWindowSize: uint16
        tcpChecksum: uint16
        tcpUrgent: uint16

    TCP* {.packed.} = object of PDU
        header: TCPHeader
        optsBuffer: ByteStream
        opts*: seq[TCPOption]
        payload*: ByteStream

proc dataOffset*(tcp: TCP): uint8 =
    return uint8(ntohs(tcp.header.tcpOffset) shr 12)

proc newTCP*(buffer: var ByteStream): TCP =
    buffer.moveMem(result.header)

    let optSize = int(result.dataOffset) - 5
    if optSize > 0:
        result.optsBuffer = buffer.newInnerBuffer(optSize)
        buffer.skipBytes(optSize)

    result.payload = buffer.newInnerBuffer()

proc sourcePort*(tcp: TCP): uint16 =
    return ntohs(tcp.header.tcpSrcPort)

proc destinationPort*(tcp: TCP): uint16 =
    return ntohs(tcp.header.tcpDstPort)

proc seqNumber*(tcp: TCP): uint32 =
    return ntohl(tcp.header.tcpSeqNum)

proc ackNumber*(tcp: TCP): uint32 =
    return ntohl(tcp.header.tcpAckNum)

proc ns*(tcp: TCP): bool =
    return bool(ntohs(tcp.header.tcpOffset) shr 8 and 0x1)

proc cwr*(tcp: TCP): bool =
    return bool(ntohs(tcp.header.tcpOffset) shr 7 and 0x1)

proc ece*(tcp: TCP): bool =
    return bool(ntohs(tcp.header.tcpOffset) shr 6 and 0x1)

proc urg*(tcp: TCP): bool =
    return bool(ntohs(tcp.header.tcpOffset) shr 5 and 0x1)

proc ack*(tcp: TCP): bool =
    return bool(ntohs(tcp.header.tcpOffset) shr 4 and 0x1)

proc psh*(tcp: TCP): bool =
    return bool(ntohs(tcp.header.tcpOffset) shr 3 and 0x1)

proc rst*(tcp: TCP): bool =
    return bool(ntohs(tcp.header.tcpOffset) shr 2 and 0x1)

proc syn*(tcp: TCP): bool =
    return bool(ntohs(tcp.header.tcpOffset) shr 1 and 0x1)

proc fin*(tcp: TCP): bool =
    return bool(ntohs(tcp.header.tcpOffset) and 0x1)

proc windowSize*(tcp: TCP): uint16 =
    return ntohs(tcp.header.tcpWindowSize)

proc checksum*(tcp: TCP): uint16 =
    return ntohs(tcp.header.tcpChecksum)

proc urgentPointer*(tcp: TCP): uint16 =
    if tcp.urg:
        return ntohs(tcp.header.tcpUrgent)

proc newTCPOption*(buffer: var ByteStream): TCPOption =
    var
        optKind: uint8
        optLen: uint8
        optValue: seq[byte]
    
    buffer.readBytes(optKind)
    case optKind:
    of EndOfOpts:
        result = TCPOption(kind: optKind)
    of NoOp:
        result = TCPOption(kind: optKind)
    else:
        buffer.readBytes(optLen)
        optValue = newSeq[byte](optLen)
        moveMem(optValue[0].addr, buffer.pos, int(optLen))
        buffer.skipBytes(int(optLen))

proc options*(tcp: var TCP): seq[TCPOption] =
    if tcp.dataOffset <= 5:
        return result

    var opt: TCPOption

    opt = tcp.optsBuffer.newTCPOption()
    result.add(opt)

    while opt.kind != EndOfOpts:
        opt = tcp.optsBuffer.newTCPOption()
        result.add(opt)

# proc pduType*()