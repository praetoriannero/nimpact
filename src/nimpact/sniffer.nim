import libpcap
import packet

iterator sniffOffline*(fileName: string): Packet =
    var 
        errorBuf: cstring
        handle: Pcap
        packetHeader: PcapPacketHeader
        packetAddr: ptr byte
        pkt: Packet

    handle = pcapOpenOffline(cstring(fileName), errorBuf)
    while true:
        packetAddr = pcapNext(handle, packetHeader.addr)
        if packetAddr == nil:
            break

        pkt = newPacket(packetAddr, packetHeader)
        yield pkt
