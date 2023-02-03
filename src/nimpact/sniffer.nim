import libpcap
import packet
import pcapng

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

iterator sniffPcapng*(filename: string): Packet =
    var
        packetHeader: PcapPacketHeader
        packetAddr: ptr byte
        pkt: Packet

    for entry in pcapngReader(fileName):
        packetAddr = entry[0].unsafeAddr
        packetHeader = PcapPacketHeader(
            capLen: cuint(entry.len)
        )
        pkt = newPacket(packetAddr, packetHeader)
        yield pkt
