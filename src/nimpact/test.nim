import libpcap
import strutils
import strformat
import times

# import byte_stream
import pdu
import packet
import ethernet
import ip
import tcp
import udp


when isMainModule:
    var 
        ret: cint
        iface: PcapIf
        errorBuf: cstring
        handle: Pcap
        packetHeader: PcapPacketHeader
        packetAddr: ptr byte
        eth: EthernetII
        ipv4: IPv4
        totalPackets: int
        elapsedTime: float
        pktsPerSecond: float
        auth: PcapRmtAuth
        file: cstring = "D:\\pcaps\\bigFlows.pcap"
        pkt: Packet
        # ipOpts: seq[IPv4Option]
        tcpPdu: TCP
        udpPdu: UDP
        ethernetCount, ipCount, tcpCount, udpCount: int
        pduChain: seq[PDU] = @[]

    # pduChain = newSeq[PDU]()

    ret = pcapFindAllDevsEx(PcapSrcIfString, auth, iface, errorBuf)

    handle = pcapOpenOffline(file, errorBuf)

    let time = cpuTime()
    while true:
        packetAddr = pcapNext(handle, packetHeader.addr)
        if packetAddr == nil:
            break

        pkt = newPacket(packetAddr, packetHeader)

        eth = pkt.payload.newEthernetII()

        # pduChain.add(eth)

        ethernetCount += 1
        if eth.type() == uint16(etIP):
            ipv4 = eth.payload.newIPv4()
            # pduChain.add(ipv4)
            ipCount += 1

            if ipv4.protocol() == uint8(IPv4Protocol.TCP):
                tcpPdu = ipv4.payload.newTCP()
                # pduChain.add(tcpPdu)
                tcpCount += 1

            elif ipv4.protocol() == uint(IPv4Protocol.UDP):
                udpPdu = ipv4.payload.newUDP()
                # pduChain.add(udpPdu)
                udpCount += 1

        totalPackets += 1
        # for entry in pduChain:
        #     echo(entry of EthernetII)

        # break
        # pduChain = newSeq[PDU](3)

    elapsedTime = cpuTime() - time
    pktsPerSecond = float(totalPackets) / elapsedTime

    echo(&"Completed in {elapsedTime} seconds")
    echo(&"{pktsPerSecond} blocks read per second")
    echo(&"{ethernetCount} Ethernet II PDUs found")
    echo(&"{ipCount}/791179 IP PDUs found")
    echo(&"{tcpCount}/633894 TCP PDUs found")
    echo(&"{udpCount}/152733 UDP PDUs found")
    echo(&"{totalPackets} total packets found")

