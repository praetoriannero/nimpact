# import libpcap
import os
import strutils
import strformat
import times

# import byte_stream
# import pdu
import packet
# import ethernet
# import ip
import sniffer
# import tcp
# import udp

when isMainModule:
    var 
        # ret: cint
        # iface: PcapIf
        # auth: PcapRmtAuth
        # errorBuf: cstring
        totalPackets: int
        elapsedTime: float
        pktsPerSecond: float
        # file: string = "D:\\pcaps\\bigFlows.pcap"
        pkt: Packet
        ethernetCount, ipCount, tcpCount, udpCount: int
        args = commandLineParams()

    if len(args) != 1:
        var error: ref IOError
        new(error)
        error.msg = "one argument is allowed: file path"
        raise error

    var
        pcapName = args[0]

    # ret = pcapFindAllDevsEx(PcapSrcIfString, auth, iface, errorBuf)
    let time = cpuTime()

    for p in sniffOffline(pcapName):
        totalPackets += 1
        pkt = p
        pkt.deserialize()

    elapsedTime = cpuTime() - time
    pktsPerSecond = float(totalPackets) / elapsedTime

    echo(&"Completed in {elapsedTime} seconds")
    echo(&"{pktsPerSecond} packets read per second")
    echo(&"{ethernetCount} Ethernet II PDUs found")
    echo(&"{ipCount} IP PDUs found")
    echo(&"{tcpCount} TCP PDUs found")
    echo(&"{udpCount} UDP PDUs found")
    echo(&"{totalPackets} total packets found")

# type MyObj = object of RootObj
#     x*: int

# type NewObj = object of MyObj
#     y*: int

# var mo = MyObj(x: 3)
# echo(mo)

# proc testProc(variable: var ptr MyObj) =
#     var no = cast[ptr NewObj](variable)
#     echo(no[].y)

# var no = NewObj(x: 1, y: 7)
# var noPointer: ptr NewObj = no.addr
# var tempPointer: ptr MyObj = cast[ptr MyObj](noPointer)

# testProc(tempPointer)
