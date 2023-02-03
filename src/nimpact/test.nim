import os
import std/enumerate
import strutils
import strformat
import times

import packet
import sniffer

when isMainModule:
    var 
        totalPackets: int
        elapsedTime: float
        pktsPerSecond: float
        pkt: Packet
        ethernetCount, ipCount, tcpCount, udpCount: int
        args = commandLineParams()

    if len(args) != 1:
        var error: ref IOError
        new(error)
        error.msg = "one argument is allowed: file path"
        raise error

    var pcapName = args[0]
    let time = cpuTime()

    # for p in sniffOffline(pcapName):
    for idx, p in enumerate(sniffPcapng(pcapName)):
        totalPackets += 1
        pkt = p
        try:
            pkt.deserialize()
        except Exception as e:
            continue

    elapsedTime = cpuTime() - time
    pktsPerSecond = float(totalPackets) / elapsedTime

    echo(&"Completed in {elapsedTime} seconds")
    echo(&"{pktsPerSecond} packets read per second")
    echo(&"{ethernetCount} Ethernet II PDUs found")
    echo(&"{ipCount} IP PDUs found")
    echo(&"{tcpCount} TCP PDUs found")
    echo(&"{udpCount} UDP PDUs found")
    echo(&"{totalPackets} total packets found")

