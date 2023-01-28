import strutils

type
    IPv4Address* = array[4, byte]

    MacAddress* = array[6, byte]

proc `$`*(mac: MacAddress): string =
    var tempArray: array[6, string]
    for i in 0..<mac.len:
        tempArray[i] = mac[i].toHex

    return join(tempArray, ":")

proc `$`*(ip: IPv4Address): string =
    var tempArray: array[4, string]
    for i in 0..<ip.len:
        tempArray[i] = intToStr(int(ip[i]))

    result = join(tempArray, ".")
