import byte_stream

type
    BasePdu* = object of RootObj
        data*: ptr ByteStream

    Null* = ptr object

type
    # PDUType* = enum
    #     pduNull
    #     pduEthernetII = "EthernetII"
    #     pduIPv4 = "IPv4"
    #     pduTCP = "TCP"
    # Frame* = object
    #     packetHeader: PcapPacketHeader


    PDU* = object of RootObj
        parentPDU: ptr PDU
        childPDU: seq[ptr PDU]
        # pduType*: PDUType
        # pdu: ptr byte
