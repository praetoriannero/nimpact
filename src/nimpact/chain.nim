import pdu

type
    Chain* = object of RootObj
        pduChain*: seq[PDU]

