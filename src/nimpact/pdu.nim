import byte_stream

type
    BasePdu* = object of RootObj
        data*: ptr ByteStream

    Null* = ptr object

type
    PDU* = object of RootObj
        parentPDU*: ptr PDU
        childPDU*: ptr PDU

    UnknownPDU* = object of PDU
        payload*: ByteStream

proc newUnknownPDU*(buffer: var ByteStream): UnknownPDU =
    result.payload = buffer
