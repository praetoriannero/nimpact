import std/json
import byte_stream

type
    BasePdu* = object of RootObj
        data*: ptr ByteStream

    Null* = ptr object

type
    PDU* = object of RootObj
        parentPDU*: ptr PDU
        childPDU*: ptr PDU
        # payload*: ByteStream
        serializeImpl*: proc (pdu: PDU): seq[byte]
            {.nimcall, gcsafe.}
        deserializeImpl*: proc (pdu: PDU)
            {.nimcall, gcsafe.}
        asJsonImpl*: proc (pdu: ptr PDU): JsonNode
            {.nimcall, gcsafe.}

    UnknownPDU* = object of PDU
        payload*: ByteStream

proc newUnknownPDU*(buffer: var ByteStream): UnknownPDU =
    result.payload = buffer

proc serialize*(pdu: PDU): seq[byte] =
    return pdu.serializeImpl(pdu)

proc deserialize*(pdu: var PDU) =
    pdu.deserializeImpl(pdu)

proc asJson*(pdu: ptr PDU): JsonNode =
    return pdu.asJsonImpl(pdu)
