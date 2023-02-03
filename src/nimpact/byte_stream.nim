const
    Printables = {
        ' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+',
        ',', '-', '.', '/', '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C',
        'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
        'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[',
        '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
        'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
        't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~'
    }

    Alignment = 4

type
    Field* = (ptr, int)

    ByteStream* = object
        start*: ptr byte
        pos*: ptr byte
        length*: int

proc getIndex*(buffer: ByteStream): int =
    return cast[int](buffer.pos) - cast[int](buffer.start)

proc asField*[T](variable: var T): auto =
    return (cast[ptr byte](variable.addr), sizeof(variable))

proc advancePos*(buffer: var ByteStream, length: int) {.inline.} =
    buffer.pos = cast[ptr byte](cast[int](buffer.pos) + sizeof(byte) * length)

proc readBytes*[T](buffer: var ByteStream, variable: var T): int {.discardable.} =
    var allocatable: int

    allocatable = buffer.length - buffer.getIndex()
    if allocatable < sizeof(variable):
        result = allocatable
    else:
        result = sizeof(variable)

    moveMem(variable.addr, buffer.pos, result)
    buffer.advancePos(result)

proc advanceBuffer*[T](destPtr: ptr T, srcPtr: var ptr byte, length: int) =
    moveMem(destPtr, srcPtr, length)
    srcPtr = cast[ptr byte](cast[int](srcPtr) + sizeof(byte) * length)

proc moveMem*[T](buffer: var ByteStream, dest: var T, length: int) {.inline.} =
    moveMem(dest.addr, buffer.pos, length)
    buffer.advancePos(length)

proc moveMem*[T](buffer: var ByteStream, dest: var T) {.inline.} =
    moveMem(dest.addr, buffer.pos, sizeof(T))
    buffer.advancePos(sizeof(T))

proc peekMem*[T](buffer: var ByteStream, dest: var T) {.inline.} =
    moveMem(dest.addr, buffer.pos, sizeof(T))

proc peekMem*[T](buffer: var ByteStream, dest: var T, length: int) {.inline.} =
    moveMem(dest.addr, buffer.pos, length)

proc skipBytes*(buffer: var ByteStream, length: int) =
    buffer.pos = cast[ptr byte](cast[int](buffer.pos) + sizeof(byte) * length)

proc readFields*(buffer: var ptr byte, fields: seq[Field]): int {.discardable.} =
    for (dstPtr, size) in fields:
        result += size
        advanceBuffer(dstPtr, buffer, size)

proc remainingBytes*(buffer: ByteStream): int {.inline.} =
    return buffer.length - buffer.getIndex()

proc newByteStream*(start: ptr byte, totalLen: int): ByteStream =
    result.start = start
    result.pos = start
    result.length = totalLen

proc newInnerBuffer*(buffer: ByteStream): ByteStream =
    result.start = buffer.pos
    result.pos = buffer.pos
    result.length = buffer.remainingBytes()

proc newInnerBuffer*(buffer: ByteStream, size: int): ByteStream =
    result.start = buffer.pos
    result.pos = buffer.pos
    result.length = size

proc align*(buffer: var ByteStream) =
    let pad = ((Alignment - buffer.getIndex() mod Alignment) mod Alignment)
    buffer.skipBytes(pad)

proc `$`*(byteArray: seq[byte]): string =
    for c in byteArray:
        if c.chr in Printables:
            result.add(c.chr)
        else:
            result.add(".")

proc byteStreamToSeq*(buffer: var ByteStream): seq[byte] =
    result = newSeq[byte](buffer.length)
    buffer.peekMem(result[0])

proc `$`*(buffer: var ByteStream): string =
    return $byteStreamToSeq(buffer)
