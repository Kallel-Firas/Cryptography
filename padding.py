class BadPaddingError(Exception):
    pass


def padding(block_size: int, msg: bytes) -> bytes:
    pad_length = (block_size - len(msg)) % block_size
    if pad_length == 0:
        pad_length = block_size
    return msg + (bytes.fromhex(f"{pad_length:02x}") * pad_length)


def check_padding(s: bytes) -> bool:
    return all(s[-1] == i for i in s[-s[-1]:])
