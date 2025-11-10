from operator import xor
from typing import List


def xor_blocks(a: List[int], b: List[int]) -> List[int]:
    return [xor(i, j) for i, j in zip(a, b)]


def xor_strings(a: bytes, b: bytes) -> bytes:
    m = b""
    for i, j in zip(a, b):
        m += bytes.fromhex(f'{xor(i, j):02x}')
    return m
