import secrets
from typing import List, Optional

from padding import *
from permutations import *
from utils import *


class DES:
    def __init__(self, key: bytes, block_size: int) -> None:
        if len(key) != 8:
            raise ValueError(f'The key must be 8 bytes long')
        self.key = key
        self.block_size = block_size
        self.round_keys = self._key_schedule()
    
    def encrypt(self, plaintext: bytes, apply_pad: bool) -> bytes:
        pass
    
    def decrypt(self, ciphertext: bytes, apply_pad: bool) -> bytes:
        pass
        
    def _encryption(self, block: bytes, encrypt: bool) -> bytes:
        block = int.from_bytes(block, byteorder='big')
        block = list(map(int, bin(block)[2:].zfill(64)))
        block = [block[i] for i in IP]
        left, right = block[:32], block[32:]
        if encrypt:
            round_keys = self.round_keys
        else:
            round_keys = self.round_keys[::-1]
        for n in range(16):
            round_key = round_keys[n]
            left, right = right, xor_blocks(left, self._cipher(right, round_key))
        block = right + left
        block = [block[i] for i in IP_inv]
        block = int('0b' + ''.join(str(b) for b in block), base=2).to_bytes(8, byteorder='big')
        return block
        
    def _cipher(self, r: List[int], k: List[int]) -> List[int]:
        subst = [S1, S2, S3, S4, S5, S6, S7, S8]
        r = [r[i] for i in E]
        rk = xor_blocks(r, k)
        res, j = [], 0
        for i in range(0, 48 - 6 + 1, 6):
            block = rk[i:i+6]
            row, col = int(f'0b{block[0]}{block[-1]}', base=2), int(f'0b{"".join(str(b) for b in block[1:-1])}', base=2)
            res += [int(b) for b in bin(subst[j][row][col])[2:].zfill(4)]
            j += 1
        res = [res[i] for i in P]
        return res
    
    def _key_schedule(self) -> List[List[int]]:
        iterations = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
        res = []
        key = int.from_bytes(self.key, byteorder='big')
        key = list(map(int, bin(key)[2:].zfill(64)))
        round_key = [key[i] for i in PC1]
        c, d = round_key[:28], round_key[28:]
        for n in range(16):
            left_shifts = iterations[n]
            c = c[left_shifts:] + c[:left_shifts]
            d = d[left_shifts:] + d[:left_shifts]
            round_key = c + d
            res.append([round_key[i] for i in PC2])
        return res
    

class DES_ECB(DES):
    def __init__(self, key: bytes, block_size: int = 8) -> None:
        super().__init__(key, block_size)
        
    def encrypt(self, plaintext: bytes, apply_pad: bool = True) -> bytes:
        res = b""
        if apply_pad:
            plaintext = padding(self.block_size, plaintext)
        for b in range(0, len(plaintext), self.block_size):
            pt_block = plaintext[b:b+self.block_size]
            res += self._encryption(pt_block, encrypt=True)
        return res
    
    def decrypt(self, ciphertext: bytes, apply_pad: bool = True) -> bytes:
        res = b""
        for b in range(0, len(ciphertext), self.block_size):
            pt_block = ciphertext[b:b+self.block_size]
            res += self._encryption(pt_block, encrypt=False)
        if apply_pad:
            if check_padding(res):
                return res[:-res[-1]]
            raise BadPaddingError('Bad padding')
        return res
    

class DES_CBC(DES):
    def __init__(self, key: bytes, block_size: int = 8, iv: Optional[bytes] = None) -> None:
        super().__init__(key, block_size)
        if iv is None:
            self.iv = secrets.token_bytes(block_size)
        else:
            self.iv = iv
        # elágazással ekvivalens: self.iv = iv or secrets.token_bytes(block_size)
        
    def encrypt(self, plaintext: bytes, apply_pad: bool = True) -> bytes:
        res = self.iv
        if apply_pad:
            plaintext = padding(self.block_size, plaintext)
        for b in range(0, len(plaintext), self.block_size):
            pt_block = plaintext[b:b+self.block_size]
            x = xor_strings(res[-self.block_size:], pt_block)
            res += self._encryption(x, encrypt=True)
        return res
        
    def decrypt(self, ciphertext: bytes, apply_pad: bool = True) -> bytes:
        res = b""
        for b in range(self.block_size, len(ciphertext), self.block_size):
            ct_block = ciphertext[b:b+self.block_size]
            t = self._encryption(ct_block, encrypt=False)
            res += xor_strings(t, ciphertext[b-self.block_size:b])
        if apply_pad:
            if check_padding(res):
                return res[:-res[-1]]
            raise BadPaddingError('Bad padding')
        return res
