# Implementation of paper: https://web.archive.org/web/20161020205326/http://www.ecrypt.eu.org/stream/ciphers/trivium/trivium.pdf
# Wikipedia page: https://en.wikipedia.org/wiki/Trivium_%28cipher%29

from bitarray import bitarray
from random import randint


class Trivium:
    def __init__(self, k: bitarray, iv: bitarray, N=2**64):
        self.bits_generated = 0
        self.N = N
        # internal state: s
        # make it one bit larger to start counting from 1 instead of 0.
        # Using bitarrays for memory efficiency. For speed, use numpy bool arrays.
        self.s = bitarray([0]*289)
        self.s[1:80+1] = k
        self.s[94:174] = iv
        self.s[286:288+1] = bitarray([1, 1, 1])
        for i in range(1, 4*288+1):
            t1 = self.s[66] ^ self.s[93]
            t2 = self.s[162] ^ self.s[177]
            t3 = self.s[243] ^ self.s[288]
            t1 = t1 ^ (self.s[91] & self.s[92]) ^ self.s[171]
            t2 = t2 ^ (self.s[175] & self.s[176]) ^ self.s[264]
            t3 = t3 ^ (self.s[286] & self.s[287]) ^ self.s[69]
            self.s[2:93+1] = self.s[1:92+1]
            self.s[1] = t3
            self.s[95:177+1] = self.s[94:176+1]
            self.s[94] = t1
            self.s[179:288+1] = self.s[178:287+1]
            self.s[178] = t2

    def _next_key(self):
        t1 = self.s[66] ^ self.s[93]
        t2 = self.s[162] ^ self.s[177]
        t3 = self.s[243] ^ self.s[288]
        z = t1 ^ t2 ^ t3
        t1 = t1 ^ (self.s[91] & self.s[92]) ^ self.s[171]
        t2 = t2 ^ (self.s[175] & self.s[176]) ^ self.s[264]
        t3 = t3 ^ (self.s[286] & self.s[287]) ^ self.s[69]
        self.s[2:93+1] = self.s[1:92+1]
        self.s[1] = t3
        self.s[95:177+1] = self.s[94:176+1]
        self.s[94] = t1
        self.s[179:288+1] = self.s[178:287+1]
        self.s[178] = t2
        return z

    def __iter__(self):
        return self

    def __next__(self):
        if self.bits_generated >= self.N:
            raise StopIteration
        self.bits_generated += 1
        return self._next_key()


k = bitarray([randint(0, 1) for i in range(80)])
iv = bitarray([randint(0, 1) for i in range(80)])
assert len(k) == 80
assert len(iv) == 80
for z in Trivium(k, iv, 100):
    print(z, end='')
print()
