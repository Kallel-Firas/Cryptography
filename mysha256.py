import hashlib
import secrets


def rotr(x, n):
    x = list(f'{x:032b}')
    return int('0b' + ''.join(x[-n:] + x[:-n]), base=2)


def shr(x, n):
    return x >> n


def sigma1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)
    
    
def sigma0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)


def Sigma0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def Sigma1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def ch(a, b, c):
    n = f'{a ^ 0xffffffff:04x}'
    return (a & b) ^ (int(n, base=16) & c)
    
    
def maj(a, b, c):
    return (a & b) ^ (a & c) ^ (b & c)


class SHA256:
    def __init__(self, orig_message, extension, orig_hash, secret_length):
        self.constants = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ]
        self.message = orig_message
        self.extension = extension
        self.orig_hash = orig_hash
        self.secret_length = secret_length
        self.new_message = self.padding(orig_message) + extension

        h0 = int('0x' + self.orig_hash[:8], base=16)
        h1 = int('0x' + self.orig_hash[8:16], base=16)
        h2 = int('0x' + self.orig_hash[16:24], base=16)
        h3 = int('0x' + self.orig_hash[24:32], base=16)
        h4 = int('0x' + self.orig_hash[32:40], base=16)
        h5 = int('0x' + self.orig_hash[40:48], base=16)
        h6 = int('0x' + self.orig_hash[48:56], base=16)
        h7 = int('0x' + self.orig_hash[56:], base=16)
        
        n_orig_blocks = (self.secret_length + len(self.message)) // 63 + 1  # with padding
        ext_message = secrets.token_bytes(self.secret_length) + self.padding(self.new_message)
        message_blocks = [ext_message[i:i+64] for i in range(0, len(ext_message), 64)]
        
        for i in range(n_orig_blocks, len(message_blocks)):
            message_block = message_blocks[i]
            w = [int.from_bytes(message_block[t:t+4], byteorder='big') for t in range(0, 64, 4)]
            t = 16
            while len(w) < 64:
                w.append((sigma1(w[t-2]) + w[t-7] + sigma0(w[t-15]) + w[t-16]) % 2 ** 32)
                t += 1
            
            a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
            for t in range(64):
                t1 = (h + Sigma1(e) + ch(e, f, g) + self.constants[t] + w[t]) % 2 ** 32
                t2 = (Sigma0(a) + maj(a, b, c)) % 2 ** 32
                h = g
                g = f
                f = e
                e = (d + t1) % 2 ** 32
                d = c
                c = b
                b = a
                a = (t1 + t2) % 2 ** 32
            
            h0 = (a + h0) % 2 ** 32
            h1 = (b + h1) % 2 ** 32
            h2 = (c + h2) % 2 ** 32
            h3 = (d + h3) % 2 ** 32
            h4 = (e + h4) % 2 ** 32
            h5 = (f + h5) % 2 ** 32
            h6 = (g + h6) % 2 ** 32
            h7 = (h + h7) % 2 ** 32
        self.new_hash = b''.join(map(lambda x: int(x).to_bytes(4, byteorder='big'), [h0, h1, h2, h3, h4, h5, h6, h7]))
        
    def padding(self, msg):
        """Calculate padding of the original message. The secret is not known but its length is"""
        bits = (self.secret_length + len(msg)) * 8
        pad1 = '0b1' + '0' * ((448 - (bits + 1)) % 512)
        pad2 = f'{bits:064b}'
        pad = pad1 + pad2
        b = ((bits + len(pad[2:])) // 512) * 64
        return msg + int(pad, base=2).to_bytes(b-(self.secret_length + len(msg)), byteorder='big')
