

MASK64 = 0xFFFFFFFFFFFFFFFF

# 1st 64 bits of the fractional parts of the cube roots
# of the first 80 prime numbers
K = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
]


# 1st 64 bits of the fractional parts of the sqrt
# of the first 8 prime numbers
INITIAL_HASH = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
]

def rotr(x, n):
    #rotate right a 64-bit integer x by n
    return ((x >> n) | (x << (64 - n))) & MASK64


def ch(x, y, z):
    #x=1 -> from y, x=0 -> from z
    return ((x & y) | (~x & MASK64 & z)) & MASK64


def maj(x, y, z):
    #1 if at least 2 of x,y,z are 1
    return (x & y) ^ (x & z) ^ (y & z)


def sigma0(x):
    #schedule expansion
    return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7)


def sigma1(x):
    return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6)


def SIGMA0(x):
    #compression function
    return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39)


def SIGMA1(x):
    return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41)


def add64(*args):
    total = 0
    for a in args:
        total += a
    return total & MASK64


#1st stage: pad the message to a multiple of 1024 bits
def pad(message):
    msg = bytearray(message)

    original_length_bits = len(message) * 8  #in bits

    msg.append(0x80)

    #leave 16 bytes at the end for the length (128-bit length field)
    while len(msg) % 128 != 112:
        msg.append(0x00)

    msg += original_length_bits.to_bytes(16, byteorder='big')

    return bytes(msg)


#2nd stage: process each 1024-bit chunk
def process_chunk(chunk, hash_values):

    if len(chunk) != 128:
        raise ValueError(f"Chunk must be 128 bytes, got {len(chunk)}")

    W = []
    for i in range(16):
        # take 8 bytes at a time
        word = int.from_bytes(chunk[i*8 : i*8+8], byteorder='big')
        W.append(word)

    for i in range(16, 80):
        # each new word mixes in four earlier words
        w = add64(sigma1(W[i-2]), W[i-7], sigma0(W[i-15]), W[i-16])
        W.append(w)

    a, b, c, d, e, f, g, h = hash_values

    for i in range(80):
        T1 = add64(h, SIGMA1(e), ch(e, f, g), K[i], W[i])
        T2 = add64(SIGMA0(a), maj(a, b, c))

        h = g
        g = f
        f = e
        e = add64(d, T1)
        d = c
        c = b
        b = a
        a = add64(T1, T2)

    return [add64(x, y) for x, y in zip(hash_values, [a, b, c, d, e, f, g, h])]


# 3rd stage: produce the final 64-byte digest
def sha512(message):

    padded = pad(message)

    hash_values = list(INITIAL_HASH)

    for i in range(0, len(padded), 128):
        hash_values = process_chunk(padded[i:i+128], hash_values)

    digest = b""
    for h in hash_values:
        digest += h.to_bytes(8, byteorder='big')

    return digest

def sha512_hex(message):
    return sha512(message).hex()
