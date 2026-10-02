import os

# X25519 (RFC 7748) -- Diffie-Hellman on Curve25519
# private key = 32 random bytes, public key = private * base point
# shared secret = my_private * their_public (both sides get the same point)

P = 2**255 - 19      #the field: all math is mod this prime
A24 = 121665         #(486662 - 2) / 4, from the curve equation y^2 = x^3 + 486662x^2 + x
BASE_U = 9           #u-coordinate of the base point (the "generator")


def clamp(k):
    #rfc 7748 section 5: fix some bits of the private key
    k = bytearray(k)
    k[0] &= 248      #clear 3 low bits -> multiple of 8, kills small-subgroup attacks
    k[31] &= 127     #clear the top bit
    k[31] |= 64      #set bit 254 -> every key has the same length (constant ladder)
    return int.from_bytes(k, 'little')


def decode_u(u_bytes):
    #the top bit of the last byte is ignored (rfc 7748 section 5)
    u = bytearray(u_bytes)
    u[31] &= 127
    return int.from_bytes(u, 'little') % P


def encode_u(u):
    return (u % P).to_bytes(32, 'little')


def cswap(swap, a, b):
    #swap a and b when swap == 1, keep them when swap == 0
    if swap:
        return b, a
    return a, b


def scalar_mult(k, u):
    #montgomery ladder: computes k * (point with u-coordinate u)
    #we only track the u (x) coordinate, which is all DH needs
    x1 = u
    x2, z2 = 1, 0    #point at infinity
    x3, z3 = u, 1    #the input point
    swap = 0

    for t in reversed(range(255)):
        k_t = (k >> t) & 1
        swap ^= k_t
        x2, x3 = cswap(swap, x2, x3)
        z2, z3 = cswap(swap, z2, z3)
        swap = k_t

        #one ladder step = double one point and add the two points
        A = (x2 + z2) % P
        AA = A * A % P
        B = (x2 - z2) % P
        BB = B * B % P
        E = (AA - BB) % P
        C = (x3 + z3) % P
        D = (x3 - z3) % P
        DA = D * A % P
        CB = C * B % P
        x3 = (DA + CB) ** 2 % P
        z3 = x1 * (DA - CB) ** 2 % P
        x2 = AA * BB % P
        z2 = E * (AA + A24 * E) % P

    x2, x3 = cswap(swap, x2, x3)
    z2, z3 = cswap(swap, z2, z3)

    #back from projective (x/z) to a normal number: z^(p-2) is 1/z (fermat)
    return x2 * pow(z2, P - 2, P) % P


def x25519(private_key, u_bytes):
    if len(private_key) != 32:
        raise ValueError("private key must be 32 bytes")
    if len(u_bytes) != 32:
        raise ValueError("public key must be 32 bytes")
    return encode_u(scalar_mult(clamp(private_key), decode_u(u_bytes)))


def generate_private_key():
    return os.urandom(32)


def public_key(private_key):
    return x25519(private_key, encode_u(BASE_U))


def shared_secret(my_private, their_public):
    secret = x25519(my_private, their_public)
    #a malicious "public key" of small order gives all zeros -> refuse it
    if secret == b'\x00' * 32:
        raise ValueError("invalid public key (shared secret is zero)")
    return secret
