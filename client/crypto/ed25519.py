import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from sha512 import sha512

#twisted Edwards curve: -x^2 + y^2 = 1 + d*x^2*y^2 (mod p)

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493  #number of points in the group we use
D = -121665 * pow(121666, P - 2, P) % P        
SQRT_M1 = pow(2, (P - 1) // 4, P)


def inv(x):
    return pow(x, P - 2, P)

def point_add(p1, p2):
    X1, Y1, Z1, T1 = p1
    X2, Y2, Z2, T2 = p2
    A = (Y1 - X1) * (Y2 - X2) % P
    B = (Y1 + X1) * (Y2 + X2) % P
    C = 2 * D * T1 * T2 % P
    Dd = 2 * Z1 * Z2 % P
    E = B - A
    F = Dd - C
    G = Dd + C
    H = B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)

def scalar_mult(k, point):
    result = (0, 1, 1, 0)  #neutral element (x=0, y=1)
    while k > 0:
        if k & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        k >>= 1
    return result


def point_equal(p1, p2):
    X1, Y1, Z1, _ = p1
    X2, Y2, Z2, _ = p2
    return (X1 * Z2 - X2 * Z1) % P == 0 and (Y1 * Z2 - Y2 * Z1) % P == 0


def recover_x(y, sign):
    #solve the curve equation for x:x^2 =(y^2-1)/(d*y^2+1)
    if y >= P:
        return None
    x2 = (y * y - 1) * inv(D * y * y + 1) % P
    if x2 == 0:
        return None if sign else 0

    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None 

    if (x & 1) != sign:
        x = P - x
    return x


# base point: y = 4/5, x is the even root
BASE_Y = 4 * inv(5) % P
BASE_X = recover_x(BASE_Y, 0)
BASE = (BASE_X, BASE_Y, 1, BASE_X * BASE_Y % P)


def encode_point(point):
    X, Y, Z, _ = point
    z_inv = inv(Z)
    x = X * z_inv % P
    y = Y * z_inv % P
    return (y | ((x & 1) << 255)).to_bytes(32, 'little')


def decode_point(data):
    if len(data) != 32:
        return None
    n = int.from_bytes(data, 'little')
    sign = n >> 255
    y = n & ((1 << 255) - 1)
    x = recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _hash_int(data):
    return int.from_bytes(sha512(data), 'little')


def _expand_private(private_key):
    #sha512 of seed: first half = scalar a
  #second half = nonce prefix
    h = sha512(private_key)
    a = int.from_bytes(h[:32], 'little')
    a &= (1 << 254) - 8  #clear 3 low bits and the top bit
    a |= (1 << 254)
    return a, h[32:]


def generate_private_key():
    return os.urandom(32)


def public_key(private_key):
    if len(private_key) != 32:
        raise ValueError("private key must be 32 bytes")
    a, _ = _expand_private(private_key)
    return encode_point(scalar_mult(a, BASE))


def sign(private_key, message):
    a, prefix = _expand_private(private_key)
    A = encode_point(scalar_mult(a, BASE))

    #r never repeats
    r = _hash_int(prefix + message) % L
    R = encode_point(scalar_mult(r, BASE))

    k = _hash_int(R + A + message) % L
    S = (r + k * a) % L

    return R + S.to_bytes(32, 'little')


def verify(public, message, signature):
    #never raises on bad input
    if len(public) != 32 or len(signature) != 64:
        return False

    A = decode_point(public)
    R = decode_point(signature[:32])
    if A is None or R is None:
        return False

    S = int.from_bytes(signature[32:], 'little')
    if S >= L:
        return False #stop malleability

    k = _hash_int(signature[:32] + public + message) % L

    #check if S*B==R+k*A
    return point_equal(scalar_mult(S, BASE), point_add(R, scalar_mult(k, A)))