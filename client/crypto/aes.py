import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

#S-BOX -> 256-byte
#derived from multiplicative inverses in GF(2^8)
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18, 0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

INV_SBOX = [0] * 256
for i in range(256):
    INV_SBOX[SBOX[i]] = i

#rcon[i] = 2^(i-1) in GF(2^8)
RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def xtime(a):
    if a & 0x80:
        return ((a << 1) ^ 0x1b) & 0xFF
    else:
        return (a << 1) & 0xFF

def gf_mul(a, b):
    #multiply two bytes in GF(2^8) using repeated doubling + XOR
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result & 0xFF

#lookup tables built once with gf_mul -- mix_columns was calling gf_mul
#hundreds of times per block, which made AES (and GCM) very slow
MUL2  = [gf_mul(0x02, x) for x in range(256)]
MUL3  = [gf_mul(0x03, x) for x in range(256)]
MUL9  = [gf_mul(0x09, x) for x in range(256)]
MUL11 = [gf_mul(0x0b, x) for x in range(256)]
MUL13 = [gf_mul(0x0d, x) for x in range(256)]
MUL14 = [gf_mul(0x0e, x) for x in range(256)]

def key_expansion(key):
    assert len(key) == 32

    # split key into 8 x 4-byte words
    words = []
    for i in range(8):
        words.append(list(key[i*4 :i*4+4]))

    # expand to 60 words
    for i in range(8, 60):
        temp = words[i-1][:]

        if i % 8 == 0:
            temp = temp[1:] + temp[:1] # rotate left 1 byte
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[i // 8]

        elif i % 8 == 4:
            temp = [SBOX[b] for b in temp]# aes only

        new_word = [temp[j] ^ words[i-8][j] for j in range(4)]
        words.append(new_word)

    # group into 15 round keys of 16 bytes
    round_keys = []
    for i in range(15):
        rk = []
        for j in range(4):
            rk += words[i*4 + j]
        round_keys.append(bytes(rk))

    return round_keys



def bytes_to_state(block):
    state = [[0]*4 for _ in range(4)]
    for col in range(4):
        for row in range(4):
            state[row][col] = block[col*4 + row]
    return state

def state_to_bytes(state):
    result = []
    for col in range(4):
        for row in range(4):
            result.append(state[row][col])
    return bytes(result)


#round ops
def add_round_key(state, round_key):
    
    rk = bytes_to_state(round_key)
    for row in range(4):
        for col in range(4):
            state[row][col] ^= rk[row][col]
    return state

def sub_bytes(state):
    for row in range(4):
        for col in range(4):
            state[row][col] = SBOX[state[row][col]]
    return state

def inv_sub_bytes(state):
    for row in range(4):
        for col in range(4):
            state[row][col] = INV_SBOX[state[row][col]]
    return state

def shift_rows(state):
    #rotate row i left by i positions
    for row in range(1, 4):
        state[row] = state[row][row:] + state[row][:row]
    return state

def inv_shift_rows(state):
    #rotate row i right by i positions
    for row in range(1, 4):
        state[row] = state[row][4-row:] + state[row][:4-row]
    return state

def mix_columns(state):
    for col in range(4):
        s0 = state[0][col]
        s1 = state[1][col]
        s2 = state[2][col]
        s3 = state[3][col]
        state[0][col] = MUL2[s0] ^ MUL3[s1] ^ s2 ^ s3
        state[1][col] = s0 ^ MUL2[s1] ^ MUL3[s2] ^ s3
        state[2][col] = s0 ^ s1 ^ MUL2[s2] ^ MUL3[s3]
        state[3][col] = MUL3[s0] ^ s1 ^ s2 ^ MUL2[s3]
    return state

def inv_mix_columns(state):
    for col in range(4):
        s0 = state[0][col]
        s1 = state[1][col]
        s2 = state[2][col]
        s3 = state[3][col]
        state[0][col] = MUL14[s0] ^ MUL11[s1] ^ MUL13[s2] ^ MUL9[s3]
        state[1][col] = MUL9[s0] ^ MUL14[s1] ^ MUL11[s2] ^ MUL13[s3]
        state[2][col] = MUL13[s0] ^ MUL9[s1] ^ MUL14[s2] ^ MUL11[s3]
        state[3][col] = MUL11[s0] ^ MUL13[s1] ^ MUL9[s2] ^ MUL14[s3]
    return state


def aes_encrypt_block(key, block, round_keys=None):
    assert len(key) == 32, "AES-256 needs a 32-byte key"
    assert len(block) == 16, "AES block must be 16 bytes"

    #callers encrypting many blocks (like GCM) pass round_keys to expand the key only once
    if round_keys is None:
        round_keys = key_expansion(key)
    state = bytes_to_state(block)

    state = add_round_key(state, round_keys[0]) #initial round

    for rnd in range(1, 14):                    
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state,round_keys[rnd])

    state = sub_bytes(state)#last round
    state = shift_rows(state)
    state = add_round_key(state,round_keys[14])

    return state_to_bytes(state)


def aes_decrypt_block(key, block):
    assert len(key) == 32, "AES-256 needs a 32-byte key"
    assert len(block) == 16, "AES block must be 16 bytes"

    round_keys = key_expansion(key)
    state= bytes_to_state(block)

    state = add_round_key(state, round_keys[14])
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)

    for rnd in range(13, 0, -1):
        state = add_round_key(state, round_keys[rnd])
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)

    state = add_round_key(state, round_keys[0]) # reverse initial round

    return state_to_bytes(state)


if __name__ == "__main__":
    print("Running AES-256 self-test...")

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected  = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")

    ciphertext = aes_encrypt_block(key, plaintext)
    decrypted  = aes_decrypt_block(key, ciphertext)

    test_cases = [
        ("Encrypt", ciphertext == expected),
        ("Decrypt",decrypted == plaintext),
    ]

    all_passed = True
    for name, passed in test_cases:
        print(f"  {name}: {'PASS' if passed else 'FAIL'}")
        if not passed:
            all_passed = False

    if all_passed:
        print("\nAll self-tests passed!")
    else:
        print(f"\n  Expected: {expected.hex()}")
        print(f"  Got:{ciphertext.hex()}")