#core encryption

from utils import permute, xor, left_shift

# Permutation tables (standard S-DES)
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8  = [6, 3, 7, 4, 8, 5, 10, 9]
IP  = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]

EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]

# S-boxes
S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
]

S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
]


def generate_keys(key10):
    key = permute(key10, P10)

    left, right = key[:5], key[5:]

    left = left_shift(left, 1)
    right = left_shift(right, 1)
    K1 = permute(left + right, P8)

    left = left_shift(left, 2)
    right = left_shift(right, 2)
    K2 = permute(left + right, P8)

    return K1, K2


def sbox_lookup(bits, sbox):
    row = int(bits[0] + bits[3], 2)
    col = int(bits[1] + bits[2], 2)
    return format(sbox[row][col], '02b')


def fk(bits, key):
    left, right = bits[:4], bits[4:]

    expanded = permute(right, EP)
    xored = xor(expanded, key)

    left_sbox = sbox_lookup(xored[:4], S0)
    right_sbox = sbox_lookup(xored[4:], S1)

    p4 = permute(left_sbox + right_sbox, P4)

    return xor(left, p4) + right


def encrypt_block(pt, K1, K2):
    pt = permute(pt, IP)

    pt = fk(pt, K1)
    pt = pt[4:] + pt[:4]  # swap

    pt = fk(pt, K2)

    return permute(pt, IP_INV)


def decrypt_block(ct, K1, K2):
    ct = permute(ct, IP)

    ct = fk(ct, K2)
    ct = ct[4:] + ct[:4]

    ct = fk(ct, K1)

    return permute(ct, IP_INV)