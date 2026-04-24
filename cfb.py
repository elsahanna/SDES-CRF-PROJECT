#CFB mode

from sdes import encrypt_block, generate_keys
import base64

BLOCK_SIZE = 8


def str_to_bits(text):
    return ''.join(format(ord(c), '08b') for c in text)


def bits_to_str(bits):
    chars = []

    # ignore incomplete last byte
    for i in range(0, len(bits) - (len(bits) % 8), 8):
        byte = bits[i:i+8]
        chars.append(chr(int(byte, 2)))

    return ''.join(chars)


def cfb_encrypt(plaintext, key10, iv):
    K1, K2 = generate_keys(key10)

    pt_bits = str_to_bits(plaintext)

    ciphertext = ""
    prev = iv

    for i in range(0, len(pt_bits), BLOCK_SIZE):
        block = pt_bits[i:i+BLOCK_SIZE]

        encrypted_iv = encrypt_block(prev, K1, K2)

        cipher_block = ''.join(
            '0' if block[j] == encrypted_iv[j] else '1'
            for j in range(len(block))
        )

        ciphertext += cipher_block
        prev = cipher_block

    return ciphertext


def cfb_decrypt(ciphertext, key10, iv):
    if len(ciphertext) % 8 != 0:
        raise ValueError("Invalid ciphertext length")
    
    K1, K2 = generate_keys(key10)

    plaintext_bits = ""
    prev = iv

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i+BLOCK_SIZE]

        encrypted_iv = encrypt_block(prev, K1, K2)

        plain_block = ''.join(
            '0' if block[j] == encrypted_iv[j] else '1'
            for j in range(len(block))
        )

        plaintext_bits += plain_block
        prev = block

    return bits_to_str(plaintext_bits)


def binary_to_hex(binary_text):
    bytes_list = [binary_text[i:i+8] for i in range(0, len(binary_text), 8)]
    return ' '.join(format(int(b, 2), '02X') for b in bytes_list)

def binary_to_base64(binary_text):
    bytes_list = bytes(
        int(binary_text[i:i+8], 2)
        for i in range(0, len(binary_text), 8)
    )
    return base64.b64encode(bytes_list).decode()

def hex_to_binary(hex_text):
    hex_text = hex_text.replace(" ", "")
    return ''.join(format(int(hex_text[i:i+2], 16), '08b')
                   for i in range(0, len(hex_text), 2))


def base64_to_binary(b64_text):
    raw = base64.b64decode(b64_text)
    return ''.join(format(byte, '08b') for byte in raw)



