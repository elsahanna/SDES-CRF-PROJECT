import base64

# =========================
# BIT OPERATIONS
# =========================
def permute(bits, table):
    return ''.join(bits[i - 1] for i in table)


def xor(bits1, bits2):
    return ''.join('0' if b1 == b2 else '1' for b1, b2 in zip(bits1, bits2))


def left_shift(bits, n):
    return bits[n:] + bits[:n]


# =========================
# FORMAT CONVERTERS
# =========================
def hex_to_binary(hex_text):
    hex_text = hex_text.replace(" ", "")
    return ''.join(format(int(hex_text[i:i+2], 16), '08b')
                   for i in range(0, len(hex_text), 2))


def base64_to_binary(b64_text):
    raw = base64.b64decode(b64_text, validate=True)
    return ''.join(format(byte, '08b') for byte in raw)



# =========================
# FORMAT MENU
# =========================
def ask_format():
    while True:
        print("\nChoose ciphertext format:")
        print("1. Binary")
        print("2. Hex")
        print("3. Base64")

        fmt = input("Choose format: ")

        if fmt in ["1", "2", "3"]:
            return fmt

        print("Invalid format. Please enter 1–3.")


# =========================
# SAFE CONVERTER
# =========================
def to_binary(text, fmt):
    try:
        if fmt == "1":
            if any(c not in "01" for c in text):
                return None
            return text

        elif fmt == "2":
            return hex_to_binary(text)

        elif fmt == "3":
            return base64_to_binary(text)

        return None

    except:
        return None


# =========================
# VALIDATED INPUT
# =========================
def get_valid_ciphertext():
    while True:
        fmt = ask_format()
        text = input("Enter ciphertext: ").strip()

        binary = to_binary(text, fmt)

        if binary is not None:

            # Binary data must be full bytes
            if len(binary) % 8 != 0:
                print("\nError: Ciphertext length must be multiple of 8 bits.")
                print("Please try again.\n")
                continue

            return binary

        print("\nError: Ciphertext does not match selected format.")
        print("Please try again.\n")