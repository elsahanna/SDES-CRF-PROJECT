from cfb import (
    cfb_encrypt, cfb_decrypt,
    binary_to_hex, binary_to_base64,
    hex_to_binary, base64_to_binary
)

from attacks import COA, KPA, CPA, CCA, CTA, brute_force
import random

SECRET_KEY = None
SECRET_IV = None

def ensure_oracle():
    global SECRET_KEY, SECRET_IV

    if SECRET_KEY is None:
        SECRET_KEY = format(random.randint(0, 1023), "010b")

    if SECRET_IV is None:
        SECRET_IV = format(random.randint(0, 255), "08b")
# =========================
# FORMAT HELPER
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
# ENCRYPTION SYSTEM
# =========================
def encryption_system():
    global SECRET_KEY, SECRET_IV

    text = input("Enter plaintext: ")

    # =========================
    # KEY VALIDATION
    # =========================
    while True:
        key = input("Enter 10-bit key: ")

        if len(key) != 10:
            print("Error: Key must contain exactly 10 bits.")
            continue

        if any(bit not in "01" for bit in key):
            print("Error: Key must contain only 0 and 1.")
            continue

        break

    # =========================
    # IV VALIDATION
    # =========================
    while True:
        iv = input("Enter 8-bit IV: ")

        if len(iv) != 8:
            print("Error: IV must contain exactly 8 bits.")
            continue

        if any(bit not in "01" for bit in iv):
            print("Error: IV must contain only 0 and 1.")
            continue

        break

    # Save secret values
    SECRET_KEY = key
    SECRET_IV = iv

    # Encrypt
    cipher = cfb_encrypt(text, key, iv)

    print("\n=== ENCRYPTION RESULT ===")
    print("Plaintext:", text)
    print("Ciphertext (Binary):", cipher)
    print("Ciphertext (Hex):", binary_to_hex(cipher))
    print("Ciphertext (Base64):", binary_to_base64(cipher))

    return cipher, key, iv

# =========================
# DECRYPTION SYSTEM
# =========================
def decryption_system():

    while True:
        fmt = ask_format()
        cipher_input = input("Enter ciphertext: ")

        try:
            if fmt == "1":
                # Binary must contain only 0 and 1
                if any(c not in "01" for c in cipher_input):
                    raise ValueError
                
                if len(cipher_input) % 8 != 0:
                    raise ValueError
                
                cipher = cipher_input

            elif fmt == "2":
                cipher = hex_to_binary(cipher_input)

            elif fmt == "3":
                cipher = base64_to_binary(cipher_input)

            break   # valid format + valid ciphertext

        except:
            print("\nError: Ciphertext does not match selected format.")
            print("Please choose the correct format again.\n")

    # KEY
    while True:
        key = input("Enter 10-bit key: ")
        if len(key) != 10 or any(b not in "01" for b in key):
            print("Error: Invalid key")
            continue
        break

    # IV
    while True:
        iv = input("Enter 8-bit IV: ")
        if len(iv) != 8 or any(b not in "01" for b in iv):
            print("Error: Invalid IV")
            continue
        break

    plain = cfb_decrypt(cipher, key, iv)

    print("\n=== DECRYPTION RESULT ===")
    print("Recovered Plaintext:", plain)


# =========================
# TEST SYSTEM
# =========================
def test_system():
    cipher, key, iv = encryption_system()
    print("\n--- Auto Decryption Test ---")
    print("Recovered Plaintext:", cfb_decrypt(cipher, key, iv))


# =========================
# MAIN MENU
# =========================
while True:
    print("\n===================================")
    print("      S-DES CFB CRYPTO SYSTEM      ")
    print("===================================")
    print("1. Encryption System")
    print("2. Decryption System")
    print("3. Encrypt + Decrypt Test")
    print("4. Exit")
    print("5. Ciphertext-Only Attack (COA)")
    print("6. Known-Plaintext Attack (KPA)")
    print("7. Chosen-Plaintext Attack (CPA)")
    print("8. Chosen-Ciphertext Attack (CCA)")
    print("9. Chosen-Text Attack (CTA)")
    print("10. Brute Force Attack")
    print("===================================")

    choice = input("Choose: ")

    if choice == "1":
        encryption_system()

    elif choice == "2":
        decryption_system()

    elif choice == "3":
        test_system()

    elif choice == "4":
        print("Exiting...")
        break

    # ================= ATTACKS =================
    elif choice == "5":
        COA()

    elif choice == "6":
        KPA()

    elif choice == "7":
        ensure_oracle()
        CPA(SECRET_KEY, SECRET_IV)

    elif choice == "8":
        ensure_oracle()
        CCA(SECRET_IV, SECRET_KEY)

    elif choice == "9":
        ensure_oracle()
        CTA(SECRET_KEY, SECRET_IV)

    elif choice == "10":
        brute_force()

    else:
        print("Invalid choice. Try again.")
