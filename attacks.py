from cfb import cfb_encrypt, cfb_decrypt
from utils import get_valid_ciphertext
from utils import to_binary
import random


def normalize_iv(iv):
    return iv.strip()


def safe_convert(ciphertext, fmt):
    data = to_binary(ciphertext, fmt)

    if data is None:
        print("Invalid ciphertext for selected format.")
        return None

    return data
# =========================
# SCORE FUNCTION
# =========================
def score_text(text):
    if not text or not text.isascii():
        return -1000 
    
    score = 0 
    t = text.lower() 
    words = t.split() 

    dictionary ={ "do", "it", "now", "to", "you", "the", "and", 
                  "page", "hello", "hi", "ok", "is", "here", "this"
    }

    for w in words:
        if w in dictionary:
            score += 20
        
        else: score -= 5 
    
    score += sum(c.isalpha() for c in text) * 2 
    score += sum(c.isspace() for c in text) 
    
    if "do it now" in t:
        score += 100 
        
    return score

# =========================
# HELPERS
# =========================
def ask_iv_mode():
    while True:
        print("\nDo you know the IV?")
        print("1. Yes")
        print("2. No")

        mode = input("Choose: ")

        if mode in ["1", "2"]:
            return mode

        print("Invalid choice. Enter 1 or 2 only.")


def print_result(best):
    print("\n=== RESULT ===")
    if best[1]:
        print("KEY:", best[1])
        print("IV:", best[2])
        print("PLAINTEXT:", best[3])
        print("SCORE:", best[0])
    else:
        print("No result found")


# =========================
# BRUTE FORCE
# =========================
def brute_force():
    ciphertext = get_valid_ciphertext()

    if len(ciphertext) < 16:
        print("Warning: Ciphertext is too short. Results may be unreliable.")

    mode = ask_iv_mode()

    best_score = -1000
    candidates = []

    if mode == "1":
        iv = input("Enter 8-bit IV: ")

        for k in range(1024):
            key = format(k, "010b")

            try:
                pt = cfb_decrypt(ciphertext, key, iv)
                s = score_text(pt)

                if s > best_score:
                    best_score = s
                    candidates = [(key, iv, pt, s)]

                elif s == best_score:
                    candidates.append((key, iv, pt, s))

            except:
                pass

    else:
        for k in range(1024):
            key = format(k, "010b")

            for i in range(256):
                iv = format(i, "08b")

                try:
                    pt = cfb_decrypt(ciphertext, key, iv)
                    s = score_text(pt)

                    if s > best_score:
                        best_score = s
                        candidates = [(key, iv, pt, s)]

                    elif s == best_score:
                        candidates.append((key, iv, pt, s))

                except:
                    pass

    print("\n=== BEST CANDIDATES ===")

    for idx, item in enumerate(candidates, 1):
        key, iv, pt, s = item
        print(f"\nCandidate {idx}")
        print("KEY:", key)
        print("IV:", iv)
        print("PLAINTEXT:", pt)
        print("SCORE:", s)


# =========================
# COA
# =========================
def COA():
    ciphertext = get_valid_ciphertext()
    mode = ask_iv_mode()
    best = (-1000, None, None, None)

    if mode == "1":
        iv = input("Enter 8-bit IV: ")

        for k in range(1024):
            key = format(k, "010b")
            try:
                pt = cfb_decrypt(ciphertext, key, iv)
                s = score_text(pt)
                if s > best[0]:
                    best = (s, key, iv, pt)
            except:
                pass
    else:
        for k in range(1024):
            key = format(k, "010b")

            for i in range(256):
                iv = format(i, "08b")
                try:
                    pt = cfb_decrypt(ciphertext, key, iv)
                    s = score_text(pt)
                    if s > best[0]:
                        best = (s, key, iv, pt)
                except:
                    pass

    print_result(best)


# =========================
# KPA
# =========================
def KPA():
    print("\n=== Known Plaintext Attack ===")

    ciphertext = get_valid_ciphertext()
    plaintext = input("Enter known plaintext: ")
    mode = ask_iv_mode()

    if mode == "1":
        iv = input("Enter IV: ")

        for k in range(1024):
            key = format(k, "010b")
            if cfb_encrypt(plaintext, key, iv) == ciphertext:
                print("\nFOUND KEY:", key)
                return
    else:
        for k in range(1024):
            key = format(k, "010b")

            for i in range(256):
                iv = format(i, "08b")

                if cfb_encrypt(plaintext, key, iv) == ciphertext:
                    print("\nFOUND KEY:", key)
                    print("FOUND IV:", iv)
                    return

    print("No result found")


def encrypt_oracle(plaintext, iv, secret_key):
    return cfb_encrypt(plaintext, secret_key, iv)
# =========================
# CPA
# =========================
def CPA(secret_key, secret_iv):
    print("\n[+] Chosen Plaintext Attack")

    plaintext = input("Enter chosen plaintext: ")

    print("\nChoose IV mode:")
    print("1. Known IV")
    print("2. Unknown IV")
    mode = input("Choose: ")

    if mode == "1":
        iv = input("Enter IV: ")
    else:
        iv = secret_iv

    ciphertext = cfb_encrypt(plaintext, secret_key, iv)

    print("\n[Oracle ciphertext]:", ciphertext)

    # attacker tries to recover key
    best_key = None

    for k in range(1024):
        key = format(k, "010b")

        if cfb_encrypt(plaintext, key, iv) == ciphertext:
            best_key = key
            break
        
    print("\n[Best guessed key]:", best_key)

# =========================
# CCA
# =========================
def normalize_bits(bits):
    #Remove spaces and ensure clean comparison
    return ''.join(bits.split())

def decryption_oracle(ciphertext, key, iv):
    return cfb_decrypt(ciphertext, key, iv)

def CCA(secret_iv, secret_key):
    print("\n[+] Chosen-Ciphertext Attack")

    ciphertext = get_valid_ciphertext()

    print("\nDo you know IV?")
    print("1. Yes")
    print("2. No")
    mode = input("Choose: ")

    if mode == "1":
        iv = input("Enter IV: ").strip()
    else:
        iv = secret_iv

    iv = normalize_iv(iv)

    # oracle (real system)
    oracle_plaintext = cfb_decrypt(ciphertext, secret_key, iv)

    best_key = None
    best_score = -99999

    for k in range(1024):
        key = format(k, "010b")

        try:
            pt = cfb_decrypt(ciphertext, key, iv)
            score = score_text(pt)

            if score > best_score:
                best_score = score
                best_key = key

        except:
            continue

    print("\n[Oracle plaintext]:", oracle_plaintext)
    print("BEST KEY GUESS:", best_key)

# =========================
# CTA
# =========================
def CTA(secret_key, secret_iv):
    print("\n[+] Chosen-Text Attack")

    print("Choose operation:")
    print("1. Encrypt chosen plaintext")
    print("2. Decrypt chosen ciphertext")
    mode = input("Choose: ")

    print("\nDo you know IV?")
    print("1. Yes")
    print("2. No")
    iv_mode = input("Choose: ")

    if iv_mode == "1":
        iv = input("Enter IV: ").strip()
    else:
        iv = secret_iv

    iv = normalize_iv(iv)

    print("IV used:", iv)

    # ---------------- encryption oracle ----------------
    if mode == "1":
        plaintext = input("Enter plaintext: ")

        ciphertext = cfb_encrypt(plaintext, secret_key, iv)

        print("\n[Oracle ciphertext]:", ciphertext)

    # ---------------- decryption oracle ----------------
    elif mode == "2":
        ciphertext = get_valid_ciphertext()

        try:
            plaintext = cfb_decrypt(ciphertext, secret_key, iv)
        except:
            plaintext = "<decryption failed>"

        print("\n[Oracle plaintext]:", plaintext)

    else:
        print("Invalid option")