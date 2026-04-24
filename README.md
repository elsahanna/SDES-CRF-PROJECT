# S-DES CFB Cryptography Project

## Description
This project implements Simplified DES (S-DES) using Cipher Feedback (CFB) mode in Python.

It supports:
- Encryption
- Decryption
- Binary / Hex / Base64 formats
- Multiple cryptanalysis attacks
- Brute force attack

---

## Files

- `main.py` → Main menu and system execution
- `sdes.py` → Core S-DES algorithm
- `cfb.py` → CFB mode implementation
- `utils.py` → Helper functions and validation
- `attacks.py` → Cryptanalysis attacks

---

## Features

### Encryption
Encrypt plaintext using:
- 10-bit key
- 8-bit IV

Outputs:
- Binary
- Hex
- Base64

### Decryption
Decrypt ciphertext using correct key and IV.

---

## Implemented Attacks

### COA
Ciphertext-Only Attack

### KPA
Known Plaintext Attack

### CPA
Chosen Plaintext Attack

### CCA
Chosen Ciphertext Attack

### CTA
Chosen Text Attack

### Brute Force
Tests all possible keys.

---

## Requirements

- Python 3.x

No external libraries required.

---

## How to Run

```bash
python main.py