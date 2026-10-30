# Cryptography Labs

University laboratory works on cryptography (UPJS / previous coursework).

Practical assignments covering classical ciphers, stream ciphers, block ciphers, modes of operation, padding and related cryptanalysis techniques.

## Structure

| File | Description |
|------|-------------|
| `Lab1_Cryptography_Yusupov_A.ipynb` | Classical substitution ciphers (monoalphabetic, affine, polygraphic, Atbash) |
| `Lab2_Vigenere_Shift_Yusupov_A.py` | Vigenère and Shift ciphers |
| `Lab3_Cryptography_Yusupov_A.ipynb` | LFSR, stream cipher cryptanalysis, Berlekamp-Massey |
| `Lab4_Cryptography_Yusupov_A.ipynb` | Stream & block ciphers test vectors (RC4, ChaCha20, ChaCha20-Poly1305, DES) + avalanche effect |
| `Lab5_Cryptography_Yusupov_A.ipynb` | Block ciphers, padding modes (PKCS#7 / ISO 7816 / X.923), error propagation across modes (ECB/CBC/OFB/CFB/CTR/OpenPGP) + modern AEAD (AES-GCM/CCM/EAX/SIV) |

## Topics covered

- Classical substitution ciphers (monoalphabetic, affine, polygraphic, Atbash)
- Vigenère and shift ciphers
- Linear Feedback Shift Registers (LFSR)
- Stream cipher cryptanalysis & Berlekamp-Massey algorithm
- Known-plaintext attacks
- Modern stream/block ciphers validation (RFC test vectors)
- Avalanche effect analysis
- Padding schemes for block ciphers
- Error propagation in different modes of operation
- Authenticated Encryption with Associated Data (AEAD)

## Requirements

- Python 3.x
- Jupyter Notebook / JupyterLab
- `pycryptodome` (or `pycryptodomex`)

```bash
pip install pycryptodome
```

## Author

**Abdulatif Yusupov**  
Cybersecurity Engineering
