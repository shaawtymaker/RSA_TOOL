🔐 RSA Encryption & Decryption Application

A simple Python GUI application for demonstrating RSA encryption and decryption.
Built with Tkinter.

🚀 Features

Generate RSA key pairs (public, private)

Encrypt plaintext messages into ciphertext

Decrypt ciphertext back into plaintext

Simple, minimal GUI

🛠 Requirements

Python 3.x

Tkinter (comes pre-installed with Python)

📂 Project Structure
rsa_project/
│
├── rsa_encryptor.py   # GUI for encryption
├── rsa_decrypter.py   # GUI for decryption
└── README.md          # Documentation

▶️ Usage
1. Run the Encryptor
python rsa_encryptor.py


Enter a message in the text box.

Generate keys or enter your own (e, n) public key.

Click Encrypt to get ciphertext.

2. Run the Decrypter
python rsa_decrypter.py


Enter the private key (d, n)
👉 Format: (45659, 67721) (tuple format)

Paste ciphertext in Python list format
👉 Example: [24286, 24851, 48229, 48229, 45023]

Click Decrypt to reveal the original message.

⚠️ Common Issues

❌ Error when decrypting → Make sure you type the private key as (d, n) without extra text like Private:.

❌ Invalid ciphertext format → Ciphertext must be a Python-style list [123, 456, ...].


📘 Notes

This is a learning project to demonstrate RSA.

Do not use for real-world security.

Keys are generated with small primes (not secure).
