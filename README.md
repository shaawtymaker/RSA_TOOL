# 🔐 RSA Encryption & Decryption App

A simple Python **GUI application** for demonstrating **RSA encryption and decryption** using **Tkinter**.  
Perfect for learning how public-key cryptography works.  

---

## ✨ Features
- 🔑 Generate RSA key pairs `(public, private)`  
- 🔏 Encrypt plaintext into ciphertext  
- 🔓 Decrypt ciphertext back into plaintext  
- 🎨 Simple Tkinter-based GUI  

---

## 📦 Requirements
- Python **3.x**  
- Tkinter (comes pre-installed with Python)  

---

## 📂 Project Structure
rsa-project/
│
├── rsa_encryptor.py # GUI for encryption
├── rsa_decrypter.py # GUI for decryption
├── screenshot.png # Example GUI screenshot
└── README.md # Documentation

## ⚡ Installation
Clone the repository:
```bash
git clone https://github.com/your-username/rsa-project.git
cd rsa-project
```

▶️ Usage
🔏 Encryption

Run:
```bash
python rsa_encryptor.py
```

Enter your message.

Provide or generate (e, n) public key.

Click Encrypt to get ciphertext.


🔓 Decryption

Run:
```bash
python rsa_decrypter.py
```

Enter private key (d, n) in tuple format → e.g. (45659, 67721)

Paste ciphertext in Python list format → e.g. [24286, 24851, 48229, 48229, 45023]

Click Decrypt to reveal original message.


⚠️ Common Issues

❌ Key Format Error → Must be (d, n) without extra text like Private:

❌ Ciphertext Error → Must be [123, 456, ...] list format
