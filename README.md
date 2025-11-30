<!-- Badges -->
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![PySide6](https://img.shields.io/badge/PySide6-%3E%3D6.0-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)
![Release](https://img.shields.io/badge/Release-v1.0.0-orange)
![Issues](https://img.shields.io/github/issues/Ankit-Upreti/ShadowCrypt-Pro)

# ShadowCrypt Pro 🔐  
A modern, professional AES-GCM file encryption application with a PySide6 GUI.

ShadowCrypt Pro is a powerful, user-friendly file encryption tool built using **PySide6**, **AES-GCM**, and **PBKDF2**. It supports secure password-based encryption, chunked streaming for large files, background-threaded processing, and a sleek dark hacker-themed interface.

---

<!-- ## 🚀 Features -->

### 🔐 Security
- AES-256-GCM authenticated encryption  
- PBKDF2-HMAC-SHA256 key derivation  
- Random salt & nonce generation  
- Integrity verification (prevents tampering)  
- Secure password handling  

<!-- ### 🖥️ GUI (PySide6) -->
- Dark hacker interface  
- Sidebar navigation  
- File selection + password input  
- Show/hide password toggle  
- Real-time console logs  
- Smooth progress bar  
- Threaded encryption/decryption (UI never freezes)  
- Settings (PBKDF2 iterations, chunk size)  

<!-- ### 📁 File Handling -->
- Works with ANY file type  
- Chunked read/write for large files  
- Preserves original file extension  

---

<!-- ## 🗂️ Repository Structure -->

ShadowCrypt-Pro/
│
├── src/
│ ├── shadowcrypt_pro.py # Main PySide6 GUI application
│
├── resources/
│ ├── icon.ico # App icon
│
├── docs/
│ ├── screenshots/ # Optional UI screenshots
│ └── report.pdf # College project report 
│
├── dist/ # Created after building exe
│ └── ShadowCrypt.exe  # Download directly
│
├── README.md
├── requirements.txt
├── LICENSE
└── .gitignore


---

## 🛠️ Installation

### 1. Clone the repository
```bash
git clone https://github.com/<your-username>/ShadowCrypt-Pro.git
cd ShadowCrypt-Pro


# 2. Install dependencies

pip install -r requirements.txt


# ▶️ Run the Application (Development Mode)

cd src
python shadowcrypt_pro.py


# 📦 Build Windows Executable (PyInstaller)

# 1. Install PyInstaller

pip install pyinstaller

# 2. Build the standalone EXE

pyinstaller --onefile --noconsole --name "ShadowCrypt" --icon=resources/icon.ico shadowcrypt_pro.py


# Output appears in:

dist/ShadowCrypt.exe

# If using logos/images:

pyinstaller --onefile --noconsole --name "ShadowCrypt" \
 --icon=resources/icon.ico \
 --add-data "resources/logo.png;resources" \
 shadowcrypt_pro.py


# 🔧 Settings Overview

# PBKDF2 Iterations

Used to hash the password into a strong key.
Higher = more secure (but slightly slower).

# Chunk Size

Controls how much data is processed at a time.
Larger chunks = faster but more RAM use.

# 🔒 Encryption File Format

Encrypted files follow this layout:

salt   (16 bytes)
nonce  (16 bytes)
ciphertext (variable)
tag    (16 bytes)

for ensuring confidentiality + integrity using AES-GCM.


# 🛡️ Security Notes

-Strong enough for academic/portfolio use
-For production security:
   -Use Argon2 instead of PBKDF2
   -Add digital signatures
   -Use secure key management


👨‍💻 Author

Ankit Upreti
Year - 3rd Year
B.Tech – Mini Project
ShadowCrypt Pro © 2025


# 📝 License

This project is licensed under the MIT License.
See LICENSE for full text.
