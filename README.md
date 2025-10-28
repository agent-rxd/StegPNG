<h1 align="center">🔒 StegPNG - LSB Steganography Tool</h1>

<p align="center">
  A Python GUI tool for hiding encrypted text inside PNG images using LSB steganography.
</p>

<p align="center">
  <a href="https://www.python.org/downloads/release/python-370/">
    <img src="https://img.shields.io/badge/python-3.7%2B-blue.svg?style=for-the-badge&logo=python" alt="Python 3.7+">
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="License: MIT">
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey.svg?style=for-the-badge" alt="Platform: Windows | Linux | macOS">
  </a>
</p>

<p align="center">
  <img src="stegpng_demo.gif" alt="StegPNG Demo GIF" width="750px"/>
</p>

---

## 📍 Table of Contents

- [Why StegPNG?](#-why-stegpng)
- [Key Features](#-key-features)
- [How It Works: A Technical Deep Dive](#-how-it-works-a-technical-deep-dive)
- [Installation & Setup](#-installation--setup)

---

## 🚀 Why StegPNG?

In a world of constant surveillance, true data privacy is rare. Steganography is the art of hiding data in plain sight. This tool was built to provide a simple, secure, and modern way to hide secret messages.

Unlike other tools that hide data in JPEGs (which can be corrupted by lossy compression), **StegPNG is built exclusively for PNG files**. This lossless format guarantees that every single bit of your hidden message is preserved perfectly, byte for byte.

It combines this reliable LSB (Least Significant Bit) hiding technique with military-grade encryption to create a two-layer security system:
1.  **Obscurity:** The message is invisible to the naked eye.
2.  **Security:** Even if the message is found, it is unreadable without the password.

This project is a perfect demonstration of applied cryptography, data manipulation, and modern GUI development in Python.

---

## ✨ Key Features

* **💻 Cyberpunk Aesthetic:** A dark-mode, hacker-themed GUI built with Tkinter, using green-on-black terminal colors.
* **🔒 Military-Grade Encryption:** Secures messages **before** hiding them using **AES-256 (CBC Mode)**, a symmetric encryption standard trusted by governments worldwide.
* **🔑 Password-Protected:** Uses **PBKDF2 (Password-Based Key Derivation Function 2)** with a 100,000-iteration hash to derive a strong encryption key from your password. This provides excellent protection against brute-force attacks.
* **🔬 Lossless Hiding:** Exclusively designed for PNG files to ensure 100% data integrity.
* **✅ Data Integrity Check:** The tool prepends a 4-byte length header to the encrypted message. During extraction, it reads this header first, so it knows *exactly* how many bytes to retrieve, preventing data corruption or "junk" bytes at the end.
* **📦 Cross-Platform:** Written in pure Python with standard libraries, `StegPNG` runs on Linux, Windows, and macOS.

---

## 🔧 How It Works: A Technical Deep Dive

The security of `StegPNG` comes from a clear, multi-step process for both hiding and extracting data.

### Hiding Process

1.  **Encrypt 🔐:** The plain-text message and password are not stored directly.
    * `Password` + `Random Salt` → `PBKDF2` → `32-byte (256-bit) AES Key`
    * `Message` + `AES Key` + `IV` → `AES-256 (CBC)` → **`Encrypted Bytes`**

2.  **Prepare 📦:** The final data to be hidden is constructed.
    * `Message Length` → `4-byte Header` (e.g., a 500-byte message becomes `b'\x00\x00\x01\xF4'`)
    * **`Payload`** = `4-byte Header` + `Salt` + `IV` + `Encrypted Bytes`

3.  **Hide 🎨:** The `Payload` is converted into a long string of bits (e.g., `01010111...`).
    * The tool reads the cover PNG pixel by pixel.
    * For each pixel, it modifies the **Least Significant Bit (LSB)** of the Red, Green, and Blue channels to match the bits from the payload.
    * `Original (R: 1101010**1**, G: 0010101**0**, B: 1110001**1**)` → `Hidden Bit: 010` → `New (R: 1101010**0**, G: 0010101**1**, B: 1110001**0**)`
    * This change is so small (e.g., a value of 221 becomes 220) that it is completely invisible to the human eye.

### Extraction Process

1.  **Read Header 📖:** The tool reads the LSBs from the first ~11 pixels to reconstruct the first 32 bits (4 bytes).
    * `Bits` → `4-byte Header` → `int.from_bytes()` → **`Message Length`**

2.  **Extract 🚛:** Now knowing the *exact* length, the tool continues reading LSBs until it has collected the full payload (Salt + IV + Encrypted Message).

3.  **Decrypt 🔑:** The tool reverses the encryption process.
    * `Password` + `Salt (from payload)` → `PBKDF2` → `32-byte (256-bit) AES Key`
    * `Encrypted Bytes` + `AES Key` + `IV (from payload)` → `AES-256 (CBC)` → **`Original Message`**
    * If the password is wrong, the derived key will be wrong, and the decryption will fail, resulting in garbage data (or a padding error).

---

## 💻 Installation & Setup

This tool is simple to run. No complex installation is needed.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/agent-rxd/StegPNG.git
    cd StegPNG
    ```

2.  **Create a virtual environment:**
    ```bash
    # On Linux/macOS
    python3 -m venv venv
    source venv/bin/activate
    
    # On Windows
    python -m venv venv
    .\venv\Scripts\activate
    ```

3.  **Install the requirements:**
    ```bash
    pip install -r requirements.txt
    ```

---

## ▶️ How to Use

Run the tool from your activated virtual environment:

```bash
python3 stegpng.py
