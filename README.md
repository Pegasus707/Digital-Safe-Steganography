# 🛡️ Digital Safe v2.0

A modern, professional desktop application to hide secret, encrypted files inside ordinary images. This tool combines **cryptography** (for security) with **steganography** (for secrecy) in a slick, easy-to-use GUI.

This is a "safe inside a safe." Your file isn't just hidden—it's fully encrypted first. Even if someone finds your secret image, they can't access the data without your password.

---

## 🚀 Key Features

* **Modern, Slick GUI:** Built with **`CustomTkinter`** for a clean, professional "native app" feel.
* **True "Spy-Craft" Security:** Uses **LSB (Least Significant Bit) steganography** to hide data at the pixel level, making it visually undetectable.
* **Real Encryption:** Integrates the **`cryptography`** library to **encrypt** all files with a password before hiding them.
* **Multi-Threaded:** The app's frontend **never freezes**, as all heavy encryption and encoding runs on a separate thread.
* **Clean & Organized:** The UI (`safe_app.py`) is completely separate from the "brain" (`steganography_engine.py`).

---

## 🛠️ How It Works: The "Backend" Engine

This project was built from scratch to show a deep understanding of file manipulation and security principles.

1.  **Password-Based Key:** Your password (e.g., `my-pass-123`) is combined with a random "salt" and run through a **PBKDF2 Key Derivation Function** to create a secure 32-byte encryption key.
2.  **AES Encryption:** The secret file is read and fully encrypted using the **Fernet** (AES-128) cipher from the `cryptography` library.
3.  **Bit-Level Hiding:** The *new, encrypted* data (plus a secret "STOP" marker) is converted into a stream of bits (`10110...`).
4.  **LSB Encoding:** The app opens the "cover" image pixel by pixel. It changes the **Least Significant Bit (LSB)** of each pixel's Red, Green, and Blue values to match the secret bitstream. This change is so small (e.g., changing a color value from 254 to 255) that it's **invisible to the human eye.**
5.  **Extraction:** The "Decode" process does this in reverse: it reads the LSB of every pixel, reassembles the encrypted file, and uses your password to decrypt it. If the password is wrong, the decryption fails, and the file remains secure.

---

## 💻 How to Run This Project

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/YOUR-USERNAME/Digital-Safe-Steganography.git](https://github.com/YOUR-USERNAME/Digital-Safe-Steganography.git)
    cd Digital-Safe-Steganography
    ```
2.  **Create a Virtual Environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
4.  **Run the App:**
    ```bash
    python safe_app.py
    ```
