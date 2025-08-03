# 🔐 SecureChat

A real-time, end-to-end encrypted chat application built with Python. This project demonstrates a classic client-server architecture secured with a hybrid encryption model, combining the strengths of both asymmetric (RSA) and symmetric (AES) cryptography.

This was originally my university assignment from late 2022, which has since been updated with modern, robust security practices.

## 🎯 **Project Purpose**

This repository is designed for students and developers who want to understand the fundamentals of network programming and applied cryptography. It provides a clear, practical example of:

- **Asymmetric Cryptography (RSA)**: For a secure initial key exchange.
- **Symmetric Cryptography (AES-GCM)**: For fast and secure message encryption.
- **Hashing for Integrity (SHA-256)**: To verify data authenticity.
- **Multi-threaded Communication**: To enable simultaneous sending and receiving.

## ✨ **Key Features & Security Enhancements**

This project uses a combination of modern cryptographic standards to protect your conversations.

- **🔑 Secure Handshake**: Establishes a secure channel using an **RSA-2048 key exchange** to safely share a session key.
- **🔒 Authenticated Encryption**: All messages are encrypted with **AES-256-GCM**, which provides both confidentiality and integrity, protecting against eavesdropping and tampering.
- **🛡️ Integrity Verification**: Public keys and messages are hashed with **SHA-256** to ensure they have not been altered.
- **💬 Real-Time Communication**: Built with Python's `threading` library to allow for a seamless, real-time chat experience.

## 🚀 **Getting Started**

### **Prerequisites**

- Python 3.7+
- pycryptodome 3.23.0

### **Installation**

1.  Clone the repository:

    ```bash
    git clone https://github.com/afifhaziq/SecureChat.git
    cd SecureChat
    ```

2.  Create and activate a virtual environment:

    ```bash
    # For Windows
    python -m venv venv
    .\venv\Scripts\activate

    # For macOS/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  Install the required packages:
    ```bash
    pip install -r requirements.txt
    ```

### **Running the Application**

1.  **Start the Server**: Open a terminal and run the server. Enter an IP address (e.g., `127.0.0.1` for local) and a port.
    `bash
    python Server.py
    `
    **Note: For demonstration purposes just run it local with loopback address 127.0.0.1 and port 80**

2.  **Start the Client**: Open a second terminal, activate the virtual environment, and run the client. Use the same IP address and port.
    ```bash
    python Client.py
    ```
3.  You can now start chatting securely!

## 📜 **License**

This project is open-source and you are welcome to contribute and benefit from it
