# Secure-Data-Exchange-Crypto-System
Hybrid cryptographic system implementing ECDH key exchange, Schnorr signatures, and GOST-GCM encryption for secure and authenticated communication.


# 🔐 Secure Mail Exchange System (ECDH + Schnorr + GOST-GCM)

## 📌 Overview
This project implements a **secure communication system over an untrusted channel** using modern cryptographic techniques.

It simulates secure message exchange between two parties (**Alice & Bob**) and combines:

- 🔑 Elliptic Curve Diffie-Hellman (ECDH) – for key exchange  
- ✍️ Schnorr Digital Signatures – for authentication  
- 🔒 GOST (Kuznyechik) in GCM mode – for encryption + integrity  
- 🔐 Secure Key Storage – using PBKDF2 + GCM  
- 🖥️ GUI Application – built with Tkinter  

The system guarantees:
- **Confidentiality**
- **Integrity**
- **Authenticity**

---

## 🧠 System Architecture

### 1. Key Exchange (ECDH)
Each user generates a public/private key pair and derives a shared secret securely.

- Implemented using elliptic curve operations
- Session key derived via SHA-256

---

### 2. Digital Signature (Schnorr)
Before sending a message:
- The sender signs it using their private key  
- The receiver verifies it using the sender's public key  

---

### 3. Encryption (GOST-GCM)
- Uses the Kuznyechik block cipher  
- Operates in GCM mode (Authenticated Encryption)  
- Ensures both **confidentiality** and **tamper detection**

---

### 4. Secure Key Storage
- Private keys are encrypted using:
  - PBKDF2 (SHA-256, 200,000 iterations)
  - GCM encryption  
- Stored safely in `users.json`

---

### 5. GUI Application
A full interactive interface simulating:
- User login
- Secure handshake
- Message sending
- Attack simulation (packet tampering)

---

## 🚀 Features

- 🔐 End-to-end encrypted communication  
- 🔄 Secure key exchange without prior contact  
- ✍️ Digital signatures (Schnorr)  
- 🧪 Built-in unit tests  
- 🧩 Fully modular cryptographic implementation  
- 🖥️ Interactive GUI simulation  
- 🚫 No external crypto libraries used  

---


https://github.com/user-attachments/assets/c0fe0866-ae7e-4cd4-bdb2-f8a9e8cc10ed


