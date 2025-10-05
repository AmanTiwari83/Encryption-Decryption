# 🔐 AES-256-GCM Encryption & Decryption (`cryptoUtils.js`)

This document explains how the `encrypt()` and `decrypt()` methods work in Node.js using the **crypto** module and the **AES-256-GCM** encryption algorithm.

---

## 🧩 Overview

We use **AES (Advanced Encryption Standard)** with **GCM (Galois/Counter Mode)** — a modern, secure encryption standard that provides:

- 🔒 **Confidentiality** → hides your data from unauthorized access  
- 🧱 **Integrity** → detects if data has been tampered with  
- ✅ **Authentication** → verifies the data was encrypted with the correct key  

> AES-GCM is the same encryption mode used in **HTTPS**, **VPNs**, and **secure messaging protocols** like Signal and WhatsApp.

---

## ⚙️ How It Works

When you encrypt something, AES-GCM produces **three outputs**:

| Component | Description | Example |
|------------|-------------|----------|
| **IV (Initialization Vector)** | A random, unique value generated for each encryption. Prevents output repetition. | `8a71a8b55c492baf8d3225eb` |
| **Auth Tag** | A verification code that ensures data integrity and authenticity. | `60b6c83699651e4ed09f698cfd19975b` |
| **Ciphertext** | The encrypted data (unreadable without the key). | `2b9e927e97b91d034dea6b833e` |

These three parts are combined into a single string:
<IV>:<AuthTag>:<Ciphertext>

Example:
8a71a8b55c492baf8d3225eb:60b6c83699651e4ed09f698cfd19975b:2b9e927e97b91d034dea6b833e