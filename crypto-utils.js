/**
 * cryptoUtils.js
 * 
 * Secure AES-256-GCM encryption and decryption utilities.
 * 
 * Usage:
 * const { encrypt, decrypt } = require('./cryptoUtils');
 * const cipherText = encrypt('Hello World');
 * const plainText = decrypt(cipherText);
 */

const crypto = require('crypto');
require('dotenv').config();

// =========================
// CONFIGURATION
// =========================
const ALGORITHM = 'aes-256-gcm';   // Encryption algorithm + mode
const IV_LENGTH = 12;              // 12 bytes = recommended IV size for GCM
const KEY_LENGTH = 32;             // 32 bytes = 256-bit key for AES-256

// Derive a 256-bit key from your SECRET_KEY (string) using scrypt KDF
const KEY = crypto.scryptSync(process.env.SECRET_KEY, 'salt', KEY_LENGTH);

// =========================
// ENCRYPTION FUNCTION
// =========================
function encrypt(text) {
  // 1️⃣ Generate a random IV (unique for each encryption)
  const iv = crypto.randomBytes(IV_LENGTH);

  // 2️⃣ Create AES-GCM cipher instance
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);

  // 3️⃣ Encrypt the text (UTF-8 → binary)
  const encrypted = Buffer.concat([
    cipher.update(text, 'utf8'),
    cipher.final()
  ]);

  // 4️⃣ Get authentication tag (ensures integrity)
  const tag = cipher.getAuthTag();

  // 5️⃣ Return combined result in hex format
  return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
}

// =========================
// DECRYPTION FUNCTION
// =========================
function decrypt(data) {
  try {
    // 1️⃣ Split stored string into components
    const [ivHex, tagHex, encryptedHex] = data.split(':');

    // 2️⃣ Convert hex → binary buffers
    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');
    const encrypted = Buffer.from(encryptedHex, 'hex');

    // 3️⃣ Create AES-GCM decipher instance
    const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);
    decipher.setAuthTag(tag); // Add integrity tag for verification

    // 4️⃣ Decrypt the ciphertext
    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ]);

    // 5️⃣ Return readable text
    return decrypted.toString('utf8');
  } catch (err) {
    throw new Error('Decryption failed or data is corrupted.');
  }
}

