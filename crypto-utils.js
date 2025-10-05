/**
 * ======================================================
 * 🔐 AES-256-GCM Encryption / Decryption Utility
 * ------------------------------------------------------
 * - Uses Node.js built-in crypto library (OpenSSL-based)
 * - Industry-standard authenticated encryption
 * - Safe for production use
 * ======================================================
 */

require('dotenv').config();
const crypto = require('crypto');

// =========================
// Configuration Constants
// =========================

// Algorithm and mode of encryption
// (Stored in .env for flexibility, but not required)
const ALGORITHM = process.env.ALGORITHM || 'aes-256-gcm';

// IV (Initialization Vector) length for AES-GCM = 12 bytes (96 bits)
const IV_LENGTH = 12;

// Key length for AES-256 = 32 bytes (256 bits)
const KEY_LENGTH = 32;

// Derive a 256-bit key from SECRET_KEY + SALT using scrypt (strong KDF)
const KEY = crypto.scryptSync(process.env.SECRET_KEY, process.env.SALT, KEY_LENGTH);

/**
 * Encrypt a plaintext string using AES-256-GCM
 * @param {string} text - The plaintext to encrypt
 * @returns {string} Combined IV:AuthTag:Ciphertext (hex-encoded)
 */
function encrypt(text) {
  // Generate a new random IV for each encryption (critical for security)
  const iv = crypto.randomBytes(IV_LENGTH);

  // Create cipher using algorithm, key, and IV
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);

  // Perform encryption
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);

  // Get authentication tag (integrity protection)
  const tag = cipher.getAuthTag();

  // Return the combined result as hex strings
  return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
}

/**
 * Decrypt a previously encrypted string using AES-256-GCM
 * @param {string} text - The IV:AuthTag:Ciphertext combined string
 * @returns {string} Decrypted plaintext
 */
function decrypt(text) {
  try {
    // Split the input into its 3 components
    const [ivHex, tagHex, encryptedHex] = text.split(':');
    if (!ivHex || !tagHex || !encryptedHex) {
      throw new Error('Invalid encrypted data format.');
    }

    // Convert hex back to binary
    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');
    const encrypted = Buffer.from(encryptedHex, 'hex');

    // Create decipher using the same algorithm, key, and IV
    const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);

    // Apply authentication tag (to verify integrity)
    decipher.setAuthTag(tag);

    // Perform decryption
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

    return decrypted.toString('utf8');
  } catch (err) {
    throw new Error('Decryption failed or data is corrupted.');
  }
}

module.exports = { encrypt, decrypt };
