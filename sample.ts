import CryptoES from "crypto-es";

function deriveKeyFromPassphrase(
  passphrase: string,
  salt: any,
  keyLength: number,
  iterations: number
) {
  const saltString = CryptoES.enc.Base64.stringify(salt);
  const key = CryptoES.PBKDF2(passphrase, saltString, {
    keySize: keyLength,
    iterations: iterations,
  });

  return key;
}

function encryptMessage(message: string, passphrase: string) {
  const salt = CryptoES.lib.WordArray.random(8); // Generate a random 64-bit salt
  const key = deriveKeyFromPassphrase(passphrase, salt, 256, 100000); // Assuming AES-256

  // Generate a random IV (Initialization Vector)
  const iv = CryptoES.lib.WordArray.random(16);

  // Convert the message to a WordArray
  const plaintext = CryptoES.enc.Utf8.parse(message);

  // Pad the message
  CryptoES.pad.Pkcs7.pad(plaintext, 16);

  // Encrypt the padded message
  const ciphertext = CryptoES.AES.encrypt(
    plaintext,
    // { ciphertext: paddedPlaintext },
    key,
    { iv: iv, mode: CryptoES.mode.CBC, padding: CryptoES.pad.NoPadding } // NoPadding because we've already padded manually
  );

  // Combine salt, iv, and ciphertext and encode as base64
  const encryptedMessage = CryptoES.enc.Base64.stringify(
    CryptoES.lib.WordArray.create(
      salt.words.concat(iv.words, ciphertext.ciphertext?.words || [])
    )
  );

  return encryptedMessage;
}

function decryptMessage(encryptedMessage: string, passphrase: string) {
  // Decode the base64-encoded input
  const _encryptedBytes = CryptoES.enc.Base64.parse(encryptedMessage);
  // convert to string
  const encryptedBytes = _encryptedBytes.toString(CryptoES.enc.Utf8);

  // Extract salt and IV
  const salt = encryptedBytes.slice(0, 8);
  const iv = encryptedBytes.slice(8, 24);
  // const salt = encryptedBytes.clone().read(8);
  // const iv = encryptedBytes.clone().read(16);

  const key = deriveKeyFromPassphrase(passphrase, salt, 256, 100000);

  // Create an AES cipher object with CBC mode
  const cipher = CryptoES.AES.algo.CBC.createDecryptor(key, { iv: iv });

  // Decrypt and unpad the message
  const decryptedBytes = cipher.process(encryptedBytes.words.slice(24));
  const unpaddedBytes = CryptoES.pad.pkcs7.strip(
    CryptoES.lib.WordArray.create(decryptedBytes)
  );

  // Convert the decrypted bytes to a string
  const decryptedMessage = CryptoES.enc.Utf8.stringify(unpaddedBytes);

  return decryptedMessage;
}

// Example usage and test:
const passphrase = "Secret Passphrase";
const messageToEncrypt = "This is a secret message.";

// Encrypt the message
const encryptedMessage = encryptMessage(messageToEncrypt, passphrase);
console.log("Encrypted Message:", encryptedMessage);

// Decrypt the message
const decryptedMessage = decryptMessage(encryptedMessage, passphrase);
console.log("Decrypted Message:", decryptedMessage);

// Ensure the decrypted message matches the original message
console.log("Decryption Match:", decryptedMessage === messageToEncrypt);
