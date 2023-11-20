import CryptoES from "crypto-es";

function wordArrayToUint8Array(wordArray) {
  // Convert the WordArray to a Uint8Array
  const uint8Array = new Uint8Array(wordArray.sigBytes);

  // Copy the bytes from the WordArray to the Uint8Array
  for (let i = 0; i < wordArray.sigBytes; i++) {
    uint8Array[i] = (wordArray.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  }

  return uint8Array;
}

function deriveKeyFromPassphrase(
  passphrase: string,
  salt: string, // as hex string
  keyLength: number,
  iterations: number
) {
  //   console.log("hex", CryptoES.enc.Hex.parse(salt.toString("hex")));
  const _saltAsWordArray = CryptoES.enc.Hex.parse(salt);
  const key = CryptoES.PBKDF2(passphrase, _saltAsWordArray, {
    keySize: keyLength / 32,
    iterations: iterations,
  });
  return key;
}

function encodePayload(payload: any, server_secret: string) {
  //assuming user password is "Secret password"
  const userPassword = "Secret password";
  const encryptedPassword = encryptMessage(
    userPassword,
    server_secret,
    "",
    false
  );
  const encryptedPayload = encryptMessage(
    JSON.stringify(payload),
    userPassword,
    encryptedPassword
  );
  return encryptedPayload;
}

function encryptMessage(
  message: string,
  passphrase: string,
  embed = "",
  encode = true
) {
  //   const salt = "01380ccf6c17bb7b";
  const salt = CryptoES.lib.WordArray.random(8).toString();
  console.log("salt", salt);
  const key = deriveKeyFromPassphrase(passphrase, salt, 256, 100000);

  // Generate a random IV (Initialization Vector)
  const iv = CryptoES.lib.WordArray.random(16);

  let messagePadded = CryptoES.enc.Utf8.parse(message);

  // Create an AES cipher object with CBC mode
  const cipher = CryptoES.AES.encrypt(messagePadded, key, { iv: iv });
  //   console.log("cipherString", cipher.toString(),'ciphertext',cipher.ciphertext);

  const add_key = embed ? embed : key.toString();
  const beforeEncode = salt + iv + add_key + cipher.ciphertext;
  //   const beforeEncode = salt + iv + key + cipher.ciphertext;
  console.log("embed", add_key);
  console.log("iv", iv.toString());
  console.log("cipher.ciphertext", cipher.ciphertext.toString());
  console.log("beforeEncode", beforeEncode);
  if (!encode) {
    return beforeEncode;
  } // Combine IV, salt, and ciphertext and encode as base64
  const encryptedMessage = CryptoES.enc.Base64.stringify(
    CryptoES.enc.Hex.parse(beforeEncode)
  );

  return encryptedMessage;
}

function decryptMessage(encryptedMessage: string, passphrase: string) {
  // Decode the base64-encoded input
  const _encryptedBytes = Buffer.from(encryptedMessage, "base64");
  //   const _encryptedBytes = CryptoES.enc.Base64.parse(encryptedMessage);

  // Extract salt and IV
  const salt = _encryptedBytes.slice(0, 8); // 8 bytes = 2 words
  const iv = _encryptedBytes.slice(8, 8 + 16); // 16 bytes = 4 words
  console.log("encryptedBytes", _encryptedBytes);
  console.log("salt", salt);
  console.log("iv", iv);
  const key = deriveKeyFromPassphrase(passphrase, salt, 32, 100000);
  console.log("key", wordArrayToUint8Array(key));

  //   // Create an AES cipher object with CBC mode
  //   const cipher = CryptoES.AES.algo.CBC.createDecryptor(key, {
  //     iv: CryptoES.lib.WordArray.create(iv),
  //   });

  //   // Decrypt and unpad the message
  //   const decryptedBytes = cipher.process(
  //     CryptoES.lib.WordArray.create(_encryptedBytes.words.slice(6))
  //   );
  //   cipher.finalize();
  //   const unpaddedBytes = CryptoES.pad.Pkcs7.unpad(decryptedBytes);

  //   // Convert the decrypted bytes to a string
  //   const decryptedMessage = CryptoES.enc.Utf8.stringify(unpaddedBytes);

  //   return decryptedMessage;
  // Create a decrypted object
  const decrypted = CryptoES.AES.decrypt("your-encrypted-message-here", key, {
    iv: iv,
    mode: CryptoES.mode.CBC,
    padding: CryptoES.pad.Pkcs7,
  });
}

const message = "Hello World!";
const passphrase = "secret";

const encryptedMessage = encodePayload({ api_key: 'jeowjeowjeo wjeow joejw oiejwoi ejiowje oijw oi',
api_secret: 'jewojeow jeowj eojwoie jwoiej oiwje iowjoie jwioj wioj' }, passphrase);
// const encryptedMessage = encryptMessage(message, passphrase);
// const messageToDecrypt =
//   "2fleaNdsqaG+iYr4zF7WM6DDppE0zV9HRhh5vPnqDlHJFa+krXfrcA==";
console.log("Encrypted message:", encryptedMessage);
// const decryptedMessage = decryptMessage(messageToDecrypt, passphrase);
// console.log("Decrypted message:", decryptedMessage);
