// crypto-engine.js
// Enterprise Cryptographic Engine for "One Encryption And Data Protection"
// Implements Web Cryptography API (SubtleCrypto) with RSA-OAEP & Hybrid AES-GCM

export class CryptoEngine {
  constructor() {
    this.crypto = window.crypto.subtle;
    if (!this.crypto) {
      console.error("Web Cryptography API (SubtleCrypto) is not supported or not running in a secure context.");
    }
  }

  // Check if Web Crypto is supported
  isSupported() {
    return !!(window.crypto && window.crypto.subtle);
  }

  // Generate RSA Key Pair (2048 or 4096 bit, SHA-256 hash, RSA-OAEP)
  async generateRSAKeyPair(modulusLength = 2048) {
    const startTime = performance.now();
    const keyPair = await this.crypto.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: modulusLength,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
        hash: "SHA-256",
      },
      true, // extractable
      ["encrypt", "decrypt"]
    );
    const duration = (performance.now() - startTime).toFixed(1);

    const publicKeyPEM = await this.exportPublicKeyToPEM(keyPair.publicKey);
    const privateKeyPEM = await this.exportPrivateKeyToPEM(keyPair.privateKey);
    const fingerprint = await this.computeKeyFingerprint(keyPair.publicKey);

    return {
      keyPair,
      publicKeyPEM,
      privateKeyPEM,
      fingerprint,
      modulusLength,
      durationMs: duration
    };
  }

  // Export Public Key to standard PEM format (SPKI)
  async exportPublicKeyToPEM(key) {
    const exported = await this.crypto.exportKey("spki", key);
    const base64 = this.arrayBufferToBase64(exported);
    const formatted = base64.match(/.{1,64}/g).join("\n");
    return `-----BEGIN PUBLIC KEY-----\n${formatted}\n-----END PUBLIC KEY-----`;
  }

  // Export Private Key to standard PEM format (PKCS8)
  async exportPrivateKeyToPEM(key) {
    const exported = await this.crypto.exportKey("pkcs8", key);
    const base64 = this.arrayBufferToBase64(exported);
    const formatted = base64.match(/.{1,64}/g).join("\n");
    return `-----BEGIN PRIVATE KEY-----\n${formatted}\n-----END PRIVATE KEY-----`;
  }

  // Import Public Key from PEM string
  async importPublicKeyFromPEM(pem) {
    const cleanPem = pem
      .replace(/-----BEGIN PUBLIC KEY-----/g, "")
      .replace(/-----END PUBLIC KEY-----/g, "")
      .replace(/[\r\n\s]/g, "");
    const binaryDer = this.base64ToArrayBuffer(cleanPem);
    return await this.crypto.importKey(
      "spki",
      binaryDer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      true,
      ["encrypt"]
    );
  }

  // Import Private Key from PEM string
  async importPrivateKeyFromPEM(pem) {
    const cleanPem = pem
      .replace(/-----BEGIN PRIVATE KEY-----/g, "")
      .replace(/-----END PRIVATE KEY-----/g, "")
      .replace(/[\r\n\s]/g, "");
    const binaryDer = this.base64ToArrayBuffer(cleanPem);
    return await this.crypto.importKey(
      "pkcs8",
      binaryDer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      true,
      ["decrypt"]
    );
  }

  // Compute SHA-256 fingerprint for public key verification
  async computeKeyFingerprint(publicKey) {
    const spkiBuffer = await this.crypto.exportKey("spki", publicKey);
    const hashBuffer = await this.crypto.digest("SHA-256", spkiBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join(':').toUpperCase();
  }

  // Direct RSA-OAEP Text Encryption (Base64 output)
  // Note: RSA-OAEP with SHA-256 and 2048-bit key can encrypt up to 190 bytes per block
  async encryptTextRSA(plainText, publicKey) {
    const startTime = performance.now();
    const encoder = new TextEncoder();
    const data = encoder.encode(plainText);

    // If text exceeds single RSA block limit, use chunked RSA or throw informative message
    // 2048-bit key modulus = 256 bytes. OAEP overhead (2 * hashLen + 2) = 2*32 + 2 = 66 bytes.
    // Max payload = 190 bytes.
    const maxChunkSize = 190;
    
    let encryptedBuffer;
    if (data.byteLength <= maxChunkSize) {
      encryptedBuffer = await this.crypto.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        data
      );
    } else {
      // Chunked encryption for messages exceeding single block
      const chunks = [];
      for (let i = 0; i < data.byteLength; i += maxChunkSize) {
        const chunk = data.slice(i, i + maxChunkSize);
        const encChunk = await this.crypto.encrypt({ name: "RSA-OAEP" }, publicKey, chunk);
        chunks.push(encChunk);
      }
      // Combine chunks with 4-byte length prefix per chunk
      let totalLength = chunks.reduce((acc, c) => acc + 4 + c.byteLength, 0);
      const combined = new Uint8Array(totalLength);
      let offset = 0;
      for (const c of chunks) {
        const cArr = new Uint8Array(c);
        const view = new DataView(combined.buffer);
        view.setUint32(offset, cArr.byteLength, false);
        offset += 4;
        combined.set(cArr, offset);
        offset += cArr.byteLength;
      }
      encryptedBuffer = combined.buffer;
    }

    const duration = (performance.now() - startTime).toFixed(1);
    const base64Cipher = this.arrayBufferToBase64(encryptedBuffer);

    return {
      cipherBase64: base64Cipher,
      cipherHex: this.arrayBufferToHex(encryptedBuffer),
      plainBytes: data.byteLength,
      cipherBytes: encryptedBuffer.byteLength,
      durationMs: duration
    };
  }

  // Direct RSA-OAEP Text Decryption
  async decryptTextRSA(base64Cipher, privateKey) {
    const startTime = performance.now();
    const cipherBuffer = this.base64ToArrayBuffer(base64Cipher);
    const decoder = new TextDecoder();

    let decryptedBuffer;
    // Check if it's chunked by inspecting if size > standard 256 bytes (2048 bit RSA) or structured
    const isChunked = cipherBuffer.byteLength > 512 || (cipherBuffer.byteLength > 256 && cipherBuffer.byteLength % 256 !== 0);

    if (!isChunked) {
      try {
        decryptedBuffer = await this.crypto.decrypt(
          { name: "RSA-OAEP" },
          privateKey,
          cipherBuffer
        );
      } catch (err) {
        // If single failed, try chunked logic just in case
        decryptedBuffer = await this.decryptChunkedRSA(cipherBuffer, privateKey);
      }
    } else {
      decryptedBuffer = await this.decryptChunkedRSA(cipherBuffer, privateKey);
    }

    const duration = (performance.now() - startTime).toFixed(1);
    const plainText = decoder.decode(decryptedBuffer);

    return {
      plainText,
      durationMs: duration,
      recoveredBytes: decryptedBuffer.byteLength
    };
  }

  async decryptChunkedRSA(cipherBuffer, privateKey) {
    const view = new DataView(cipherBuffer);
    let offset = 0;
    const decryptedParts = [];

    while (offset < cipherBuffer.byteLength) {
      if (offset + 4 > cipherBuffer.byteLength) break;
      const chunkLen = view.getUint32(offset, false);
      offset += 4;
      if (offset + chunkLen > cipherBuffer.byteLength) {
        throw new Error("Corrupted or malformed ciphertext chunk boundaries.");
      }
      const chunkData = cipherBuffer.slice(offset, offset + chunkLen);
      offset += chunkLen;

      const decPart = await this.crypto.decrypt({ name: "RSA-OAEP" }, privateKey, chunkData);
      decryptedParts.push(new Uint8Array(decPart));
    }

    const totalDecLen = decryptedParts.reduce((acc, p) => acc + p.byteLength, 0);
    const finalBuffer = new Uint8Array(totalDecLen);
    let curOffset = 0;
    for (const p of decryptedParts) {
      finalBuffer.set(p, curOffset);
      curOffset += p.byteLength;
    }
    return finalBuffer.buffer;
  }

  // -------------------------------------------------------------
  // Real-World Hybrid Cryptosystem: RSA-OAEP + AES-256-GCM
  // Suitable for arbitrary file sizes and large payloads
  // -------------------------------------------------------------
  async encryptFileHybrid(fileArrayBuffer, fileName, fileType, publicKey) {
    const startTime = performance.now();

    // 1. Generate an ephemeral AES-256 symmetric key
    const aesKey = await this.crypto.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    // 2. Generate a 12-byte initialization vector (IV) for AES-GCM
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    // 3. Encrypt the file payload using AES-GCM (Authenticated Encryption)
    const encryptedPayload = await this.crypto.encrypt(
      { name: "AES-GCM", iv: iv },
      aesKey,
      fileArrayBuffer
    );

    // 4. Export the raw AES key
    const rawAesKey = await this.crypto.exportKey("raw", aesKey);

    // 5. Encrypt the raw AES key using RSA-OAEP Public Key
    const encryptedAesKey = await this.crypto.encrypt(
      { name: "RSA-OAEP" },
      publicKey,
      rawAesKey
    );

    // 6. Build the encrypted container package:
    // Header format:
    // MAGIC: 8 bytes ("ONECRYPT")
    // Version: 1 byte (0x01)
    // Metadata JSON length: 2 bytes
    // Metadata JSON: UTF-8 string (fileName, fileType, originalSize, timestamp)
    // Encrypted AES Key length: 2 bytes
    // Encrypted AES Key: byte array (e.g. 256 or 512 bytes)
    // IV: 12 bytes
    // Encrypted Payload: remaining bytes
    const metadata = JSON.stringify({
      name: fileName,
      type: fileType || "application/octet-stream",
      size: fileArrayBuffer.byteLength,
      timestamp: new Date().toISOString()
    });
    const metaBytes = new TextEncoder().encode(metadata);

    const magic = new TextEncoder().encode("ONECRYPT");
    const containerSize =
      8 + // Magic
      1 + // Version
      2 + metaBytes.byteLength + // Meta len + Meta
      2 + encryptedAesKey.byteLength + // RSA-wrapped key len + wrapped key
      12 + // IV
      encryptedPayload.byteLength; // Ciphertext + GCM Auth Tag

    const container = new Uint8Array(containerSize);
    const view = new DataView(container.buffer);

    let offset = 0;
    container.set(magic, offset); offset += 8;
    view.setUint8(offset, 1); offset += 1; // v1

    view.setUint16(offset, metaBytes.byteLength, false); offset += 2;
    container.set(metaBytes, offset); offset += metaBytes.byteLength;

    view.setUint16(offset, encryptedAesKey.byteLength, false); offset += 2;
    container.set(new Uint8Array(encryptedAesKey), offset); offset += encryptedAesKey.byteLength;

    container.set(iv, offset); offset += 12;
    container.set(new Uint8Array(encryptedPayload), offset);

    const duration = (performance.now() - startTime).toFixed(1);

    return {
      containerBuffer: container.buffer,
      originalSize: fileArrayBuffer.byteLength,
      protectedSize: container.buffer.byteLength,
      durationMs: duration,
      fileName: fileName
    };
  }

  // Decrypt Protected File Container (.onedata) using RSA Private Key
  async decryptFileHybrid(containerArrayBuffer, privateKey) {
    const startTime = performance.now();
    const container = new Uint8Array(containerArrayBuffer);
    const view = new DataView(containerArrayBuffer);

    // Validate Magic bytes
    let offset = 0;
    const magicStr = new TextDecoder().decode(container.slice(0, 8));
    if (magicStr !== "ONECRYPT") {
      throw new Error("Invalid file format. Not an authentic OneCrypt protected package.");
    }
    offset += 8;

    const version = view.getUint8(offset); offset += 1;
    if (version !== 1) {
      throw new Error(`Unsupported package version: ${version}`);
    }

    // Read Metadata
    const metaLen = view.getUint16(offset, false); offset += 2;
    const metaBytes = container.slice(offset, offset + metaLen); offset += metaLen;
    const metadata = JSON.parse(new TextDecoder().decode(metaBytes));

    // Read Encrypted AES Key
    const encKeyLen = view.getUint16(offset, false); offset += 2;
    const encKeyBytes = containerArrayBuffer.slice(offset, offset + encKeyLen); offset += encKeyLen;

    // Read IV
    const iv = container.slice(offset, offset + 12); offset += 12;

    // Remaining is AES-GCM Encrypted Payload
    const encryptedPayload = containerArrayBuffer.slice(offset);

    // 1. Decrypt AES Key using RSA Private Key
    const rawAesKey = await this.crypto.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      encKeyBytes
    );

    // 2. Import raw AES key
    const aesKey = await this.crypto.importKey(
      "raw",
      rawAesKey,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    // 3. Decrypt Payload using AES-GCM
    const decryptedPayload = await this.crypto.decrypt(
      { name: "AES-GCM", iv: iv },
      aesKey,
      encryptedPayload
    );

    const duration = (performance.now() - startTime).toFixed(1);

    return {
      decryptedBuffer: decryptedPayload,
      metadata,
      durationMs: duration
    };
  }

  // -------------------------------------------------------------
  // Helper Utilities
  // -------------------------------------------------------------
  arrayBufferToBase64(buffer) {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  base64ToArrayBuffer(base64) {
    const binary = window.atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  arrayBufferToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
}
