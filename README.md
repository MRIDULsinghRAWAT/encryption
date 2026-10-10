# One Encryption And Data Protection

An enterprise-grade client-side encryption and data protection web application built with **HTML5, CSS3, and JavaScript**, implementing hardware-accelerated **RSA asymmetric cryptography** (RSA-OAEP), **hybrid AES-256-GCM data protection**, and an interactive **RSA mathematical visualizer**.

---

## 🌟 Alignment with Project Specification

| Specification Requirement | Implementation Details |
| :--- | :--- |
| **"Developed an encryption and data protection web application using HTML, CSS, and JavaScript"** | Pure vanilla web application with zero heavy build-step dependencies. Features a custom glassmorphism cybersecurity design system (`style.css`), modular ES6 architecture (`crypto-engine.js`, `rsa-visualizer.js`, `app.js`), and responsive cross-device layout. |
| **"Implemented the RSA algorithm to securely encrypt and decrypt sensitive information"** | Implements both:<br>1. **Enterprise RSA-OAEP** via the browser's native `SubtleCrypto` API for cryptographically secure 2048-bit and 4096-bit encryption/decryption.<br>2. **Educational BigInt RSA Engine** from scratch demonstrating prime selection ($p, q$), totient calculation ($\phi(n)$), coprime public exponent ($e$), modular inverse private exponent ($d$), and modular exponentiation ($C = M^e \pmod n$, $M = C^d \pmod n$). |
| **"Applied web security principles while building an interactive and user-friendly interface"** | - **Zero-Knowledge Architecture:** Cryptographic keys and plaintext never leave the browser's volatile memory.<br>- **OAEP Random Padding:** Completely eliminates deterministic textbook RSA vulnerabilities.<br>- **Hybrid Cryptosystem:** Uses RSA-OAEP key encapsulation with AES-256-GCM authenticated encryption for arbitrary file sizes without RSA byte limitations.<br>- **Storage Isolation:** Sensitive private keys are never stored in unencrypted `localStorage` to guard against XSS key harvesting. |

---

## 🚀 Key Features

### 1. 🔑 Asymmetric RSA Key Pair Manager
- Generate **2048-bit** (fast enterprise standard) or **4096-bit** (military grade) RSA key pairs.
- Standard **PEM formatted export & import** (`-----BEGIN PUBLIC KEY-----` / `-----BEGIN PRIVATE KEY-----`).
- Real-time **SHA-256 Key Fingerprinting** (`xx:xx:xx:...`) for public key authenticity verification.
- Download keys as `.pub` and `.pem` files, copy to clipboard, or toggle private key visibility mask.

### 2. 🔒 Text & Message Encryption Studio
- Encrypt plain text using active public key into clean **Base64** and **Hex** ciphertext.
- Decrypt ciphertext using active private key and recover original plain text with microsecond benchmark stats.
- One-click presets: *Database Secrets & Credentials*, *Patient Medical Diagnostics*, and *SWIFT Financial Tokens*.
- Direct "Transfer to Decryptor" routing for instant validation.

### 3. 📁 File Vault & Hybrid Data Protection
- Real-world file protection overcoming RSA payload limits using **Hybrid Cryptography**:
  - Automatically generates an ephemeral **256-bit AES-GCM symmetric key** with 96-bit IV.
  - Encrypts file payload using authenticated AES-GCM.
  - Encapsulates the AES symmetric key using **RSA-OAEP**.
  - Packs into a single authenticated `.onedata` container.
- Decrypt `.onedata` files with private key and immediately download the restored original file (preserves original filename and MIME type).

### 4. 🧠 Interactive RSA Algorithm Visualizer
- Visualizes the deep mathematics of the RSA algorithm:
  - Select prime numbers $p$ and $q$.
  - Calculates $n = p \cdot q$ and Euler's Totient $\phi(n) = (p-1)(q-1)$.
  - Calculates public exponent $e$ and modular multiplicative inverse $d \equiv e^{-1} \pmod{\phi(n)}$ using Extended Euclidean Algorithm.
  - Shows step-by-step modular exponentiation table encrypting and recovering characters.

### 5. 🛡️ Web Security Principles Dashboard
- In-depth reference detailing **Zero-Knowledge Memory Management**, **OAEP Padding Security**, **Hybrid Performance**, and **Client-Side Sandbox Isolation**.

---

## 📁 Project Structure

```
encryption/
├── index.html              # Main single-page application layout & UI
├── css/
│   └── style.css           # Modern cyber-glass design system & typography
├── js/
│   ├── crypto-engine.js    # Web Cryptography API (SubtleCrypto RSA-OAEP & Hybrid AES-GCM)
│   ├── rsa-visualizer.js   # Pure JavaScript BigInt mathematical RSA demonstration
│   └── app.js              # UI state manager, event listeners, file handling & toasts
└── README.md               # Documentation and technical reference
```

---

## 💻 How to Run Locally

Because the application uses native ES6 JavaScript modules and the browser's Web Cryptography API (`crypto.subtle`), run it via any local web server:

### Option 1: Python HTTP Server (Built-in)
```powershell
python -m http.server 8080
```
Then navigate to: `http://localhost:8080`

### Option 2: Node.js `serve` / `npx`
```powershell
npx -y serve .
```

### Option 3: VS Code Live Server
Right-click `index.html` and click **"Open with Live Server"**.

---

## 🔒 Security Specifications

- **Cryptographic Algorithms:** RSA-OAEP, AES-256-GCM, SHA-256
- **Key Sizes Supported:** 2048-bit, 4096-bit
- **Public Exponent:** $65537$ ($2^{16} + 1$, Fermat prime $F_4$)
- **Data Packaging:** Custom binary container `.onedata` with magic header verification
