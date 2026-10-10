// app.js
// Main UI Controller and Event Binding for One Encryption And Data Protection

import { CryptoEngine } from './crypto-engine.js';
import { RSAVisualizer } from './rsa-visualizer.js';

// Initialize Engines
const cryptoEngine = new CryptoEngine();
const rsaVisualizer = new RSAVisualizer();

// Application State
const state = {
  activeKeyPair: null,
  activeKeyStrength: 2048,
  selectedFileToEncrypt: null,
  encryptedFilePackage: null,
  selectedFileToDecrypt: null,
  decryptedFileResult: null,
};

// DOM Elements Cache
const DOM = {
  // Tabs
  tabButtons: document.querySelectorAll('.tab-btn'),
  tabContents: document.querySelectorAll('.tab-content'),

  // Keygen
  btnGenerate: document.getElementById('btn-generate-keys'),
  btnGenerateText: document.getElementById('btn-generate-text'),
  btnLoadDemo: document.getElementById('btn-load-demo-keys'),
  radioKey2048: document.getElementById('radio-key-2048'),
  radioKey4096: document.getElementById('radio-key-4096'),
  radioLabel2048: document.getElementById('radio-label-2048'),
  radioLabel4096: document.getElementById('radio-label-4096'),
  keygenTimerBadge: document.getElementById('keygen-timer-badge'),
  statKeyStrength: document.getElementById('stat-key-strength'),

  // Key Displays
  publicKeyDisplay: document.getElementById('public-key-display'),
  privateKeyDisplay: document.getElementById('private-key-display'),
  publicKeyFp: document.getElementById('public-key-fp'),
  btnCopyPublic: document.getElementById('btn-copy-public'),
  btnDownloadPublic: document.getElementById('btn-download-public'),
  btnCopyPrivate: document.getElementById('btn-copy-private'),
  btnDownloadPrivate: document.getElementById('btn-download-private'),
  btnToggleMaskPrivate: document.getElementById('btn-toggle-mask-private'),

  // Text Encrypt / Decrypt
  plainTextInput: document.getElementById('plaintext-input'),
  plainTextCharCount: document.getElementById('plaintext-char-count'),
  btnEncryptText: document.getElementById('btn-encrypt-text'),
  cipherTextOutput: document.getElementById('ciphertext-output'),
  encStatSize: document.getElementById('enc-stat-size'),
  encStatTime: document.getElementById('enc-stat-time'),
  btnCopyCipher: document.getElementById('btn-copy-cipher'),
  btnSendToDecrypt: document.getElementById('btn-send-to-decrypt'),

  cipherTextInput: document.getElementById('ciphertext-input'),
  btnDecryptText: document.getElementById('btn-decrypt-text'),
  decryptedOutput: document.getElementById('decrypted-output'),
  decStatStatus: document.getElementById('dec-stat-status'),
  decStatTime: document.getElementById('dec-stat-time'),
  btnCopyDecrypted: document.getElementById('btn-copy-decrypted'),
  presetChips: document.querySelectorAll('.preset-chip'),

  // File Vault
  encFileDropzone: document.getElementById('encrypt-file-dropzone'),
  encFileInput: document.getElementById('encrypt-file-input'),
  encFileInfo: document.getElementById('encrypt-file-info'),
  encFilename: document.getElementById('enc-filename'),
  encFilesize: document.getElementById('enc-filesize'),
  btnProcessEncryptFile: document.getElementById('btn-process-encrypt-file'),
  encResultCard: document.getElementById('encrypt-result-card'),
  encProtectedName: document.getElementById('enc-protected-name'),
  btnDownloadEncryptedFile: document.getElementById('btn-download-encrypted-file'),

  decFileDropzone: document.getElementById('decrypt-file-dropzone'),
  decFileInput: document.getElementById('decrypt-file-input'),
  decFileInfo: document.getElementById('decrypt-file-info'),
  decFilename: document.getElementById('dec-filename'),
  decFilesize: document.getElementById('dec-filesize'),
  btnProcessDecryptFile: document.getElementById('btn-process-decrypt-file'),
  decResultCard: document.getElementById('decrypt-result-card'),
  decRestoredName: document.getElementById('dec-restored-name'),
  btnDownloadRestoredFile: document.getElementById('btn-download-restored-file'),

  // Math Visualizer
  mathPrimeP: document.getElementById('math-prime-p'),
  mathPrimeQ: document.getElementById('math-prime-q'),
  mathInputText: document.getElementById('math-input-text'),
  btnCalculateMath: document.getElementById('btn-calculate-math'),
  btnMathPreset1: document.getElementById('btn-math-preset-1'),
  btnMathPreset2: document.getElementById('btn-math-preset-2'),
  btnMathPreset3: document.getElementById('btn-math-preset-3'),
  mathValP: document.getElementById('math-val-p'),
  mathValQ: document.getElementById('math-val-q'),
  mathValN: document.getElementById('math-val-n'),
  mathValP1: document.getElementById('math-val-p1'),
  mathValQ1: document.getElementById('math-val-q1'),
  mathValPhi: document.getElementById('math-val-phi'),
  mathValE: document.getElementById('math-val-e'),
  mathValD: document.getElementById('math-val-d'),
  mathPkE: document.getElementById('math-pk-e'),
  mathPkN: document.getElementById('math-pk-n'),
  mathSkD: document.getElementById('math-sk-d'),
  mathSkN: document.getElementById('math-sk-n'),
  mathTableBody: document.getElementById('math-table-body'),

  // Toasts
  toastContainer: document.getElementById('toast-container'),
};

// ----------------------------------------------------------------
// Toast Notification Helper
// ----------------------------------------------------------------
function showToast(message, type = 'success') {
  const toast = document.createElement('div');
  toast.className = `toast ${type === 'error' ? 'toast-error' : ''}`;

  const iconSvg = type === 'error'
    ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#f43f5e" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`
    : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#34d399" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`;

  toast.innerHTML = `${iconSvg}<span>${message}</span>`;
  DOM.toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(20px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// ----------------------------------------------------------------
// Tab Switching
// ----------------------------------------------------------------
DOM.tabButtons.forEach(btn => {
  btn.addEventListener('click', () => {
    const targetTabId = btn.getAttribute('data-tab');

    DOM.tabButtons.forEach(b => b.classList.remove('active'));
    DOM.tabContents.forEach(c => c.classList.remove('active'));

    btn.classList.add('active');
    const targetPanel = document.getElementById(targetTabId);
    if (targetPanel) {
      targetPanel.classList.add('active');
    }
  });
});

// ----------------------------------------------------------------
// Radio Selection for Key Size
// ----------------------------------------------------------------
function updateKeySizeSelection(size) {
  state.activeKeyStrength = size;
  if (size === 2048) {
    DOM.radioKey2048.checked = true;
    DOM.radioLabel2048.classList.add('selected');
    DOM.radioLabel4096.classList.remove('selected');
  } else {
    DOM.radioKey4096.checked = true;
    DOM.radioLabel4096.classList.add('selected');
    DOM.radioLabel2048.classList.remove('selected');
  }
}

DOM.radioLabel2048.addEventListener('click', () => updateKeySizeSelection(2048));
DOM.radioLabel4096.addEventListener('click', () => updateKeySizeSelection(4096));

// ----------------------------------------------------------------
// Key Generation Action
// ----------------------------------------------------------------
async function handleGenerateKeys() {
  const modulus = state.activeKeyStrength;
  DOM.btnGenerate.disabled = true;
  DOM.btnGenerateText.textContent = `Generating ${modulus}-bit RSA Key Pair...`;
  DOM.keygenTimerBadge.textContent = 'Computing entropy...';

  try {
    const keyData = await cryptoEngine.generateRSAKeyPair(modulus);
    state.activeKeyPair = keyData;

    DOM.publicKeyDisplay.value = keyData.publicKeyPEM;
    DOM.privateKeyDisplay.value = keyData.privateKeyPEM;
    DOM.publicKeyFp.textContent = keyData.fingerprint;
    DOM.statKeyStrength.textContent = `${modulus}-bit RSA`;
    DOM.keygenTimerBadge.textContent = `Generated in ${keyData.durationMs} ms`;

    showToast(`Successfully generated ${modulus}-bit RSA Key Pair in ${keyData.durationMs}ms`);
  } catch (err) {
    console.error('Key generation error:', err);
    showToast(`Failed to generate keys: ${err.message}`, 'error');
  } finally {
    DOM.btnGenerate.disabled = false;
    DOM.btnGenerateText.textContent = 'Generate New RSA Key Pair';
  }
}

DOM.btnGenerate.addEventListener('click', handleGenerateKeys);
DOM.btnLoadDemo.addEventListener('click', handleGenerateKeys);

// ----------------------------------------------------------------
// Key Display Utility Actions (Copy, Download, Mask)
// ----------------------------------------------------------------
DOM.btnCopyPublic.addEventListener('click', () => {
  if (!DOM.publicKeyDisplay.value) return showToast('No public key to copy', 'error');
  navigator.clipboard.writeText(DOM.publicKeyDisplay.value);
  showToast('Public key copied to clipboard');
});

DOM.btnDownloadPublic.addEventListener('click', () => {
  if (!DOM.publicKeyDisplay.value) return showToast('No public key to download', 'error');
  downloadBlob(DOM.publicKeyDisplay.value, 'rsa_public_key.pub', 'text/plain');
  showToast('Downloaded rsa_public_key.pub');
});

DOM.btnCopyPrivate.addEventListener('click', () => {
  if (!DOM.privateKeyDisplay.value) return showToast('No private key to copy', 'error');
  navigator.clipboard.writeText(DOM.privateKeyDisplay.value);
  showToast('Private key copied to clipboard');
});

DOM.btnDownloadPrivate.addEventListener('click', () => {
  if (!DOM.privateKeyDisplay.value) return showToast('No private key to download', 'error');
  downloadBlob(DOM.privateKeyDisplay.value, 'rsa_private_key.pem', 'text/plain');
  showToast('Downloaded rsa_private_key.pem');
});

DOM.btnToggleMaskPrivate.addEventListener('click', () => {
  DOM.privateKeyDisplay.classList.toggle('private-masked');
  showToast('Toggled private key visual mask');
});

function downloadBlob(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ----------------------------------------------------------------
// Text Encryption & Decryption
// ----------------------------------------------------------------
DOM.plainTextInput.addEventListener('input', () => {
  DOM.plainTextCharCount.textContent = `${DOM.plainTextInput.value.length} characters`;
});

// Sample Presets
const SAMPLE_PRESETS = {
  cred: "DB_HOST=cluster-vault.internal.net\nDB_PASS=AES256_Kms_x8849204_Key\nAPI_SECRET=sec_9948293f0b83e491290",
  med: "PATIENT_ID: #882940\nDIAGNOSIS: Acute Respiratory Tract Infiltration\nVITALS: BP 120/80 | SpO2 98% | HR 72bpm\nCONFIDENTIAL CLINICAL RECORD",
  fin: "SWIFT_TXN_ID: 9948210385\nSENDER_IBAN: GB82WEST12345698765432\nAMOUNT: $250,000.00 USD\nSETTLEMENT: INSTANT FEDWIRE"
};

DOM.presetChips.forEach(chip => {
  chip.addEventListener('click', () => {
    const presetKey = chip.getAttribute('data-preset');
    if (SAMPLE_PRESETS[presetKey]) {
      DOM.plainTextInput.value = SAMPLE_PRESETS[presetKey];
      DOM.plainTextCharCount.textContent = `${DOM.plainTextInput.value.length} characters`;
      showToast(`Loaded preset into plain text input`);
    }
  });
});

DOM.btnEncryptText.addEventListener('click', async () => {
  const text = DOM.plainTextInput.value.trim();
  if (!text) {
    return showToast('Please enter text to encrypt', 'error');
  }

  let publicKey;
  try {
    if (state.activeKeyPair && state.activeKeyPair.keyPair.publicKey) {
      publicKey = state.activeKeyPair.keyPair.publicKey;
    } else if (DOM.publicKeyDisplay.value.trim()) {
      publicKey = await cryptoEngine.importPublicKeyFromPEM(DOM.publicKeyDisplay.value.trim());
    } else {
      return showToast('No active public key. Generate or provide one first.', 'error');
    }

    DOM.btnEncryptText.disabled = true;
    const result = await cryptoEngine.encryptTextRSA(text, publicKey);

    DOM.cipherTextOutput.value = result.cipherBase64;
    DOM.encStatSize.textContent = `Cipher size: ${result.cipherBytes} bytes (Plain: ${result.plainBytes} B)`;
    DOM.encStatTime.textContent = `Execution: ${result.durationMs} ms`;

    showToast(`Message encrypted via RSA-OAEP (${result.durationMs}ms)`);
  } catch (err) {
    console.error('Encryption error:', err);
    showToast(`Encryption failed: ${err.message}`, 'error');
  } finally {
    DOM.btnEncryptText.disabled = false;
  }
});

DOM.btnCopyCipher.addEventListener('click', () => {
  if (!DOM.cipherTextOutput.value) return showToast('No ciphertext to copy', 'error');
  navigator.clipboard.writeText(DOM.cipherTextOutput.value);
  showToast('Ciphertext copied to clipboard');
});

DOM.btnSendToDecrypt.addEventListener('click', () => {
  if (!DOM.cipherTextOutput.value) return showToast('No ciphertext generated yet', 'error');
  DOM.cipherTextInput.value = DOM.cipherTextOutput.value;
  DOM.cipherTextInput.scrollIntoView({ behavior: 'smooth' });
  showToast('Ciphertext transferred to decryptor');
});

DOM.btnDecryptText.addEventListener('click', async () => {
  const cipher = DOM.cipherTextInput.value.trim();
  if (!cipher) {
    return showToast('Please enter ciphertext to decrypt', 'error');
  }

  let privateKey;
  try {
    if (state.activeKeyPair && state.activeKeyPair.keyPair.privateKey) {
      privateKey = state.activeKeyPair.keyPair.privateKey;
    } else if (DOM.privateKeyDisplay.value.trim()) {
      privateKey = await cryptoEngine.importPrivateKeyFromPEM(DOM.privateKeyDisplay.value.trim());
    } else {
      return showToast('No active private key. Generate or provide one first.', 'error');
    }

    DOM.btnDecryptText.disabled = true;
    const result = await cryptoEngine.decryptTextRSA(cipher, privateKey);

    DOM.decryptedOutput.value = result.plainText;
    DOM.decStatStatus.textContent = `Status: Decrypted successfully (${result.recoveredBytes} bytes)`;
    DOM.decStatTime.textContent = `Execution: ${result.durationMs} ms`;

    showToast(`Decryption successful in ${result.durationMs}ms`);
  } catch (err) {
    console.error('Decryption error:', err);
    DOM.decStatStatus.textContent = 'Status: Decryption failed (Key mismatch or corrupted cipher)';
    showToast(`Decryption failed: Private key cannot decrypt this ciphertext`, 'error');
  } finally {
    DOM.btnDecryptText.disabled = false;
  }
});

DOM.btnCopyDecrypted.addEventListener('click', () => {
  if (!DOM.decryptedOutput.value) return showToast('No decrypted text to copy', 'error');
  navigator.clipboard.writeText(DOM.decryptedOutput.value);
  showToast('Plaintext copied to clipboard');
});

// ----------------------------------------------------------------
// File Vault (Hybrid RSA-OAEP + AES-GCM)
// ----------------------------------------------------------------
function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Encrypt File Dropzone Setup
DOM.encFileDropzone.addEventListener('click', () => DOM.encFileInput.click());
DOM.encFileDropzone.addEventListener('dragover', (e) => {
  e.preventDefault();
  DOM.encFileDropzone.classList.add('dragover');
});
DOM.encFileDropzone.addEventListener('dragleave', () => DOM.encFileDropzone.classList.remove('dragover'));
DOM.encFileDropzone.addEventListener('drop', (e) => {
  e.preventDefault();
  DOM.encFileDropzone.classList.remove('dragover');
  if (e.dataTransfer.files && e.dataTransfer.files[0]) {
    handleSelectFileToEncrypt(e.dataTransfer.files[0]);
  }
});
DOM.encFileInput.addEventListener('change', (e) => {
  if (e.target.files && e.target.files[0]) {
    handleSelectFileToEncrypt(e.target.files[0]);
  }
});

function handleSelectFileToEncrypt(file) {
  state.selectedFileToEncrypt = file;
  DOM.encFilename.textContent = file.name;
  DOM.encFilesize.textContent = formatBytes(file.size);
  DOM.encFileInfo.style.display = 'flex';
  DOM.encResultCard.style.display = 'none';
}

DOM.btnProcessEncryptFile.addEventListener('click', async () => {
  if (!state.selectedFileToEncrypt) return showToast('No file selected', 'error');

  let publicKey;
  try {
    if (state.activeKeyPair && state.activeKeyPair.keyPair.publicKey) {
      publicKey = state.activeKeyPair.keyPair.publicKey;
    } else if (DOM.publicKeyDisplay.value.trim()) {
      publicKey = await cryptoEngine.importPublicKeyFromPEM(DOM.publicKeyDisplay.value.trim());
    } else {
      return showToast('No active public key. Please generate keys first.', 'error');
    }

    DOM.btnProcessEncryptFile.disabled = true;
    DOM.btnProcessEncryptFile.textContent = 'Encrypting...';

    const fileBuffer = await state.selectedFileToEncrypt.arrayBuffer();
    const result = await cryptoEngine.encryptFileHybrid(
      fileBuffer,
      state.selectedFileToEncrypt.name,
      state.selectedFileToEncrypt.type,
      publicKey
    );

    state.encryptedFilePackage = result;
    DOM.encProtectedName.textContent = `${result.fileName}.onedata (${formatBytes(result.protectedSize)})`;
    DOM.encResultCard.style.display = 'block';

    showToast(`File encrypted into .onedata package (${result.durationMs}ms)`);
  } catch (err) {
    console.error('File encryption error:', err);
    showToast(`File encryption error: ${err.message}`, 'error');
  } finally {
    DOM.btnProcessEncryptFile.disabled = false;
    DOM.btnProcessEncryptFile.textContent = 'Encrypt File';
  }
});

DOM.btnDownloadEncryptedFile.addEventListener('click', () => {
  if (!state.encryptedFilePackage) return showToast('No encrypted file package available', 'error');
  const blob = new Blob([state.encryptedFilePackage.containerBuffer], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${state.encryptedFilePackage.fileName}.onedata`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast('Encrypted file downloaded');
});

// Decrypt File Dropzone Setup
DOM.decFileDropzone.addEventListener('click', () => DOM.decFileInput.click());
DOM.decFileDropzone.addEventListener('dragover', (e) => {
  e.preventDefault();
  DOM.decFileDropzone.classList.add('dragover');
});
DOM.decFileDropzone.addEventListener('dragleave', () => DOM.decFileDropzone.classList.remove('dragover'));
DOM.decFileDropzone.addEventListener('drop', (e) => {
  e.preventDefault();
  DOM.decFileDropzone.classList.remove('dragover');
  if (e.dataTransfer.files && e.dataTransfer.files[0]) {
    handleSelectFileToDecrypt(e.dataTransfer.files[0]);
  }
});
DOM.decFileInput.addEventListener('change', (e) => {
  if (e.target.files && e.target.files[0]) {
    handleSelectFileToDecrypt(e.target.files[0]);
  }
});

function handleSelectFileToDecrypt(file) {
  state.selectedFileToDecrypt = file;
  DOM.decFilename.textContent = file.name;
  DOM.decFilesize.textContent = formatBytes(file.size);
  DOM.decFileInfo.style.display = 'flex';
  DOM.decResultCard.style.display = 'none';
}

DOM.btnProcessDecryptFile.addEventListener('click', async () => {
  if (!state.selectedFileToDecrypt) return showToast('No .onedata file selected', 'error');

  let privateKey;
  try {
    if (state.activeKeyPair && state.activeKeyPair.keyPair.privateKey) {
      privateKey = state.activeKeyPair.keyPair.privateKey;
    } else if (DOM.privateKeyDisplay.value.trim()) {
      privateKey = await cryptoEngine.importPrivateKeyFromPEM(DOM.privateKeyDisplay.value.trim());
    } else {
      return showToast('No active private key. Please generate keys first.', 'error');
    }

    DOM.btnProcessDecryptFile.disabled = true;
    DOM.btnProcessDecryptFile.textContent = 'Decrypting...';

    const containerBuffer = await state.selectedFileToDecrypt.arrayBuffer();
    const result = await cryptoEngine.decryptFileHybrid(containerBuffer, privateKey);

    state.decryptedFileResult = result;
    DOM.decRestoredName.textContent = `${result.metadata.name} (${formatBytes(result.decryptedBuffer.byteLength)})`;
    DOM.decResultCard.style.display = 'block';

    showToast(`File successfully decrypted & verified (${result.durationMs}ms)`);
  } catch (err) {
    console.error('File decryption error:', err);
    showToast(`File decryption failed: ${err.message}`, 'error');
  } finally {
    DOM.btnProcessDecryptFile.disabled = false;
    DOM.btnProcessDecryptFile.textContent = 'Decrypt File';
  }
});

DOM.btnDownloadRestoredFile.addEventListener('click', () => {
  if (!state.decryptedFileResult) return showToast('No decrypted file to download', 'error');
  const { decryptedBuffer, metadata } = state.decryptedFileResult;
  const blob = new Blob([decryptedBuffer], { type: metadata.type || 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = metadata.name || 'decrypted_file';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast(`Downloaded original file: ${metadata.name}`);
});

// ----------------------------------------------------------------
// RSA Algorithm Visualizer & Mathematical Engine
// ----------------------------------------------------------------
function runMathVisualizer() {
  try {
    const p = DOM.mathPrimeP.value;
    const q = DOM.mathPrimeQ.value;
    const text = DOM.mathInputText.value || 'SAFE';

    const params = rsaVisualizer.calculateKeyParams(p, q);

    DOM.mathValP.textContent = params.p.toString();
    DOM.mathValQ.textContent = params.q.toString();
    DOM.mathValN.textContent = params.n.toString();
    DOM.mathValP1.textContent = (params.p - 1n).toString();
    DOM.mathValQ1.textContent = (params.q - 1n).toString();
    DOM.mathValPhi.textContent = params.phi.toString();
    DOM.mathValE.textContent = params.e.toString();
    DOM.mathValD.textContent = params.d.toString();

    DOM.mathPkE.textContent = params.e.toString();
    DOM.mathPkN.textContent = params.n.toString();
    DOM.mathSkD.textContent = params.d.toString();
    DOM.mathSkN.textContent = params.n.toString();

    const encResult = rsaVisualizer.encryptMessage(text, params);
    const decResult = rsaVisualizer.decryptMessage(encResult.cipherString, params);

    // Build Table Rows
    DOM.mathTableBody.innerHTML = '';
    encResult.steps.forEach((step, idx) => {
      const decStep = decResult.steps[idx];
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong style="color: var(--accent-cyan); font-size: 0.95rem;">${step.char}</strong></td>
        <td><code>${step.m}</code></td>
        <td><code>${step.formula}</code></td>
        <td><strong style="color: #c084fc;">${step.c}</strong></td>
        <td><code>${decStep ? decStep.formula : ''}</code></td>
        <td><strong style="color: #34d399; font-size: 0.95rem;">${decStep ? decStep.char : ''}</strong></td>
      `;
      DOM.mathTableBody.appendChild(tr);
    });

  } catch (err) {
    console.error('Math visualizer error:', err);
    showToast(err.message, 'error');
  }
}

DOM.btnCalculateMath.addEventListener('click', runMathVisualizer);

DOM.btnMathPreset1.addEventListener('click', () => {
  DOM.mathPrimeP.value = '61';
  DOM.mathPrimeQ.value = '53';
  DOM.mathInputText.value = 'SAFE';
  runMathVisualizer();
});

DOM.btnMathPreset2.addEventListener('click', () => {
  DOM.mathPrimeP.value = '151';
  DOM.mathPrimeQ.value = '211';
  DOM.mathInputText.value = 'CRYPTO';
  runMathVisualizer();
});

DOM.btnMathPreset3.addEventListener('click', () => {
  DOM.mathPrimeP.value = '1009';
  DOM.mathPrimeQ.value = '1013';
  DOM.mathInputText.value = 'ANTIGRAVITY';
  runMathVisualizer();
});

// ----------------------------------------------------------------
// Application Startup
// ----------------------------------------------------------------
window.addEventListener('DOMContentLoaded', async () => {
  // Check Web Crypto API
  if (!cryptoEngine.isSupported()) {
    showToast('Notice: Web Cryptography API requires modern browser or secure context (localhost/HTTPS).', 'error');
  }

  // Pre-generate standard 2048-bit keys on first launch for instant testing
  await handleGenerateKeys();

  // Initialize Math Visualizer with default primes
  runMathVisualizer();
});
