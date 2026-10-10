// rsa-visualizer.js
// Interactive Mathematical Engine & Step-by-Step RSA Visualizer
// Explains and calculates raw RSA using JavaScript BigInt arithmetic

export class RSAVisualizer {
  constructor() {
    // Curated prime candidates for educational visualization
    this.presetPrimes = [
      { p: 61n, q: 53n, desc: "Classic Textbook Example (Small)" },
      { p: 151n, q: 211n, desc: "Intermediate Primes" },
      { p: 1009n, q: 1013n, desc: "Advanced 4-Digit Primes" },
      { p: 10007n, q: 10009n, desc: "5-Digit Demonstration Primes" }
    ];
  }

  // Greatest Common Divisor
  gcd(a, b) {
    while (b !== 0n) {
      const temp = b;
      b = a % b;
      a = temp;
    }
    return a;
  }

  // Extended Euclidean Algorithm to calculate modular inverse: (e * d) % phi === 1
  modInverse(e, phi) {
    let m0 = phi;
    let y = 0n;
    let x = 1n;

    if (phi === 1n) return 0n;

    let a = e;
    let b = phi;

    while (a > 1n) {
      if (b === 0n) throw new Error("No modular inverse exists");
      const q = a / b;
      let t = b;

      b = a % b;
      a = t;
      t = y;

      y = x - q * y;
      x = t;
    }

    if (x < 0n) {
      x = x + m0;
    }

    return x;
  }

  // Modular Exponentiation: (base^exp) % mod
  modPow(base, exp, mod) {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
      if (exp % 2n === 1n) {
        result = (result * base) % mod;
      }
      exp = exp / 2n;
      base = (base * base) % mod;
    }
    return result;
  }

  // Check if a BigInt number is prime
  isPrime(n) {
    if (n <= 1n) return false;
    if (n <= 3n) return true;
    if (n % 2n === 0n || n % 3n === 0n) return false;
    for (let i = 5n; i * i <= n; i += 6n) {
      if (n % i === 0n || n % (i + 2n) === 0n) return false;
    }
    return true;
  }

  // Generate an educational RSA key set from p and q
  calculateKeyParams(pVal, qVal, chosenE = 65537n) {
    const p = BigInt(pVal);
    const q = BigInt(qVal);

    if (!this.isPrime(p)) {
      throw new Error(`p (${p}) is not a prime number!`);
    }
    if (!this.isPrime(q)) {
      throw new Error(`q (${q}) is not a prime number!`);
    }
    if (p === q) {
      throw new Error("p and q must be distinct prime numbers!");
    }

    // 1. Compute modulus n = p * q
    const n = p * q;

    // 2. Compute Euler's totient phi(n) = (p - 1) * (q - 1)
    const phi = (p - 1n) * (q - 1n);

    // 3. Find/verify public exponent e such that 1 < e < phi and gcd(e, phi) == 1
    let e = chosenE;
    if (e >= phi || this.gcd(e, phi) !== 1n) {
      // Find an alternate small coprime e
      const candidates = [65537n, 17n, 7n, 5n, 3n];
      let found = false;
      for (const cand of candidates) {
        if (cand < phi && this.gcd(cand, phi) === 1n) {
          e = cand;
          found = true;
          break;
        }
      }
      if (!found) {
        // Fallback search
        for (let candidate = 3n; candidate < phi; candidate += 2n) {
          if (this.gcd(candidate, phi) === 1n) {
            e = candidate;
            found = true;
            break;
          }
        }
      }
    }

    // 4. Compute private exponent d = e^-1 mod phi
    const d = this.modInverse(e, phi);

    return {
      p,
      q,
      n,
      phi,
      e,
      d,
      publicKey: { e, n },
      privateKey: { d, n }
    };
  }

  // Encrypt an educational message (ASCII character codes or integer)
  encryptMessage(message, params) {
    const { e, n } = params;
    const steps = [];

    // Process character by character
    const charCodes = [];
    const cipherCodes = [];

    for (let i = 0; i < message.length; i++) {
      const char = message[i];
      const m = BigInt(char.charCodeAt(0));

      if (m >= n) {
        throw new Error(
          `Character '${char}' (code ${m}) exceeds modulus n (${n}). Pick larger primes p and q!`
        );
      }

      const c = this.modPow(m, e, n);
      charCodes.push(m);
      cipherCodes.push(c);

      steps.push({
        char,
        m,
        formula: `${m}^${e} mod ${n}`,
        c
      });
    }

    return {
      originalText: message,
      charCodes,
      cipherCodes,
      steps,
      cipherString: cipherCodes.map(c => c.toString()).join(" ")
    };
  }

  // Decrypt an educational ciphertext array
  decryptMessage(cipherString, params) {
    const { d, n } = params;
    const cipherTokens = cipherString.trim().split(/\s+/).filter(Boolean);
    const steps = [];
    let recoveredText = "";

    for (const token of cipherTokens) {
      const c = BigInt(token);
      const m = this.modPow(c, d, n);
      const char = String.fromCharCode(Number(m));
      recoveredText += char;

      steps.push({
        c,
        formula: `${c}^${d} mod ${n}`,
        m,
        char
      });
    }

    return {
      recoveredText,
      steps
    };
  }
}
