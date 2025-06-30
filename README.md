# Quantum Vault
## Verification & Encryption tool

## Features
* **Generate** 3168‑byte secret key (`secretKey.qkey`) & 1568-byte public key (`publicKey.qkey`) for ML-KEM-1024 post-quantum key encapsulation algorithm.
* **Encrypt** client-side arbitrary files using hybrid cryptography. In this approach, the ML-KEM-1024 securely negotiates a symmetric key between the sides, which is then used by AES-256-GCM to directly encrypt the file data.
* **Decrypt** `.qenc` containers created by this tool.
* **Split** `.qenc` cryptocontainers into multiple shards. You can set the required minimum number of shares (threshold) required for subsequent recovery of the secret. If the number of shares is less than this, no information about the original secret can be retrieved.
* **Restore** a cryptocontainer from a sufficient number of shards, according to a given threshold.
* **Verifies** file integrity using SHA3-512 hash sum and provides process logs to track operations.
* All cryptographic operations are performed directly in the client's browser, ensuring the confidentiality of user data.

------------

* Lattice-based key encapsulation mechanism, defined in [FIPS-203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf). This algorithm, like other post-quantum algorithms, is designed to be resistant to attacks by quantum computers that could potentially break modern cryptosystems based on factorisation of large numbers or discrete logarithm, such as RSA and ECC. The ML-KEM-1024 provides Category 5 security level (roughly equivalent to AES-256) according to NIST guidelines.
* Using audited libraries for hashing and secret-sharing: `noble-hashes` was independently audited by Cure53, and `shamir-secret-sharing` was audited by Cure53 and Zellic. The `noble-post-quantum` library has not been independently audited at this time.
* Using SHA3-512 for hash sums is in line with post-quantum security recommendations, as quantum computers can reduce hash cracking time from 2^n to 2^n/2 operations. Australian ASD prohibits SHA256 and similar hashes after 2030.
* There is no protection in JavaScript implementations of cryptographic algorithms against side-channel attacks. This is due to the way JIT compilers and rubbish collectors work in JavaScript environments, which makes achieving true runtime constancy extremely difficult. If an attacker can access application memory, they can potentially extract sensitive information.
* ML-KEM (Key Encapsulation Mechanism) does not check who sent the ciphertext. If you decrypt it with the wrong public key, it will simply return a different shared secret, not an error.
* Shamir's algorithm (SSS) provides information-theoretic security, which means that if there are less than a threshold number of shares, no information about the original secret can be obtained, regardless of computational power. Users need to independently ensure the reliability of storing each share.

## Development
```bash
npm install
npm run dev
```

## Build & Deploy to GitHub Pages
```bash
npm run deploy
```

## License

This project is distributed under the terms of the GNU General Public License v3.0. See the `LICENSE` file for the full text.

### Third‑party software licensed under other licenses

Browser encryption/decryption tool libraries:
* SHA3-512 for hashing [noble-hashes](https://github.com/paulmillr/noble-hashes);
* ML-KEM-1024 for post-quantum key encapsulation used in combination with AES-256-GCM for symmetric file encryption [noble-post-quantum](https://github.com/paulmillr/noble-post-quantum);
* Shamir's secret sharing algorithm for splitting [shamir-secret-sharing](https://github.com/privy-io/shamir-secret-sharing).

The application incorporates the following dependencies that are released under the permissive MIT License and Apache License 2.0.

| Library               | Version | Copyright holder | Upstream repository                               |
| --------------------- | ------- | ---------------- | ------------------------------------------------- |
| shamir-secret-sharing | 0.0.3   | Privy            | https://github.com/privy-io/shamir-secret-sharing |
| noble-post-quantum    | 0.4.1   | Paul Miller      | https://github.com/paulmillr/noble-post-quantum   |
| noble-hashes          | 1.8.0   | Paul Miller      | https://github.com/paulmillr/noble-hashes         |
