# secure-password-hash

A secure password hashing library using PBKDF2 (Password-Based Key Derivation Function 2). This library provides a simple and secure way to hash passwords and verify them later.

## Features

- Secure password hashing using PBKDF2
- Configurable rounds for adjusting computational intensity
- Constant-time comparison to prevent timing attacks
- Promise-based API
- Zero dependencies
- Built on Node.js crypto module

## Installation

```bash
npm install secure-password-hash