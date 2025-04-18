const crypto = require('crypto');

// Configuration
const saltLength = 16;
const hashLength = 64;
const iterations = 10000;
const digest = 'sha512';
const separator = '$';

async function hash(password, rounds = 10) {
    if (typeof password !== 'string') {
        throw new Error('Password must be a string');
    }
    
    // Generate random salt
    const salt = crypto.randomBytes(saltLength).toString('hex');
    
    // Hash the password
    const derivedKey = await new Promise((resolve, reject) => {
        crypto.pbkdf2(
            password, 
            salt, 
            iterations * rounds, 
            hashLength, 
            digest, 
            (err, derivedKey) => {
                if (err) reject(err);
                resolve(derivedKey.toString('hex'));
            }
        );
    });
    
    // Format: algorithm$rounds$salt$hash
    return `pbkdf2$${rounds}$${salt}$${derivedKey}`;
}

async function compare(password, hashedPassword) {
    if (typeof password !== 'string' || typeof hashedPassword !== 'string') {
        return false;
    }
    
    // Parse the stored hash
    const parts = hashedPassword.split(separator);
    if (parts.length !== 4 || parts[0] !== 'pbkdf2') {
        return false;
    }
    
    const rounds = parseInt(parts[1]);
    const salt = parts[2];
    const storedHash = parts[3];
    
    // Hash the incoming password with the same parameters
    const derivedKey = await new Promise((resolve, reject) => {
        crypto.pbkdf2(
            password, 
            salt, 
            iterations * rounds, 
            hashLength, 
            digest, 
            (err, derivedKey) => {
                if (err) reject(err);
                resolve(derivedKey.toString('hex'));
            }
        );
    });
    
    // Constant-time comparison to prevent timing attacks
    return crypto.timingSafeEqual(
        Buffer.from(derivedKey, 'hex'),
        Buffer.from(storedHash, 'hex')
    );
}

module.exports = {
    hash,
    compare
};