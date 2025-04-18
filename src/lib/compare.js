const crypto = require('crypto');
const {
    hashLength,
    iterations,
    digest,
    separator
} = require('./constants');

async function compare(password, hashedPassword) {
    if (typeof password !== 'string' || typeof hashedPassword !== 'string') {
        return false;
    }
    
    const parts = hashedPassword.split(separator);
    if (parts.length !== 4 || parts[0] !== 'pbkdf2') {
        return false;
    }
    
    const rounds = parseInt(parts[1]);
    const salt = parts[2];
    const storedHash = parts[3];
    
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
    
    return crypto.timingSafeEqual(
        Buffer.from(derivedKey, 'hex'),
        Buffer.from(storedHash, 'hex')
    );
}

module.exports = compare;