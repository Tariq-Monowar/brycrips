const crypto = require('crypto');
const {
    saltLength,
    hashLength,
    iterations,
    digest,
    separator
} = require('./constants');

async function hash(password, rounds = 10) {
    if (typeof password !== 'string') {
        throw new Error('Password must be a string');
    }
    
    const salt = crypto.randomBytes(saltLength).toString('hex');
    
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
    
    return `pbkdf2${separator}${rounds}${separator}${salt}${separator}${derivedKey}`;
}

module.exports = hash;