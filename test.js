const { hash, compare } = require('./index');

async function test() {
    try {
        const password = 'mySecurePassword123';
        
        // Test hashing
        const hashed = await hash(password, 10);
        console.log('Hashed password:', hashed);
        
        // Test comparison
        const match = await compare(password, hashed);
        console.log('Password matches:', match);
        
        const wrongMatch = await compare('wrongPassword', hashed);
        console.log('Wrong password matches:', wrongMatch);
        
    } catch (err) {
        console.error('Error:', err);
    }
}

test();