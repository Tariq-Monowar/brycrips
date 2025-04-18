
const x = require('../src/index');
async function test() {
    try {
        const password = 'mySecurePassword123';
        
        const hashed = await x.hash(password, 10);
        console.log('Hashed password:', hashed);
        
        const match = await x.compare(password, hashed);
        console.log('Password matches:', match);
        
        const wrongMatch = await x.compare('wrongPassword', hashed);
        console.log('Wrong password matches:', wrongMatch);
        
    } catch (err) {
        console.error('Error:', err);
    }
}

test();