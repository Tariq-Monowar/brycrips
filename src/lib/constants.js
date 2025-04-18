const saltLength = 16;
const hashLength = 64;
const iterations = 10000;
const digest = 'sha512';
const separator = '$';

module.exports = {
    saltLength,
    hashLength,
    iterations,
    digest,
    separator
};