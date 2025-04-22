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

#include <napi.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>
#include <cstring>

const int SALT_LENGTH = 16;
const int HASH_LENGTH = 64;
const int ITERATIONS = 10000;
const std::string SEPARATOR = "$";

std::string toHex(const unsigned char* data, int length) {
    std::ostringstream oss;
    for (int i = 0; i < length; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    return oss.str();
}

bool constantTimeCompare(const unsigned char* a, const unsigned char* b, size_t len) {
    unsigned char result = 0;
    for (size_t i = 0; i < len; ++i) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

Napi::Value HashPassword(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "String expected").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string password = info[0].As<Napi::String>().Utf8Value();
    int rounds = info.Length() > 1 && info[1].IsNumber() ? info[1].As<Napi::Number>().Int32Value() : 10;

    try {
        unsigned char salt[SALT_LENGTH];
        if (RAND_status() != 1 || !RAND_bytes(salt, sizeof(salt))) {
            throw std::runtime_error("Secure RNG failed");
        }

        std::vector<unsigned char> hash(HASH_LENGTH);
        int totalIterations = ITERATIONS * rounds;

        if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                               salt, sizeof(salt),
                               totalIterations, EVP_sha512(),
                               hash.size(), hash.data())) {
            throw std::runtime_error("PBKDF2 failed");
        }

        std::string result = "pbkdf2" + SEPARATOR + std::to_string(rounds) + SEPARATOR +
                            toHex(salt, sizeof(salt)) + SEPARATOR +
                            toHex(hash.data(), hash.size());

        return Napi::String::New(env, result);
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

Napi::Value ComparePassword(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
        Napi::TypeError::New(env, "Two strings expected").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string password = info[0].As<Napi::String>().Utf8Value();
    std::string hashedPassword = info[1].As<Napi::String>().Utf8Value();

    try {
        std::stringstream ss(hashedPassword);
        std::string segment;
        std::vector<std::string> parts;

        while (std::getline(ss, segment, '$')) {
            parts.push_back(segment);
        }

        if (parts.size() != 4 || parts[0] != "pbkdf2") 
            return Napi::Boolean::New(env, false);

        int rounds = std::stoi(parts[1]);
        std::string saltHex = parts[2];
        std::string storedHashHex = parts[3];

        if (saltHex.length() != SALT_LENGTH * 2 || storedHashHex.length() != HASH_LENGTH * 2) {
            return Napi::Boolean::New(env, false);
        }

        unsigned char salt[SALT_LENGTH];
        for (int i = 0; i < SALT_LENGTH; ++i) {
            salt[i] = static_cast<unsigned char>(std::stoi(saltHex.substr(i * 2, 2), nullptr, 16));
        }

        std::vector<unsigned char> derivedHash(HASH_LENGTH);
        if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                               salt, sizeof(salt),
                               ITERATIONS * rounds, EVP_sha512(),
                               derivedHash.size(), derivedHash.data())) {
            return Napi::Boolean::New(env, false);
        }

        unsigned char storedHash[HASH_LENGTH];
        for (int i = 0; i < HASH_LENGTH; ++i) {
            storedHash[i] = static_cast<unsigned char>(std::stoi(storedHashHex.substr(i * 2, 2), nullptr, 16));
        }

        return Napi::Boolean::New(env, constantTimeCompare(derivedHash.data(), storedHash, HASH_LENGTH));
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("hash", Napi::Function::New(env, HashPassword));
    exports.Set("compare", Napi::Function::New(env, ComparePassword));
    return exports;
}

NODE_API_MODULE(secure_password, Init)
