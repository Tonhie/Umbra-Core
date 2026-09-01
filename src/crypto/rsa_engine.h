#pragma once

#include <NTL/ZZ.h>

#include <cstring>
#include <fstream>
#include <memory>

#include "crypto_engine.h"

namespace umbra::crypto::rsa {

#define DEFAULT_MODULUS_BIT 1024

class PublicKey : public crypto::PublicKey {
public:
    NTL::ZZ n, e;
    PublicKey(const NTL::ZZ& n, const NTL::ZZ& e)
        : n(n), e(e) {};
    CryptoType type() const override { return CryptoType::RSA; }
    ~PublicKey() override = default;

    PublicKey(const std::string& str);
    operator std::string() const override;
};

class PrivateKey : public crypto::PrivateKey {
public:
    NTL::ZZ p, q, d;
    PrivateKey(const NTL::ZZ& p, const NTL::ZZ& q, const NTL::ZZ& d)
        : p(p), q(q), d(d) {};
    CryptoType type() const override { return CryptoType::RSA; }
    ~PrivateKey() override = default;

    PrivateKey(const std::string& str);
    operator std::string() const override;
};

class EncryptionEngine : public crypto::EncryptionEngine {
public:
    EncryptionEngine() = default;
    ~EncryptionEngine() override = default;
    CryptoType type() const override { return CryptoType::RSA; }
    crypto::Keypair generate_keypair(
        const long modulus_bits = DEFAULT_MODULUS_BIT
    ) const override;
    std::string encrypt(
        const std::string& plaintext,
        const crypto::PublicKey& public_key
    ) const override;
    std::string decrypt(
        const std::string& ciphertext,
        const crypto::PrivateKey& private_key
    ) const override;

    std::unique_ptr<crypto::PublicKey> string_to_public_key(
        const std::string& str
    ) const override {
        return std::make_unique<PublicKey>(str);
    }
    std::unique_ptr<crypto::PrivateKey> string_to_private_key(
        const std::string& str
    ) const override {
        return std::make_unique<PrivateKey>(str);
    }
};

class SignatureEngine : public crypto::SignatureEngine {
public:
    SignatureEngine() = default;
    ~SignatureEngine() override = default;
    CryptoType type() const override { return CryptoType::RSA; }
    std::string sign(
        const std::string& message,
        const crypto::PrivateKey& private_key
    ) const override;
    bool verify(
        const std::string& message,
        const std::string& signature,
        const crypto::PublicKey& public_key
    ) const override;
};

} // namespace umbra::crypto::rsa
