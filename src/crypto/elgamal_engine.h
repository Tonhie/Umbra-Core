#pragma once

#include <NTL/ZZ.h>

#include <cstring>
#include <fstream>
#include <memory>

#include "crypto_engine.h"

#define DEFAULT_ELGAMAL_BITS 2048

namespace umbra::crypto::elgamal {

class PublicKey : public crypto::PublicKey {
public:
    NTL::ZZ p, alpha, beta;
    PublicKey(const NTL::ZZ& p, const NTL::ZZ& alpha, const NTL::ZZ& beta)
        : p(p), alpha(alpha), beta(beta) {};
    CryptoType type() const override { return CryptoType::Elgamal; }
    ~PublicKey() override = default;

    PublicKey(const std::string& str);
    operator std::string() const override;
};

class PrivateKey : public crypto::PrivateKey {
public:
    NTL::ZZ p, alpha, a;
    PrivateKey(const NTL::ZZ& p, const NTL::ZZ& alpha, const NTL::ZZ& a)
        : p(p), alpha(alpha), a(a) {};
    CryptoType type() const override { return CryptoType::Elgamal; }
    ~PrivateKey() override = default;
    PrivateKey(const std::string& str);
    operator std::string() const override;
};

class EncryptionEngine : public crypto::EncryptionEngine {
public:
    EncryptionEngine() = default;
    ~EncryptionEngine() override = default;
    CryptoType type() const override { return CryptoType::Elgamal; }
    crypto::Keypair generate_keypair(const long modulus_bits = DEFAULT_ELGAMAL_BITS) const override;
    std::string decrypt(
        const std::string& ciphertext,
        const crypto::PrivateKey& private_key
    ) const override;
    std::string encrypt(
        const std::string& plaintext,
        const crypto::PublicKey& public_key
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
    CryptoType type() const override { return CryptoType::Elgamal; }
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

} // namespace umbra::crypto::elgamal
