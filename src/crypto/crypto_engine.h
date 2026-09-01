#pragma once

#include <NTL/ZZ.h>

#include <memory>
#include <string>

namespace umbra::crypto {

enum class CryptoType {
    RSA,
    Elgamal
};

class PrivateKey {
public:
    virtual CryptoType type() const = 0;
    virtual ~PrivateKey() = default;
    virtual operator std::string() const = 0;
};

class PublicKey {
public:
    virtual CryptoType type() const = 0;
    virtual ~PublicKey() = default;
    virtual operator std::string() const = 0;
};

struct Keypair {
    std::unique_ptr<PrivateKey> private_key;
    std::unique_ptr<PublicKey> public_key;

    Keypair(
        std::unique_ptr<PrivateKey> private_key,
        std::unique_ptr<PublicKey> public_key
    ) : private_key(std::move(private_key)),
        public_key(std::move(public_key)) {}
};

class EncryptionEngine {
public:
    virtual ~EncryptionEngine() = default;
    virtual CryptoType type() const = 0;
    virtual Keypair generate_keypair(long modulus_bits) const = 0;
    virtual std::string encrypt(
        const std::string& plaintext,
        const PublicKey& public_key
    ) const = 0;
    virtual std::string decrypt(
        const std::string& ciphertext,
        const PrivateKey& private_key
    ) const = 0;
    virtual std::unique_ptr<PublicKey> string_to_public_key(const std::string& str) const = 0;
    virtual std::unique_ptr<PrivateKey> string_to_private_key(const std::string& str) const = 0;
};

class SignatureEngine {
public:
    virtual ~SignatureEngine() = default;
    virtual CryptoType type() const = 0;
    virtual std::string sign(
        const std::string& message,
        const PrivateKey& private_key
    ) const = 0;
    virtual bool verify(
        const std::string& message,
        const std::string& signature,
        const PublicKey& public_key
    ) const = 0;
};

std::unique_ptr<EncryptionEngine> create_encryption_engine(CryptoType type);
std::unique_ptr<SignatureEngine> create_signature_engine(CryptoType type);

} // namespace umbra::crypto
