#pragma once

#include <NTL/ZZ.h>

#include <crypto/crypto_engine.h>
#include <crypto/elgamal_engine.h>
#include <crypto/rsa_engine.h>

#include <memory>
#include <string>
#include <vector>

namespace umbra::certificate {

// flag2: purpose of the public key contained in the certificate
enum class KeyPurpose {
    Encryption = 0,
    Signature = 1
};

KeyPurpose parse_key_purpose(const std::string& value);

class Certificate {
private:
    std::string issuer_id;
    std::string subject_id;
    std::string subject_public_key;
    std::string signature;
    // flag1: signature algorithm used by the issuer (0=RSA, 1=Elgamal)
    crypto::CryptoType algorithm;
    // flag2: purpose of the subject public key
    KeyPurpose purpose;

public:
    Certificate(
        std::string issuer_id,
        std::string subject_id,
        std::string subject_public_key,
        std::string signature,
        crypto::CryptoType algorithm,
        KeyPurpose purpose
    );

    const std::string& Issuer() const { return issuer_id; }
    const std::string& Subject() const { return subject_id; }
    const std::string& SubjectPublicKey() const { return subject_public_key; }
    const std::string& Signature() const { return signature; }
    crypto::CryptoType Algorithm() const { return algorithm; }
    KeyPurpose Purpose() const { return purpose; }

    // The exact byte string that the issuer signs.
    // It is "ID(Alice) || ver_Alice" in the assignment notation.
    std::string signed_payload() const;
    bool is_self_signed() const { return issuer_id == subject_id; }

    std::string to_string() const;
    static Certificate from_string(const std::string& text);
};

// A certificate path (chain) returned by the certificate library:
// the root certificate comes first, the leaf certificate comes last.
struct CertificatePath {
    std::vector<Certificate> certificates;
};

// Helpers used by certificate authorities and secure mail.
// The public key text starts with a type marker line ("RSA" or "ELGAMAL").
std::string public_key_to_string(const crypto::PublicKey& key);
std::unique_ptr<crypto::PublicKey> parse_public_key(const std::string& key_text);

// Default RSA/Elgamal key size in bits (1024 / 2048).
long default_key_bits(crypto::CryptoType type);

bool verify_certificate_signature(
    const Certificate& certificate,
    const crypto::PublicKey& issuer_public_key
);

// Verify every link of the path: the self-signed root certificate against
// root_public_key, then each certificate against the public key of the
// certificate above it in the path.
bool verify_certificate_path(
    const CertificatePath& path,
    const crypto::PublicKey& root_public_key
);

} // namespace umbra::certificate
