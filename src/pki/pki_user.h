#pragma once

#include <certificate/certificate.h>
#include <certificate/certificate_authority.h>

#include <memory>
#include <string>
#include <vector>

namespace umbra::pki {

// A user of the PKI system (Alice, Bob, Eve). Each user owns an encryption
// key pair and a signature key pair, and holds the two certificates issued
// by its CA (one per key purpose).
class PkiUser {
private:
    std::string user_id;
    crypto::CryptoType encryption_algorithm;
    crypto::CryptoType signature_algorithm;
    std::unique_ptr<crypto::PublicKey> encryption_public_key_;
    std::unique_ptr<crypto::PrivateKey> encryption_private_key_;
    std::unique_ptr<crypto::PublicKey> signature_public_key_;
    std::unique_ptr<crypto::PrivateKey> signature_private_key_;
    std::vector<certificate::Certificate> certificates_;

public:
    PkiUser(
        const std::string& user_id,
        crypto::CryptoType encryption_algorithm = crypto::CryptoType::RSA,
        crypto::CryptoType signature_algorithm = crypto::CryptoType::RSA,
        long modulus_bits = 0
    );

    const std::string& UserId() const { return user_id; }
    const crypto::PublicKey& encryption_public_key() const {
        return *encryption_public_key_;
    }
    const crypto::PrivateKey& encryption_private_key() const {
        return *encryption_private_key_;
    }
    const crypto::PublicKey& signature_public_key() const {
        return *signature_public_key_;
    }
    const crypto::PrivateKey& signature_private_key() const {
        return *signature_private_key_;
    }
    std::string encryption_public_key_text() const;
    std::string signature_public_key_text() const;
    const std::vector<certificate::Certificate>& certificates() const {
        return certificates_;
    }

    // Apply to a CA for an encryption-purpose and a signature-purpose
    // certificate; the certificates are kept and returned.
    std::vector<certificate::Certificate> apply_for_certificates(
        const certificate::CertificateAuthority& ca
    );

    // Usage example (task 4): sign with the signature private key,
    // verify with the signature public key.
    std::string sign(const std::string& message) const;
    bool verify(const std::string& message, const std::string& signature) const;
};

} // namespace umbra::pki
