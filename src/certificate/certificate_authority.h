#pragma once

#include "certificate.h"

#include <memory>
#include <string>

namespace umbra::certificate {

// A certificate authority in the strict hierarchical PKI system
// (textbook section 12.3.1). The root CA signs its own certificate;
// the subordinate CAs (CA1, CA2, ...) hold a certificate issued by their
// parent CA; users hold certificates issued by a subordinate CA.
class CertificateAuthority {
private:
    std::string authority_id;
    // flag1 of the certificates issued by this CA: 0=RSA, 1=Elgamal
    crypto::CryptoType algorithm;
    std::unique_ptr<crypto::PublicKey> public_key_;
    std::unique_ptr<crypto::PrivateKey> private_key_;

public:
    CertificateAuthority(
        const std::string& authority_id,
        crypto::CryptoType algorithm = crypto::CryptoType::RSA,
        long modulus_bits = 0
    );

    const std::string& AuthorityId() const { return authority_id; }
    crypto::CryptoType Algorithm() const { return algorithm; }
    const crypto::PublicKey& public_key() const { return *public_key_; }
    std::string public_key_text() const;

    // The root CA issues its own (self-signed) certificate.
    Certificate self_sign() const;
    // Issue a certificate whose subject public key is given as text.
    Certificate issue_certificate(
        const std::string& subject_id,
        const std::string& subject_public_key,
        KeyPurpose purpose
    ) const;
};

} // namespace umbra::certificate
