#include "certificate_authority.h"

#include <utility>

namespace umbra::certificate {

/*
    CertificateAuthority Implementation
*/

CertificateAuthority::CertificateAuthority(
    const std::string& authority_id,
    crypto::CryptoType algorithm,
    long modulus_bits
) : authority_id(authority_id), algorithm(algorithm) {
    // The CA signs certificates with its own signature key pair.
    auto engine = umbra::crypto::create_encryption_engine(algorithm);
    const long bits = (modulus_bits == 0) ? default_key_bits(algorithm)
                                          : modulus_bits;
    auto keypair = engine->generate_keypair(bits);
    public_key_ = std::move(keypair.public_key);
    private_key_ = std::move(keypair.private_key);
}

std::string CertificateAuthority::public_key_text() const {
    return public_key_to_string(*public_key_);
}

Certificate CertificateAuthority::self_sign() const {
    auto engine = umbra::crypto::create_signature_engine(algorithm);
    const std::string payload = authority_id + '\n' + public_key_text();
    const std::string signature = engine->sign(payload, *private_key_);
    return Certificate(
        authority_id,
        authority_id,
        public_key_text(),
        signature,
        algorithm,
        KeyPurpose::Signature
    );
}

Certificate CertificateAuthority::issue_certificate(
    const std::string& subject_id,
    const std::string& subject_public_key,
    KeyPurpose purpose
) const {
    auto engine = umbra::crypto::create_signature_engine(algorithm);
    const std::string payload = subject_id + '\n' + subject_public_key;
    const std::string signature = engine->sign(payload, *private_key_);
    return Certificate(
        authority_id,
        subject_id,
        subject_public_key,
        signature,
        algorithm,
        purpose
    );
}

} // namespace umbra::certificate
