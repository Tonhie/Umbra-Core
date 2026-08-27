#include "pki_user.h"

#include <utility>

namespace umbra::pki {

/*
    PkiUser Implementation
*/

PkiUser::PkiUser(
    const std::string& user_id,
    crypto::CryptoType encryption_algorithm,
    crypto::CryptoType signature_algorithm,
    long modulus_bits
) : user_id(user_id),
    encryption_algorithm(encryption_algorithm),
    signature_algorithm(signature_algorithm) {
    auto encryption_engine =
        umbra::crypto::create_encryption_engine(encryption_algorithm);
    auto signature_engine =
        umbra::crypto::create_encryption_engine(signature_algorithm);
    const long encryption_bits = (modulus_bits == 0)
        ? certificate::default_key_bits(encryption_algorithm)
        : modulus_bits;
    const long signature_bits = (modulus_bits == 0)
        ? certificate::default_key_bits(signature_algorithm)
        : modulus_bits;
    auto encryption_keypair = encryption_engine->generate_keypair(
        encryption_bits
    );
    auto signature_keypair = signature_engine->generate_keypair(
        signature_bits
    );
    encryption_public_key_ = std::move(encryption_keypair.public_key);
    encryption_private_key_ = std::move(encryption_keypair.private_key);
    signature_public_key_ = std::move(signature_keypair.public_key);
    signature_private_key_ = std::move(signature_keypair.private_key);
}

std::string PkiUser::encryption_public_key_text() const {
    return certificate::public_key_to_string(*encryption_public_key_);
}

std::string PkiUser::signature_public_key_text() const {
    return certificate::public_key_to_string(*signature_public_key_);
}

std::vector<certificate::Certificate> PkiUser::apply_for_certificates(
    const certificate::CertificateAuthority& ca
) {
    certificates_.clear();
    certificates_.push_back(ca.issue_certificate(
        user_id,
        encryption_public_key_text(),
        certificate::KeyPurpose::Encryption
    ));
    certificates_.push_back(ca.issue_certificate(
        user_id,
        signature_public_key_text(),
        certificate::KeyPurpose::Signature
    ));
    return certificates_;
}

std::string PkiUser::sign(const std::string& message) const {
    auto engine = umbra::crypto::create_signature_engine(
        signature_public_key_->type()
    );
    return engine->sign(message, *signature_private_key_);
}

bool PkiUser::verify(
    const std::string& message,
    const std::string& signature
) const {
    auto engine = umbra::crypto::create_signature_engine(
        signature_public_key_->type()
    );
    return engine->verify(message, signature, *signature_public_key_);
}

} // namespace umbra::pki
