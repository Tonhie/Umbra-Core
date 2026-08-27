#include "certificate_library.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace umbra::certificate {

/*
    CertificateLibrary Implementation
*/

CertificateLibrary::CertificateLibrary(
    const std::string& root_id,
    const crypto::PublicKey& root_public_key
) : root_id(root_id) {
    this->root_public_key = parse_public_key(
        public_key_to_string(root_public_key)
    );
}

bool CertificateLibrary::store(const Certificate& certificate) {
    if (certificate.is_self_signed()) {
        // Only the trusted root may hold a self-signed certificate.
        if (certificate.Subject() != root_id) {
            return false;
        }
        if (!verify_certificate_signature(certificate, *root_public_key)) {
            return false;
        }
    } else {
        // Verify the certificate against the public key of its issuer,
        // whose certificate must already be stored in the library.
        const Certificate* issuer_certificate = find_certificate(
            certificate.Issuer(), KeyPurpose::Signature
        );
        if (issuer_certificate == nullptr) {
            return false;
        }
        auto issuer_key = parse_public_key(
            issuer_certificate->SubjectPublicKey()
        );
        if (issuer_key == nullptr) {
            return false;
        }
        if (!verify_certificate_signature(certificate, *issuer_key)) {
            return false;
        }
    }
    certificates.push_back(certificate);
    return true;
}

CertificatePath CertificateLibrary::query(const std::string& subject_id) const {
    const Certificate* leaf = find_certificate(subject_id, KeyPurpose::Signature);
    if (leaf == nullptr) {
        throw std::runtime_error(
            "certificate not found in library: " + subject_id
        );
    }
    return build_path(*leaf);
}

CertificatePath CertificateLibrary::query(
    const std::string& subject_id,
    KeyPurpose purpose
) const {
    const Certificate* leaf = find_certificate(subject_id, purpose);
    if (leaf == nullptr) {
        throw std::runtime_error(
            "certificate not found in library: " + subject_id
        );
    }
    return build_path(*leaf);
}

const Certificate* CertificateLibrary::find_certificate(
    const std::string& subject_id,
    KeyPurpose preferred
) const {
    // Prefer the certificate with the requested purpose; fall back to any
    // certificate of the subject (a user holds one certificate per purpose).
    const Certificate* fallback = nullptr;
    for (const auto& certificate : certificates) {
        if (certificate.Subject() != subject_id) {
            continue;
        }
        if (certificate.Purpose() == preferred) {
            return &certificate;
        }
        if (fallback == nullptr) {
            fallback = &certificate;
        }
    }
    return fallback;
}

CertificatePath CertificateLibrary::build_path(const Certificate& leaf) const {
    std::vector<Certificate> chain;
    const Certificate* current = &leaf;
    chain.push_back(*current);
    // Walk from the leaf up to the self-signed root certificate.
    while (!current->is_self_signed()) {
        const Certificate* issuer = find_certificate(
            current->Issuer(), KeyPurpose::Signature
        );
        if (issuer == nullptr || issuer == current) {
            throw std::runtime_error(
                "broken certificate chain: issuer not found for " +
                current->Subject()
            );
        }
        chain.push_back(*issuer);
        current = issuer;
    }
    std::reverse(chain.begin(), chain.end());
    return CertificatePath{std::move(chain)};
}

} // namespace umbra::certificate
