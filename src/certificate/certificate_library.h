#pragma once

#include "certificate.h"

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

namespace umbra::certificate {

// A publicly queryable certificate library (证书库).
// Only certificates whose signature chains to the trusted root are stored.
class CertificateLibrary {
private:
    std::string root_id;
    std::unique_ptr<crypto::PublicKey> root_public_key;
    std::vector<Certificate> certificates;

public:
    CertificateLibrary(
        const std::string& root_id,
        const crypto::PublicKey& root_public_key
    );

    // Store a CA-issued certificate. Returns false when the certificate is
    // not issued by the trusted root or by a CA whose certificate is
    // already stored in the library.
    bool store(const Certificate& certificate);
    // Query by owner id: returns the certificate path <root, ..., leaf>.
    CertificatePath query(const std::string& subject_id) const;
    // Query by owner id and key purpose (used by the secure mail system).
    CertificatePath query(const std::string& subject_id, KeyPurpose purpose) const;
    std::size_t size() const { return certificates.size(); }

private:
    const Certificate* find_certificate(
        const std::string& subject_id,
        KeyPurpose preferred
    ) const;
    CertificatePath build_path(const Certificate& leaf) const;
};

} // namespace umbra::certificate
