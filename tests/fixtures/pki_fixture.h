#pragma once

#include "certificate/certificate_authority.h"
#include "certificate/certificate_library.h"
#include "pki/pki_user.h"

#include <stdexcept>
#include <vector>

// Shared strict-hierarchy PKI setup used by the certificate-library and
// secure-mail test programs:
//   CA_root (RSA, self-signed)
//    |-- CA1 (Elgamal): Alice, Eve
//    `-- CA2 (RSA):     Bob
struct PkiFixture {
    umbra::certificate::CertificateAuthority root;
    umbra::certificate::CertificateAuthority ca1;
    umbra::certificate::CertificateAuthority ca2;
    umbra::certificate::CertificateLibrary library;
    umbra::pki::PkiUser alice;
    umbra::pki::PkiUser bob;
    umbra::pki::PkiUser eve;

    PkiFixture()
        : root("CA_root", umbra::crypto::CryptoType::RSA, 256),
          ca1("CA1", umbra::crypto::CryptoType::Elgamal, 256),
          ca2("CA2", umbra::crypto::CryptoType::RSA, 256),
          library("CA_root", root.public_key()),
          alice("Alice", umbra::crypto::CryptoType::RSA,
                umbra::crypto::CryptoType::RSA, 256),
          bob("Bob", umbra::crypto::CryptoType::Elgamal,
              umbra::crypto::CryptoType::RSA, 256),
          eve("Eve", umbra::crypto::CryptoType::RSA,
              umbra::crypto::CryptoType::Elgamal, 256) {
        store_or_throw(root.self_sign());
        store_or_throw(root.issue_certificate(
            ca1.AuthorityId(), ca1.public_key_text(),
            umbra::certificate::KeyPurpose::Signature
        ));
        store_or_throw(root.issue_certificate(
            ca2.AuthorityId(), ca2.public_key_text(),
            umbra::certificate::KeyPurpose::Signature
        ));
        alice.apply_for_certificates(ca1);
        bob.apply_for_certificates(ca2);
        eve.apply_for_certificates(ca1);
        store_or_throw(alice.certificates());
        store_or_throw(bob.certificates());
        store_or_throw(eve.certificates());
    }

    void store_or_throw(const umbra::certificate::Certificate& certificate) {
        if (!library.store(certificate)) {
            throw std::runtime_error("fixture setup: certificate rejected");
        }
    }

    void store_or_throw(
        const std::vector<umbra::certificate::Certificate>& certificates
    ) {
        for (const auto& certificate : certificates) {
            store_or_throw(certificate);
        }
    }
};
