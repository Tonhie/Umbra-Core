#include "certificate/certificate_authority.h"

#include <iostream>
#include <string>

namespace {

int failures = 0;

void expect(bool condition, const std::string& name) {
    if (condition) {
        std::cout << "PASS: " << name << '\n';
    } else {
        std::cerr << "FAIL: " << name << '\n';
        ++failures;
    }
}

int test_root_self_sign() {
    umbra::certificate::CertificateAuthority root(
        "CA_root", umbra::crypto::CryptoType::RSA, 256
    );
    const umbra::certificate::Certificate cert = root.self_sign();
    expect(
        cert.is_self_signed() && cert.Issuer() == "CA_root" &&
            cert.Subject() == "CA_root" &&
            cert.Purpose() == umbra::certificate::KeyPurpose::Signature,
        "root certificate is self-signed"
    );
    expect(
        umbra::certificate::verify_certificate_signature(cert, root.public_key()),
        "root certificate verifies against its own key"
    );
    return 0;
}

int test_issue_user_certificate() {
    umbra::certificate::CertificateAuthority ca(
        "CA1", umbra::crypto::CryptoType::RSA, 256
    );
    auto user_engine = umbra::crypto::create_encryption_engine(
        umbra::crypto::CryptoType::Elgamal
    );
    const auto user_keypair = user_engine->generate_keypair(256);
    const std::string ver_alice = umbra::certificate::public_key_to_string(
        *user_keypair.public_key
    );
    const umbra::certificate::Certificate cert = ca.issue_certificate(
        "Alice", ver_alice, umbra::certificate::KeyPurpose::Encryption
    );
    expect(
        cert.Issuer() == "CA1" &&
            cert.Subject() == "Alice" &&
            cert.Algorithm() == umbra::crypto::CryptoType::RSA &&
            cert.Purpose() == umbra::certificate::KeyPurpose::Encryption,
        "CA-issued user certificate fields"
    );
    expect(
        umbra::certificate::verify_certificate_signature(cert, ca.public_key()),
        "CA-issued user certificate verifies with the CA key"
    );

    // The certificate must carry the subject's key type marker.
    auto subject_key = umbra::certificate::parse_public_key(
        cert.SubjectPublicKey()
    );
    expect(
        subject_key != nullptr &&
            subject_key->type() == umbra::crypto::CryptoType::Elgamal,
        "subject public key type is preserved in the certificate"
    );
    return 0;
}

int test_issue_subordinate_ca() {
    umbra::certificate::CertificateAuthority root(
        "CA_root", umbra::crypto::CryptoType::RSA, 256
    );
    umbra::certificate::CertificateAuthority ca1(
        "CA1", umbra::crypto::CryptoType::Elgamal, 256
    );
    const umbra::certificate::Certificate cert = root.issue_certificate(
        ca1.AuthorityId(), ca1.public_key_text(),
        umbra::certificate::KeyPurpose::Signature
    );
    expect(
        cert.Issuer() == "CA_root" && cert.Subject() == "CA1" &&
            cert.Algorithm() == umbra::crypto::CryptoType::RSA,
        "subordinate CA certificate is signed by the root (flag1 = RSA)"
    );
    expect(
        umbra::certificate::verify_certificate_signature(cert, root.public_key()),
        "subordinate CA certificate verifies with the root key"
    );

    // The public key inside the certificate is the subordinate CA's key.
    auto ca1_key = umbra::certificate::parse_public_key(cert.SubjectPublicKey());
    expect(
        ca1_key != nullptr &&
            ca1_key->type() == umbra::crypto::CryptoType::Elgamal &&
            static_cast<std::string>(*ca1_key) ==
                static_cast<std::string>(ca1.public_key()),
        "subordinate CA key is preserved in the certificate"
    );
    return 0;
}

} // namespace

int main() {
    std::cout << "=== Certificate Authority Tests ===\n";

    test_root_self_sign();
    test_issue_user_certificate();
    test_issue_subordinate_ca();

    if (failures > 0) {
        std::cerr << "\n" << failures << " test(s) FAILED\n";
        return 1;
    }
    std::cout << "\nAll certificate authority tests PASSED\n";
    return 0;
}
