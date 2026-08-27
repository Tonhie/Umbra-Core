#include "pki/pki_user.h"

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

int test_apply_for_certificates() {
    umbra::certificate::CertificateAuthority ca1(
        "CA1", umbra::crypto::CryptoType::Elgamal, 256
    );
    umbra::pki::PkiUser alice(
        "Alice", umbra::crypto::CryptoType::RSA,
        umbra::crypto::CryptoType::RSA, 256
    );

    const std::vector<umbra::certificate::Certificate> certificates =
        alice.apply_for_certificates(ca1);
    expect(certificates.size() == 2, "user holds two certificates");

    const umbra::certificate::Certificate& encryption_cert = certificates[0];
    const umbra::certificate::Certificate& signature_cert = certificates[1];
    expect(
        encryption_cert.Subject() == "Alice" &&
            encryption_cert.Purpose() == umbra::certificate::KeyPurpose::Encryption &&
            signature_cert.Subject() == "Alice" &&
            signature_cert.Purpose() == umbra::certificate::KeyPurpose::Signature,
        "encryption and signature certificates are issued per purpose"
    );
    expect(
        encryption_cert.Algorithm() == umbra::crypto::CryptoType::Elgamal &&
            signature_cert.Algorithm() == umbra::crypto::CryptoType::Elgamal,
        "flag1 is the issuing CA's algorithm"
    );
    expect(
        umbra::certificate::verify_certificate_signature(
            encryption_cert, ca1.public_key()
        ) &&
            umbra::certificate::verify_certificate_signature(
                signature_cert, ca1.public_key()
            ),
        "both certificates verify with the CA key"
    );

    // The certified public keys match the user's own keys.
    auto certified_enc = umbra::certificate::parse_public_key(
        encryption_cert.SubjectPublicKey()
    );
    auto certified_sig = umbra::certificate::parse_public_key(
        signature_cert.SubjectPublicKey()
    );
    expect(
        certified_enc != nullptr && certified_sig != nullptr &&
            static_cast<std::string>(*certified_enc) ==
                static_cast<std::string>(alice.encryption_public_key()) &&
            static_cast<std::string>(*certified_sig) ==
                static_cast<std::string>(alice.signature_public_key()),
        "certificates carry the user's public keys"
    );
    return 0;
}

int test_sign_verify() {
    umbra::pki::PkiUser alice(
        "Alice", umbra::crypto::CryptoType::RSA,
        umbra::crypto::CryptoType::Elgamal, 256
    );
    const std::string message = "Hello, this message is signed by Alice.";
    const std::string signature = alice.sign(message);
    expect(alice.verify(message, signature), "sign + verify round trip");
    expect(
        !alice.verify(message + "!", signature),
        "tampered message rejected"
    );
    expect(
        !alice.verify(message, alice.sign("another message")),
        "wrong signature rejected"
    );
    return 0;
}

} // namespace

int main() {
    std::cout << "=== Pki User Tests ===\n";

    test_apply_for_certificates();
    test_sign_verify();

    if (failures > 0) {
        std::cerr << "\n" << failures << " test(s) FAILED\n";
        return 1;
    }
    std::cout << "\nAll pki user tests PASSED\n";
    return 0;
}
