#include "certificate/trusted_authority.h"

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

umbra::certificate::Certificate grant_for_alice(
    umbra::certificate::TrustedAuthority& ta,
    umbra::crypto::CryptoType alice_algorithm,
    umbra::certificate::KeyPurpose purpose
) {
    auto alice_engine = umbra::crypto::create_encryption_engine(alice_algorithm);
    const auto alice_keypair = alice_engine->generate_keypair(256);
    std::string alice_id = "Alice";
    const std::string ver_alice = umbra::certificate::public_key_to_string(
        *alice_keypair.public_key
    );
    return ta.grant_certificate(alice_id, ver_alice, purpose);
}

int test_ta_issues_rsa_certificate() {
    umbra::certificate::TrustedAuthority ta(
        "TA", umbra::crypto::CryptoType::RSA, 256
    );
    const umbra::certificate::Certificate cert =
        grant_for_alice(ta, umbra::crypto::CryptoType::RSA,
                        umbra::certificate::KeyPurpose::Signature);
    expect(
        cert.Issuer() == "TA" &&
            cert.Subject() == "Alice" &&
            cert.Algorithm() == umbra::crypto::CryptoType::RSA &&
            cert.Purpose() == umbra::certificate::KeyPurpose::Signature,
        "TA(RSA) certificate fields"
    );
    expect(
        umbra::certificate::verify_certificate_signature(cert, ta.public_key()),
        "TA(RSA) certificate signature verifies"
    );

    // A certificate with a tampered subject must not verify.
    const umbra::certificate::Certificate forged(
        cert.Issuer(), "Mallory", cert.SubjectPublicKey(), cert.Signature(),
        cert.Algorithm(), cert.Purpose()
    );
    expect(
        !umbra::certificate::verify_certificate_signature(forged, ta.public_key()),
        "tampered TA(RSA) certificate rejected"
    );

    // The wrong issuer key must not verify the certificate.
    umbra::certificate::TrustedAuthority other_ta(
        "TA", umbra::crypto::CryptoType::RSA, 256
    );
    expect(
        !umbra::certificate::verify_certificate_signature(cert, other_ta.public_key()),
        "wrong TA(RSA) key rejected"
    );
    return 0;
}

int test_ta_issues_elgamal_certificate() {
    umbra::certificate::TrustedAuthority ta(
        "TA", umbra::crypto::CryptoType::Elgamal, 256
    );
    const umbra::certificate::Certificate cert =
        grant_for_alice(ta, umbra::crypto::CryptoType::Elgamal,
                        umbra::certificate::KeyPurpose::Signature);
    expect(
        cert.Algorithm() == umbra::crypto::CryptoType::Elgamal &&
            cert.Purpose() == umbra::certificate::KeyPurpose::Signature,
        "TA(Elgamal) certificate fields"
    );
    expect(
        umbra::certificate::verify_certificate_signature(cert, ta.public_key()),
        "TA(Elgamal) certificate signature verifies"
    );
    expect(
        !umbra::certificate::verify_certificate_signature(
            cert, umbra::certificate::TrustedAuthority(
                       "TA", umbra::crypto::CryptoType::Elgamal, 256
                   ).public_key()
        ),
        "wrong TA(Elgamal) key rejected"
    );
    return 0;
}

int test_ta_issue_purpose_flag() {
    umbra::certificate::TrustedAuthority ta(
        "TA", umbra::crypto::CryptoType::RSA, 256
    );
    const umbra::certificate::Certificate encryption_cert = grant_for_alice(
        ta, umbra::crypto::CryptoType::RSA, umbra::certificate::KeyPurpose::Encryption
    );
    const umbra::certificate::Certificate signature_cert = grant_for_alice(
        ta, umbra::crypto::CryptoType::RSA, umbra::certificate::KeyPurpose::Signature
    );
    expect(
        encryption_cert.Purpose() == umbra::certificate::KeyPurpose::Encryption &&
            signature_cert.Purpose() == umbra::certificate::KeyPurpose::Signature,
        "flag2 (key purpose) is issued as requested"
    );
    expect(
        umbra::certificate::verify_certificate_signature(
            encryption_cert, ta.public_key()
        ) &&
            umbra::certificate::verify_certificate_signature(
                signature_cert, ta.public_key()
            ),
        "both purpose certificates verify"
    );
    return 0;
}

} // namespace

int main() {
    std::cout << "=== Trusted Authority Tests ===\n";

    test_ta_issues_rsa_certificate();
    test_ta_issues_elgamal_certificate();
    test_ta_issue_purpose_flag();

    if (failures > 0) {
        std::cerr << "\n" << failures << " test(s) FAILED\n";
        return 1;
    }
    std::cout << "\nAll trusted authority tests PASSED\n";
    return 0;
}
