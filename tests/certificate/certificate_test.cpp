#include "certificate/certificate.h"

#include <iostream>
#include <stdexcept>
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

int test_certificate_txt_round_trip() {
    const umbra::certificate::Certificate rsa_cert(
        "TA", "Alice", "RSA\n12345\n65537", "67890",
        umbra::crypto::CryptoType::RSA,
        umbra::certificate::KeyPurpose::Signature
    );
    const umbra::certificate::Certificate parsed_rsa =
        umbra::certificate::Certificate::from_string(rsa_cert.to_string());
    expect(
        parsed_rsa.Issuer() == "TA" &&
            parsed_rsa.Subject() == "Alice" &&
            parsed_rsa.SubjectPublicKey() == "RSA\n12345\n65537" &&
            parsed_rsa.Signature() == "67890" &&
            parsed_rsa.Algorithm() == umbra::crypto::CryptoType::RSA &&
            parsed_rsa.Purpose() == umbra::certificate::KeyPurpose::Signature,
        "certificate txt round trip (RSA)"
    );

    // Elgamal certificates carry a two-line signature.
    const umbra::certificate::Certificate elgamal_cert(
        "TA", "Bob", "ELGAMAL\n1009\n2\n512", "123\n456",
        umbra::crypto::CryptoType::Elgamal,
        umbra::certificate::KeyPurpose::Encryption
    );
    const umbra::certificate::Certificate parsed_elgamal =
        umbra::certificate::Certificate::from_string(elgamal_cert.to_string());
    expect(
        parsed_elgamal.Subject() == "Bob" &&
            parsed_elgamal.SubjectPublicKey() == "ELGAMAL\n1009\n2\n512" &&
            parsed_elgamal.Signature() == "123\n456" &&
            parsed_elgamal.Algorithm() == umbra::crypto::CryptoType::Elgamal &&
            parsed_elgamal.Purpose() == umbra::certificate::KeyPurpose::Encryption,
        "certificate txt round trip (Elgamal)"
    );

    return 0;
}

int test_certificate_signed_payload() {
    const umbra::certificate::Certificate cert(
        "TA", "Alice", "RSA\n12345\n65537", "67890",
        umbra::crypto::CryptoType::RSA,
        umbra::certificate::KeyPurpose::Signature
    );
    expect(
        cert.signed_payload() == "Alice\nRSA\n12345\n65537",
        "signed payload is ID(Alice) || ver_Alice"
    );
    expect(cert.is_self_signed() == false, "Alice certificate is not self signed");
    const umbra::certificate::Certificate root_cert(
        "CA_root", "CA_root", "RSA\n1\n2", "3",
        umbra::crypto::CryptoType::RSA,
        umbra::certificate::KeyPurpose::Signature
    );
    expect(root_cert.is_self_signed(), "root certificate is self signed");
    return 0;
}

int test_flag_values() {
    // flag1: 0=RSA, 1=Elgamal; flag2: 0=Encryption, 1=Signature.
    expect(
        static_cast<int>(umbra::crypto::CryptoType::RSA) == 0 &&
            static_cast<int>(umbra::crypto::CryptoType::Elgamal) == 1 &&
            static_cast<int>(umbra::certificate::KeyPurpose::Encryption) == 0 &&
            static_cast<int>(umbra::certificate::KeyPurpose::Signature) == 1,
        "flag1 / flag2 numeric values"
    );
    expect(
        umbra::certificate::parse_key_purpose("Encryption") ==
                umbra::certificate::KeyPurpose::Encryption &&
            umbra::certificate::parse_key_purpose("0") ==
                umbra::certificate::KeyPurpose::Encryption &&
            umbra::certificate::parse_key_purpose("Signature") ==
                umbra::certificate::KeyPurpose::Signature &&
            umbra::certificate::parse_key_purpose("1") ==
                umbra::certificate::KeyPurpose::Signature,
        "parse key purpose (name and numeric)"
    );
    bool threw = false;
    try {
        umbra::certificate::parse_key_purpose("KeyExchange");
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    expect(threw, "invalid key purpose throws");
    return 0;
}

int test_public_key_serialization() {
    // RSA keys round trip through public_key_to_string / parse_public_key.
    auto rsa_engine = umbra::crypto::create_encryption_engine(
        umbra::crypto::CryptoType::RSA
    );
    const auto rsa_keypair = rsa_engine->generate_keypair(256);
    const std::string rsa_text = umbra::certificate::public_key_to_string(
        *rsa_keypair.public_key
    );
    expect(rsa_text.rfind("RSA\n", 0) == 0, "RSA public key text carries marker");
    auto parsed_rsa = umbra::certificate::parse_public_key(rsa_text);
    expect(
        parsed_rsa != nullptr &&
            static_cast<std::string>(*parsed_rsa) ==
                static_cast<std::string>(*rsa_keypair.public_key),
        "RSA public key text round trip"
    );

    // Elgamal keys round trip as well.
    auto elgamal_engine = umbra::crypto::create_encryption_engine(
        umbra::crypto::CryptoType::Elgamal
    );
    const auto elgamal_keypair = elgamal_engine->generate_keypair(256);
    const std::string elgamal_text = umbra::certificate::public_key_to_string(
        *elgamal_keypair.public_key
    );
    expect(
        elgamal_text.rfind("ELGAMAL\n", 0) == 0,
        "Elgamal public key text carries marker"
    );
    auto parsed_elgamal = umbra::certificate::parse_public_key(elgamal_text);
    expect(
        parsed_elgamal != nullptr &&
            static_cast<std::string>(*parsed_elgamal) ==
                static_cast<std::string>(*elgamal_keypair.public_key),
        "Elgamal public key text round trip"
    );

    // Text without a type marker is rejected.
    bool threw = false;
    try {
        umbra::certificate::parse_public_key("12345\n65537");
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    expect(threw, "marker-less public key text is rejected");
    return 0;
}

int test_verify_certificate_signature() {
    // Sign a certificate with the issuer's engine directly.
    auto engine = umbra::crypto::create_encryption_engine(
        umbra::crypto::CryptoType::RSA
    );
    auto signer = umbra::crypto::create_signature_engine(
        umbra::crypto::CryptoType::RSA
    );
    const auto issuer_keypair = engine->generate_keypair(256);
    const auto subject_keypair = engine->generate_keypair(256);
    const std::string ver_alice = umbra::certificate::public_key_to_string(
        *subject_keypair.public_key
    );
    const std::string payload = "Alice\n" + ver_alice;
    const std::string signature = signer->sign(payload, *issuer_keypair.private_key);
    const umbra::certificate::Certificate cert(
        "TA", "Alice", ver_alice, signature,
        umbra::crypto::CryptoType::RSA, umbra::certificate::KeyPurpose::Signature
    );

    expect(
        umbra::certificate::verify_certificate_signature(cert, *issuer_keypair.public_key),
        "certificate signature verifies with the issuer key"
    );
    const umbra::certificate::Certificate forged(
        cert.Issuer(), "Mallory", cert.SubjectPublicKey(), cert.Signature(),
        cert.Algorithm(), cert.Purpose()
    );
    expect(
        !umbra::certificate::verify_certificate_signature(forged, *issuer_keypair.public_key),
        "tampered certificate rejected"
    );
    expect(
        !umbra::certificate::verify_certificate_signature(cert, *subject_keypair.public_key),
        "wrong issuer key rejected"
    );
    return 0;
}

} // namespace

int main() {
    std::cout << "=== Certificate Tests ===\n";

    test_certificate_txt_round_trip();
    test_certificate_signed_payload();
    test_flag_values();
    test_public_key_serialization();
    test_verify_certificate_signature();

    if (failures > 0) {
        std::cerr << "\n" << failures << " test(s) FAILED\n";
        return 1;
    }
    std::cout << "\nAll certificate tests PASSED\n";
    return 0;
}
