#include "certificate/certificate_library.h"

#include "../fixtures/pki_fixture.h"

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

int test_chain_queries() {
    const PkiFixture fixture;

    // Alice's certificate was issued by CA1: <CA_root, CA1, Alice>.
    const umbra::certificate::CertificatePath alice_path =
        fixture.library.query("Alice");
    expect(alice_path.certificates.size() == 3, "Alice chain has 3 certificates");
    expect(
        alice_path.certificates[0].Subject() == "CA_root" &&
            alice_path.certificates[1].Subject() == "CA1" &&
            alice_path.certificates[2].Subject() == "Alice",
        "Alice chain order is <CA_root, CA1, Alice>"
    );
    expect(
        alice_path.certificates[0].is_self_signed(),
        "Alice chain starts with the self-signed root certificate"
    );
    expect(
        umbra::certificate::verify_certificate_path(alice_path, fixture.root.public_key()),
        "Alice chain verifies against the root public key"
    );

    // Bob's certificate was issued by CA2: <CA_root, CA2, Bob>.
    const umbra::certificate::CertificatePath bob_path =
        fixture.library.query("Bob");
    expect(
        bob_path.certificates.size() == 3 &&
            bob_path.certificates[1].Subject() == "CA2" &&
            bob_path.certificates[2].Subject() == "Bob",
        "Bob chain order is <CA_root, CA2, Bob>"
    );
    expect(
        umbra::certificate::verify_certificate_path(bob_path, fixture.root.public_key()),
        "Bob chain verifies against the root public key"
    );

    // The CA's own certificate is <CA_root, CA1> and the root's is <CA_root>.
    expect(
        fixture.library.query("CA1").certificates.size() == 2 &&
            fixture.library.query("CA_root").certificates.size() == 1,
        "CA and root chains have the expected lengths"
    );

    // Each user holds one certificate per key purpose.
    const umbra::certificate::CertificatePath alice_enc =
        fixture.library.query("Alice", umbra::certificate::KeyPurpose::Encryption);
    const umbra::certificate::CertificatePath alice_sig =
        fixture.library.query("Alice", umbra::certificate::KeyPurpose::Signature);
    expect(
        alice_enc.certificates.back().Purpose() ==
                umbra::certificate::KeyPurpose::Encryption &&
            alice_sig.certificates.back().Purpose() ==
                umbra::certificate::KeyPurpose::Signature &&
            fixture.library.query("Alice").certificates.back().Purpose() ==
                umbra::certificate::KeyPurpose::Signature,
        "purpose-specific and owner-id queries return the right certificates"
    );
    return 0;
}

int test_store_rejects_forged_certificates() {
    PkiFixture fixture;

    // A certificate signed by an unknown authority is rejected.
    umbra::certificate::CertificateAuthority rogue(
        "RogueCA", umbra::crypto::CryptoType::RSA, 256
    );
    const umbra::certificate::Certificate rogue_cert = rogue.issue_certificate(
        "Mallory", fixture.alice.signature_public_key_text(),
        umbra::certificate::KeyPurpose::Signature
    );
    expect(!fixture.library.store(rogue_cert), "certificate from unknown CA rejected");

    // A self-signed certificate that is not the trusted root is rejected.
    expect(
        !fixture.library.store(rogue.self_sign()),
        "self-signed certificate of a non-root CA rejected"
    );

    // A certificate issued by a CA whose key does not match the library's
    // record is rejected.
    umbra::certificate::CertificateAuthority impostor_ca1(
        "CA1", umbra::crypto::CryptoType::RSA, 256
    );
    const umbra::certificate::Certificate forged = impostor_ca1.issue_certificate(
        "Mallory", fixture.alice.signature_public_key_text(),
        umbra::certificate::KeyPurpose::Signature
    );
    expect(
        !fixture.library.store(forged),
        "certificate forged with a wrong CA key rejected"
    );
    return 0;
}

int test_tampered_chain_fails_verification() {
    const PkiFixture fixture;

    const umbra::certificate::CertificatePath alice_path =
        fixture.library.query("Alice");
    const umbra::certificate::Certificate& alice_cert =
        alice_path.certificates.back();

    // Tamper with Alice's public key inside her leaf certificate.
    const umbra::certificate::Certificate tampered(
        alice_cert.Issuer(), alice_cert.Subject(),
        alice_cert.SubjectPublicKey() + "\n999999",
        alice_cert.Signature(), alice_cert.Algorithm(), alice_cert.Purpose()
    );
    umbra::certificate::CertificatePath tampered_path = alice_path;
    tampered_path.certificates.back() = tampered;
    expect(
        !umbra::certificate::verify_certificate_path(tampered_path, fixture.root.public_key()),
        "tampered leaf certificate fails chain verification"
    );

    // Tamper with the intermediate CA1 certificate.
    umbra::certificate::CertificatePath tampered_ca1_path = alice_path;
    tampered_ca1_path.certificates[1] = tampered;
    expect(
        !umbra::certificate::verify_certificate_path(tampered_ca1_path, fixture.root.public_key()),
        "tampered intermediate CA certificate fails chain verification"
    );

    // Verifying with a wrong root key fails.
    umbra::certificate::CertificateAuthority other_root(
        "CA_root", umbra::crypto::CryptoType::RSA, 256
    );
    expect(
        !umbra::certificate::verify_certificate_path(alice_path, other_root.public_key()),
        "chain fails verification with a wrong root key"
    );
    return 0;
}

int test_query_unknown_subject_throws() {
    const PkiFixture fixture;
    bool threw = false;
    try {
        fixture.library.query("Mallory");
    } catch (const std::runtime_error&) {
        threw = true;
    }
    expect(threw, "querying an unknown owner id throws");
    return 0;
}

// The usage example from the assignment (section 12.3.1):
// Alice sends a message and its signature; Bob queries Alice's certificate
// path in the library, verifies it, then verifies Alice's signature with
// the public key taken from the certificate.
int test_usage_example_alice_to_bob() {
    const PkiFixture fixture;

    const std::string message = "Hello Bob, this message is signed by Alice.";
    const std::string signature = fixture.alice.sign(message);

    const umbra::certificate::CertificatePath alice_path =
        fixture.library.query("Alice");
    expect(
        umbra::certificate::verify_certificate_path(alice_path, fixture.root.public_key()),
        "Bob verifies Alice's certificate path"
    );

    auto alice_public_key = umbra::certificate::parse_public_key(
        alice_path.certificates.back().SubjectPublicKey()
    );
    expect(alice_public_key != nullptr, "Bob extracts Alice's public key from the certificate");
    auto signer = umbra::crypto::create_signature_engine(
        alice_public_key->type()
    );
    expect(
        signer->verify(message, signature, *alice_public_key),
        "Bob verifies Alice's signature with the certified public key"
    );
    expect(
        !signer->verify(message + "!", signature, *alice_public_key),
        "Bob rejects a tampered message"
    );
    return 0;
}

} // namespace

int main() {
    std::cout << "=== Certificate Library Tests ===\n";

    test_chain_queries();
    test_store_rejects_forged_certificates();
    test_tampered_chain_fails_verification();
    test_query_unknown_subject_throws();
    test_usage_example_alice_to_bob();

    if (failures > 0) {
        std::cerr << "\n" << failures << " test(s) FAILED\n";
        return 1;
    }
    std::cout << "\nAll certificate library tests PASSED\n";
    return 0;
}
