#include "mail/secure_mail.h"

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

int test_mail_round_trip() {
    const PkiFixture fixture;

    const std::string message = "Hello Bob!\nThis mail contains a newline "
                                "and \u4e2d\u6587\u5b57\u7b26.";
    const std::string ciphertext = umbra::mail::send_mail(
        message,
        fixture.alice.signature_private_key(),
        fixture.library,
        "Bob",
        fixture.root.public_key()
    );
    expect(!ciphertext.empty(), "sender produces a ciphertext");

    const std::string recovered = umbra::mail::receive_mail(
        ciphertext,
        fixture.bob.encryption_private_key(),
        fixture.library,
        "Alice",
        fixture.root.public_key()
    );
    expect(recovered == message, "receiver recovers the original mail");
    return 0;
}

int test_signed_mail_split_round_trip() {
    const PkiFixture fixture;

    const std::string message = "line one\nline two\nline three";
    const std::string signed_mail = umbra::mail::sign_mail(
        message, fixture.alice.signature_private_key()
    );
    const umbra::mail::SignedMail parsed = umbra::mail::parse_signed_mail(signed_mail);
    expect(parsed.message == message, "m || s splits back into m");
    expect(
        umbra::mail::verify_mail(
            parsed.message, parsed.signature, fixture.alice.signature_public_key()
        ),
        "signature verifies after split"
    );
    expect(
        !umbra::mail::verify_mail(
            parsed.message + "!", parsed.signature,
            fixture.alice.signature_public_key()
        ),
        "tampered message rejected after split"
    );
    return 0;
}

int test_mail_tampered_ciphertext_fails() {
    const PkiFixture fixture;

    const std::string ciphertext = umbra::mail::send_mail(
        "Secret plan for Friday.",
        fixture.alice.signature_private_key(),
        fixture.library,
        "Bob",
        fixture.root.public_key()
    );

    std::string tampered = ciphertext;
    tampered[0] = (tampered[0] == '0') ? '1' : '0';
    bool threw = false;
    try {
        umbra::mail::receive_mail(
            tampered,
            fixture.bob.encryption_private_key(),
            fixture.library,
            "Alice",
            fixture.root.public_key()
        );
    } catch (const std::exception&) {
        threw = true;
    }
    expect(threw, "tampered ciphertext fails on the receiver side");
    return 0;
}

int test_mail_wrong_receiver_private_key_fails() {
    const PkiFixture fixture;

    const std::string ciphertext = umbra::mail::send_mail(
        "Secret plan for Friday.",
        fixture.alice.signature_private_key(),
        fixture.library,
        "Bob",
        fixture.root.public_key()
    );

    // Eve tries to decrypt a mail addressed to Bob.
    bool threw = false;
    try {
        umbra::mail::receive_mail(
            ciphertext,
            fixture.eve.encryption_private_key(),
            fixture.library,
            "Alice",
            fixture.root.public_key()
        );
    } catch (const std::exception&) {
        threw = true;
    }
    expect(threw, "wrong receiver private key cannot recover the mail");
    return 0;
}

int test_mail_unknown_sender_fails() {
    const PkiFixture fixture;

    const std::string ciphertext = umbra::mail::send_mail(
        "Who is this from?",
        fixture.alice.signature_private_key(),
        fixture.library,
        "Bob",
        fixture.root.public_key()
    );

    // The sender claims to be Mallory, who holds no certificate.
    bool threw = false;
    try {
        umbra::mail::receive_mail(
            ciphertext,
            fixture.bob.encryption_private_key(),
            fixture.library,
            "Mallory",
            fixture.root.public_key()
        );
    } catch (const std::exception&) {
        threw = true;
    }
    expect(threw, "sender without a certificate is rejected");
    return 0;
}

int test_mail_rejects_untrusted_chain() {
    // A rogue CA self-signs its own certificate, but the mail system
    // verifies every chain against the trusted root's public key.
    umbra::certificate::CertificateAuthority rogue(
        "RogueCA", umbra::crypto::CryptoType::RSA, 256
    );
    umbra::certificate::CertificateLibrary rogue_library(
        "RogueCA", rogue.public_key()
    );
    expect(rogue_library.store(rogue.self_sign()), "rogue library stores its root");

    umbra::pki::PkiUser mallory(
        "Mallory", umbra::crypto::CryptoType::RSA,
        umbra::crypto::CryptoType::RSA, 256
    );
    mallory.apply_for_certificates(rogue);
    for (const auto& certificate : mallory.certificates()) {
        expect(rogue_library.store(certificate), "rogue library stores Mallory's certificates");
    }

    umbra::certificate::CertificateAuthority trusted_root(
        "CA_root", umbra::crypto::CryptoType::RSA, 256
    );
    bool threw = false;
    try {
        umbra::mail::send_mail(
            "Hello?",
            mallory.signature_private_key(),
            rogue_library,
            "Mallory",
            trusted_root.public_key()
        );
    } catch (const std::exception&) {
        threw = true;
    }
    expect(threw, "chain not rooted at the trusted root is rejected");
    return 0;
}

} // namespace

int main() {
    std::cout << "=== Secure Mail Tests ===\n";

    test_mail_round_trip();
    test_signed_mail_split_round_trip();
    test_mail_tampered_ciphertext_fails();
    test_mail_wrong_receiver_private_key_fails();
    test_mail_unknown_sender_fails();
    test_mail_rejects_untrusted_chain();

    if (failures > 0) {
        std::cerr << "\n" << failures << " test(s) FAILED\n";
        return 1;
    }
    std::cout << "\nAll secure mail tests PASSED\n";
    return 0;
}
