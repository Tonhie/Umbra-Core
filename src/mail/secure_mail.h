#pragma once

#include <certificate/certificate.h>
#include <certificate/certificate_library.h>
#include <crypto/crypto_engine.h>

#include <string>

namespace umbra::mail {

// The signed mail m || s.
struct SignedMail {
    std::string message;    // m
    std::string signature;  // s = sig(H(m))
};

// Build m || s where s = sig(sender_signature_private_key, H(m)).
std::string sign_mail(
    const std::string& message,
    const crypto::PrivateKey& sender_signature_private_key
);

// Split an m || s payload back into message and signature.
SignedMail parse_signed_mail(const std::string& signed_mail);

// Encrypt m || s with the receiver's encryption public key.
std::string encrypt_mail(
    const std::string& signed_mail,
    const crypto::PublicKey& receiver_encryption_public_key
);

// Decrypt with the receiver's encryption private key.
std::string decrypt_mail(
    const std::string& ciphertext,
    const crypto::PrivateKey& receiver_encryption_private_key
);

// Verify s over H(m) with the sender's signature public key.
bool verify_mail(
    const std::string& message,
    const std::string& signature,
    const crypto::PublicKey& sender_signature_public_key
);

// Sender procedure (steps 1-5 in the assignment):
//   1. query and verify the receiver's encryption-key certificate chain;
//   2. sign H(m) with the sender's signature private key;
//   3. take the receiver's encryption public key from the leaf certificate;
//   4. encrypt m || s with the receiver's encryption public key;
//   5. return the ciphertext c.
// Throws std::runtime_error when the receiver's certificate chain cannot
// be verified (the interactive layer may then retry or exit).
std::string send_mail(
    const std::string& message,
    const crypto::PrivateKey& sender_signature_private_key,
    const certificate::CertificateLibrary& library,
    const std::string& receiver_id,
    const crypto::PublicKey& root_public_key
);

// Receiver procedure (steps 1-4 in the assignment):
//   1. decrypt c with the receiver's encryption private key;
//   2. query and verify the sender's signature-key certificate chain;
//   3. take the sender's signature public key from the leaf certificate;
//   4. verify the signature.
// Returns the recovered message m.
// Throws std::runtime_error when the sender's certificate chain or the
// signature cannot be verified.
std::string receive_mail(
    const std::string& ciphertext,
    const crypto::PrivateKey& receiver_encryption_private_key,
    const certificate::CertificateLibrary& library,
    const std::string& sender_id,
    const crypto::PublicKey& root_public_key
);

} // namespace umbra::mail
