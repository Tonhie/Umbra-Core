#include "secure_mail.h"

#include <stdexcept>

namespace umbra::mail {

/*
    m || s Encoding
*/

std::string sign_mail(
    const std::string& message,
    const crypto::PrivateKey& sender_signature_private_key
) {
    auto engine = umbra::crypto::create_signature_engine(
        sender_signature_private_key.type()
    );
    const std::string signature = engine->sign(message, sender_signature_private_key);
    // m || s with a length prefix so that multi-line messages split cleanly.
    return std::to_string(message.size()) + '\n' + message + signature;
}

SignedMail parse_signed_mail(const std::string& signed_mail) {
    const std::size_t newline = signed_mail.find('\n');
    if (newline == std::string::npos) {
        throw std::runtime_error("malformed signed mail: missing length");
    }
    const std::size_t length = std::stoul(signed_mail.substr(0, newline));
    if (newline + 1 + length > signed_mail.size()) {
        throw std::runtime_error("malformed signed mail: truncated payload");
    }
    SignedMail result;
    result.message = signed_mail.substr(newline + 1, length);
    result.signature = signed_mail.substr(newline + 1 + length);
    return result;
}

std::string encrypt_mail(
    const std::string& signed_mail,
    const crypto::PublicKey& receiver_encryption_public_key
) {
    auto engine = umbra::crypto::create_encryption_engine(
        receiver_encryption_public_key.type()
    );
    return engine->encrypt(signed_mail, receiver_encryption_public_key);
}

std::string decrypt_mail(
    const std::string& ciphertext,
    const crypto::PrivateKey& receiver_encryption_private_key
) {
    auto engine = umbra::crypto::create_encryption_engine(
        receiver_encryption_private_key.type()
    );
    return engine->decrypt(ciphertext, receiver_encryption_private_key);
}

bool verify_mail(
    const std::string& message,
    const std::string& signature,
    const crypto::PublicKey& sender_signature_public_key
) {
    auto engine = umbra::crypto::create_signature_engine(
        sender_signature_public_key.type()
    );
    return engine->verify(message, signature, sender_signature_public_key);
}

/*
    Sender Procedure
*/

std::string send_mail(
    const std::string& message,
    const crypto::PrivateKey& sender_signature_private_key,
    const certificate::CertificateLibrary& library,
    const std::string& receiver_id,
    const crypto::PublicKey& root_public_key
) {
    // Step 1: query the receiver's encryption-key certificate chain and
    // verify it.
    const certificate::CertificatePath receiver_path = library.query(
        receiver_id, certificate::KeyPurpose::Encryption
    );
    if (!certificate::verify_certificate_path(receiver_path, root_public_key)) {
        throw std::runtime_error(
            "receiver certificate chain verification failed: " + receiver_id
        );
    }

    // Step 3: take the receiver's encryption public key from the leaf
    // certificate.
    auto receiver_public_key = certificate::parse_public_key(
        receiver_path.certificates.back().SubjectPublicKey()
    );
    if (receiver_public_key == nullptr) {
        throw std::runtime_error(
            "cannot parse receiver public key: " + receiver_id
        );
    }

    // Step 2: sign H(m), then Step 4: encrypt m || s.
    const std::string signed_mail = sign_mail(message, sender_signature_private_key);
    return encrypt_mail(signed_mail, *receiver_public_key);
}

/*
    Receiver Procedure
*/

std::string receive_mail(
    const std::string& ciphertext,
    const crypto::PrivateKey& receiver_encryption_private_key,
    const certificate::CertificateLibrary& library,
    const std::string& sender_id,
    const crypto::PublicKey& root_public_key
) {
    // Step 1: decrypt with the receiver's encryption private key.
    const std::string signed_mail = decrypt_mail(
        ciphertext, receiver_encryption_private_key
    );
    const SignedMail parsed = parse_signed_mail(signed_mail);

    // Step 2: query the sender's signature-key certificate chain and
    // verify it.
    const certificate::CertificatePath sender_path = library.query(
        sender_id, certificate::KeyPurpose::Signature
    );
    if (!certificate::verify_certificate_path(sender_path, root_public_key)) {
        throw std::runtime_error(
            "sender certificate chain verification failed: " + sender_id
        );
    }

    // Step 3: take the sender's signature public key from the leaf
    // certificate.
    auto sender_public_key = certificate::parse_public_key(
        sender_path.certificates.back().SubjectPublicKey()
    );
    if (sender_public_key == nullptr) {
        throw std::runtime_error(
            "cannot parse sender public key: " + sender_id
        );
    }

    // Step 4: verify the signature.
    if (!verify_mail(parsed.message, parsed.signature, *sender_public_key)) {
        throw std::runtime_error(
            "mail signature verification failed: " + sender_id
        );
    }

    return parsed.message;
}

} // namespace umbra::mail
