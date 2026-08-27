#include "certificate.h"

#include <cstddef>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace umbra::certificate {
namespace {

std::string algorithm_name(umbra::crypto::CryptoType type) {
    switch (type) {
    case umbra::crypto::CryptoType::RSA:
        return "RSA";
    case umbra::crypto::CryptoType::Elgamal:
        return "Elgamal";
    }
    throw std::invalid_argument("unknown crypto type");
}

std::string purpose_name(KeyPurpose purpose) {
    switch (purpose) {
    case KeyPurpose::Encryption:
        return "Encryption";
    case KeyPurpose::Signature:
        return "Signature";
    }
    throw std::invalid_argument("unknown key purpose");
}

umbra::crypto::CryptoType parse_algorithm(const std::string& value) {
    if (value == "RSA" || value == "0") {
        return umbra::crypto::CryptoType::RSA;
    }
    if (value == "Elgamal" || value == "1") {
        return umbra::crypto::CryptoType::Elgamal;
    }
    throw std::invalid_argument("unknown crypto type: " + value);
}

} // namespace

KeyPurpose parse_key_purpose(const std::string& value) {
    if (value == "Encryption" || value == "0") {
        return KeyPurpose::Encryption;
    }
    if (value == "Signature" || value == "1") {
        return KeyPurpose::Signature;
    }
    throw std::invalid_argument("unknown key purpose: " + value);
}

/*
    Certificate Implementation
*/

Certificate::Certificate(
    std::string issuer_id,
    std::string subject_id,
    std::string subject_public_key,
    std::string signature,
    crypto::CryptoType algorithm,
    KeyPurpose purpose
) : issuer_id(std::move(issuer_id)),
    subject_id(std::move(subject_id)),
    subject_public_key(std::move(subject_public_key)),
    signature(std::move(signature)),
    algorithm(algorithm),
    purpose(purpose) {}

std::string Certificate::signed_payload() const {
    return subject_id + '\n' + subject_public_key;
}

/*
    Certificate txt format:
    BEGIN UMBRA CERTIFICATE
    ISSUER:<id>
    SUBJECT:<id>
    ALGORITHM:<RSA|Elgamal>
    PURPOSE:<Encryption|Signature>
    PUBLIC_KEY:<subject_public_key text, possibly multi-line>
    SIGNATURE:
    <signature text, possibly multi-line>
    END UMBRA CERTIFICATE
*/

std::string Certificate::to_string() const {
    std::ostringstream out;
    out << "BEGIN UMBRA CERTIFICATE\n";
    out << "ISSUER:" << issuer_id << '\n';
    out << "SUBJECT:" << subject_id << '\n';
    out << "ALGORITHM:" << algorithm_name(algorithm) << '\n';
    out << "PURPOSE:" << purpose_name(purpose) << '\n';
    out << "PUBLIC_KEY:" << subject_public_key << '\n';
    out << "SIGNATURE:\n" << signature << '\n';
    out << "END UMBRA CERTIFICATE\n";
    return out.str();
}

Certificate Certificate::from_string(const std::string& text) {
    std::istringstream in(text);
    std::string line;

    if (!std::getline(in, line) || line != "BEGIN UMBRA CERTIFICATE") {
        throw std::runtime_error("malformed certificate: missing header");
    }

    std::string issuer_id;
    std::string subject_id;
    std::string key_text;
    std::string signature_text;
    umbra::crypto::CryptoType algorithm = umbra::crypto::CryptoType::RSA;
    KeyPurpose purpose = KeyPurpose::Encryption;

    if (!std::getline(in, line) || line.rfind("ISSUER:", 0) != 0) {
        throw std::runtime_error("malformed certificate: missing issuer");
    }
    issuer_id = line.substr(7);

    if (!std::getline(in, line) || line.rfind("SUBJECT:", 0) != 0) {
        throw std::runtime_error("malformed certificate: missing subject");
    }
    subject_id = line.substr(8);

    if (!std::getline(in, line) || line.rfind("ALGORITHM:", 0) != 0) {
        throw std::runtime_error("malformed certificate: missing algorithm");
    }
    algorithm = parse_algorithm(line.substr(10));

    if (!std::getline(in, line) || line.rfind("PURPOSE:", 0) != 0) {
        throw std::runtime_error("malformed certificate: missing purpose");
    }
    purpose = parse_key_purpose(line.substr(8));

    if (!std::getline(in, line) || line.rfind("PUBLIC_KEY:", 0) != 0) {
        throw std::runtime_error("malformed certificate: missing public key");
    }
    key_text = line.substr(11);
    while (std::getline(in, line) && line != "SIGNATURE:") {
        key_text += '\n';
        key_text += line;
    }
    if (line != "SIGNATURE:") {
        throw std::runtime_error("malformed certificate: missing signature");
    }

    while (std::getline(in, line) && line != "END UMBRA CERTIFICATE") {
        if (!signature_text.empty()) {
            signature_text += '\n';
        }
        signature_text += line;
    }
    if (line != "END UMBRA CERTIFICATE") {
        throw std::runtime_error("malformed certificate: missing footer");
    }

    return Certificate(
        issuer_id, subject_id, key_text, signature_text, algorithm, purpose
    );
}

/*
    Key Conversion Helpers
*/

std::string public_key_to_string(const crypto::PublicKey& key) {
    const std::string text = static_cast<std::string>(key);
    switch (key.type()) {
    case crypto::CryptoType::RSA:
        return "RSA\n" + text;
    case crypto::CryptoType::Elgamal:
        return "ELGAMAL\n" + text;
    }
    throw std::invalid_argument("unsupported public key type");
}

std::unique_ptr<crypto::PublicKey> parse_public_key(const std::string& key_text) {
    std::istringstream in(key_text);
    std::string marker;
    in >> marker;

    umbra::crypto::CryptoType type;
    if (marker == "RSA") {
        type = umbra::crypto::CryptoType::RSA;
    } else if (marker == "ELGAMAL") {
        type = umbra::crypto::CryptoType::Elgamal;
    } else {
        throw std::invalid_argument("public key text lacks a type marker");
    }

    std::ostringstream body;
    std::string rest;
    std::getline(in, rest);
    if (!rest.empty()) {
        body << rest;
    }
    std::string line;
    while (std::getline(in, line)) {
        body << '\n' << line;
    }
    return umbra::crypto::create_encryption_engine(type)
        ->string_to_public_key(body.str());
}

long default_key_bits(crypto::CryptoType type) {
    switch (type) {
    case crypto::CryptoType::RSA:
        return DEFAULT_MODULUS_BIT;
    case crypto::CryptoType::Elgamal:
        return DEFAULT_ELGAMAL_BITS;
    }
    throw std::invalid_argument("unknown crypto type");
}

/*
    Verification
*/

bool verify_certificate_signature(
    const Certificate& certificate,
    const crypto::PublicKey& issuer_public_key
) {
    auto engine = umbra::crypto::create_signature_engine(certificate.Algorithm());
    return engine->verify(
        certificate.signed_payload(),
        certificate.Signature(),
        issuer_public_key
    );
}

bool verify_certificate_path(
    const CertificatePath& path,
    const crypto::PublicKey& root_public_key
) {
    if (path.certificates.empty()) {
        return false;
    }

    const Certificate& root_certificate = path.certificates.front();
    if (!root_certificate.is_self_signed()) {
        return false;
    }
    if (!verify_certificate_signature(root_certificate, root_public_key)) {
        return false;
    }

    for (std::size_t i = 1; i < path.certificates.size(); ++i) {
        auto issuer_key = parse_public_key(
            path.certificates[i - 1].SubjectPublicKey()
        );
        if (issuer_key == nullptr) {
            return false;
        }
        if (!verify_certificate_signature(
                path.certificates[i], *issuer_key
            )) {
            return false;
        }
    }
    return true;
}

} // namespace umbra::certificate
