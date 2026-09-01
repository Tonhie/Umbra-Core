#include "rsa_engine.h"
#include "../hash/sha_256.h"
#include <stdexcept>
#include <sstream>
#include <vector>

using namespace umbra::crypto::rsa;

/**
 * Key Conversion
 */


PublicKey::PublicKey(const std::string& str) {
    std::stringstream ss(str);
    ss >> this->n >> this->e;
}

PublicKey::operator std::string() const {
    std::stringstream ss;
    ss << this->n << std::endl << this->e;
    return ss.str();
}

PrivateKey::PrivateKey(const std::string& str) {
    std::stringstream ss(str);
    ss >> this->p >> this->q >> this->d;
}

PrivateKey::operator std::string() const {
    std::stringstream ss;
    ss << this->p << std::endl << this->q << std::endl << this->d;
    return ss.str();
}

/*
    EncryptionEngine Implementation
*/

::umbra::crypto::Keypair EncryptionEngine::generate_keypair(long modulus_bits) const {
    // Implement RSA keypair generation logic here
    // Generate public and private keys and assign them to keypair
    NTL::ZZ p, q, e = NTL::ZZ(65537), d;
    while (true) {
        // Generate two distinct prime numbers p and q
        p = NTL::GenPrime_ZZ(modulus_bits);
        q = NTL::GenPrime_ZZ(modulus_bits);
        if (p == q) continue;
        NTL::ZZ p1 = p - 1, q1 = q - 1;
        NTL::ZZ lambda = p1 / NTL::GCD(p1, q1) * q1;
        if (NTL::GCD(e, lambda) == 1) {
            d = NTL::InvMod(e, lambda);
            break;
        }
    }
    // Assign the generated keys to the keypair
    return umbra::crypto::Keypair(
        std::make_unique<PrivateKey>(p, q, d),
        std::make_unique<PublicKey>(p * q, e)
    );
}

std::string EncryptionEngine::encrypt(
    const std::string& plaintext,
    const crypto::PublicKey& public_key
) const {
    const auto* key = dynamic_cast<const PublicKey*>(&public_key);
    if (key == nullptr) {
        throw std::invalid_argument("invalid RSA public key");
    }

    const long block_size = NTL::NumBytes(key->n) - 1;
    if (block_size <= 0) {
        throw std::runtime_error("invalid RSA modulus");
    }
    std::ostringstream out;
    for (std::size_t offset = 0; offset < plaintext.size(); offset += block_size) {
        long current_size = static_cast<long>(
            std::min<std::size_t>(block_size, plaintext.size() - offset)
        );
        const auto* block = reinterpret_cast<const unsigned char*>(plaintext.data() + offset);
        NTL::ZZ m = NTL::ZZFromBytes(block, current_size);
        NTL::ZZ c = NTL::PowerMod(m, key->e, key->n);
        out << current_size << '-' << c << '\n';
    }
    return out.str();
}

std::string EncryptionEngine::decrypt(
    const std::string& ciphertext,
    const crypto::PrivateKey& private_key
) const {
    const auto* key = dynamic_cast<const PrivateKey*>(&private_key);
    if (key == nullptr) {
        throw std::invalid_argument("invalid RSA private key");
    }

    std::istringstream in(ciphertext);
    std::ostringstream out;

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) {
            continue;
        }

        const std::size_t separator = line.find('-');
        if (separator == std::string::npos) {
            throw std::runtime_error("invalid RSA ciphertext block");
        }

        const long block_size = std::stol(line.substr(0, separator));
        if (block_size < 0) {
            throw std::runtime_error("invalid RSA block size");
        }

        NTL::ZZ c;
        std::istringstream block_stream(line.substr(separator + 1));
        if (!(block_stream >> c)) {
            throw std::runtime_error("invalid RSA ciphertext value");
        }

        // Normalize the ciphertext value so that tampered input cannot
        // trigger an NTL error inside PowerMod.
        NTL::ZZ n = key->p * key->q;
        c = c % n;
        if (c < 0) {
            c += n;
        }

        NTL::ZZ m = NTL::PowerMod(c, key->d, n);
        std::vector<unsigned char> buffer(block_size);
        NTL::BytesFromZZ(buffer.data(), m, block_size);
        out.write(reinterpret_cast<const char*>(buffer.data()), block_size);
    }
    return out.str();
}

std::string SignatureEngine::sign(
    const std::string& message,
    const crypto::PrivateKey& private_key
) const {
    const auto* key = dynamic_cast<const PrivateKey*>(&private_key);
    if (key == nullptr) {
        throw std::invalid_argument("invalid RSA private key");
    }

    const std::string digest = umbra::hash::sha256(message);

    NTL::ZZ n = key->p * key->q;
    NTL::ZZ m = NTL::ZZFromBytes(
        reinterpret_cast<const unsigned char*>(digest.data()),
        static_cast<long>(digest.size())
    );

    if (m >= n) {
        throw std::runtime_error("RSA modulus too small for signature hash");
    }

    NTL::ZZ s = NTL::PowerMod(m, key->d, n);

    std::ostringstream out;
    out << s;
    return out.str();
}

bool SignatureEngine::verify(
    const std::string& message,
    const std::string& signature,
    const crypto::PublicKey& public_key
) const {
    const auto* key = dynamic_cast<const PublicKey*>(&public_key);
    if (key == nullptr) {
        return false;
    }

    NTL::ZZ s;
    std::istringstream sig_stream(signature);
    if (!(sig_stream >> s)) {
        return false;
    }

    // The signature text may be checked against a foreign modulus; reduce
    // it first so that PowerMod never receives a base outside [0, n).
    s = s % key->n;
    if (s < 0) {
        s += key->n;
    }

    const std::string expected_digest = umbra::hash::sha256(message);

    NTL::ZZ recovered = NTL::PowerMod(s, key->e, key->n);

    std::vector<unsigned char> buffer(expected_digest.size());
    NTL::BytesFromZZ(
        buffer.data(),
        recovered,
        static_cast<long>(buffer.size())
    );

    std::string recovered_digest(
        reinterpret_cast<const char*>(buffer.data()),
        buffer.size()
    );

    return recovered_digest == expected_digest;
}

