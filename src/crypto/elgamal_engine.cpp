#include "elgamal_engine.h"
#include "../hash/sha_256.h"
#include <stdexcept>
#include <sstream>
#include <vector>

namespace umbra::crypto::elgamal {

/**
 * PrivateKey's Conversion
 */

PublicKey::PublicKey(const std::string& str) {
    std::stringstream ss(str);
    ss >> this->p >> this->alpha >> this->beta;
}

PublicKey::operator std::string() const {
    std::stringstream ss;
    ss << this->p << std::endl << this->alpha << std::endl << this->beta;
    return ss.str();
}

PrivateKey::PrivateKey(const std::string& str) {
    std::stringstream ss(str);
    ss >> this->p >> this->alpha >> this->a;
}

PrivateKey::operator std::string() const {
    std::stringstream ss;
    ss << this->p << std::endl << this->alpha << std::endl << this->a;
    return ss.str();
}

/*
    EncryptionEngine Implementation
*/

crypto::Keypair EncryptionEngine::generate_keypair(long modulus_bits) const {
    // Generate a safe prime p = 2q + 1 and a generator alpha of the quadratic residue subgroup
    NTL::ZZ p, q, alpha, a, beta;
    while (true) {
        q = NTL::GenPrime_ZZ(modulus_bits - 1);
        p = 2 * q + 1;
        if (NTL::ProbPrime(p)) break;
    }
    // Find generator of order q by squaring a random element
    while (true) {
        NTL::ZZ r = NTL::RandomBnd(p - 2) + 2;
        alpha = NTL::PowerMod(r, 2, p);
        if (alpha != 1) break;
    }
    // Pick private key a and compute public key beta = alpha^a mod p
    a = NTL::RandomBnd(q - 1) + 1;
    beta = NTL::PowerMod(alpha, a, p);
    return Keypair(
        std::make_unique<PrivateKey>(p, alpha, a),
        std::make_unique<PublicKey>(p, alpha, beta)
    );
}

std::string EncryptionEngine::encrypt(
    const std::string& plaintext,
    const crypto::PublicKey& public_key
) const {
    const auto* key = dynamic_cast<const PublicKey*>(&public_key);
    if (key == nullptr) {
        throw std::invalid_argument("invalid ElGamal public key");
    }
    const long block_size = NTL::NumBytes(key->p) - 1;
    if (block_size <= 0) {
        throw std::runtime_error("invalid ElGamal modulus");
    }
    NTL::ZZ q = (key->p - 1) / 2;
    std::ostringstream out;
    for (std::size_t offset = 0; offset < plaintext.size(); offset += block_size) {
        long current_size = static_cast<long>(
            std::min<std::size_t>(block_size, plaintext.size() - offset)
        );
        const auto* block = reinterpret_cast<const unsigned char*>(plaintext.data() + offset);
        NTL::ZZ m = NTL::ZZFromBytes(block, current_size);
        // Ephemeral key k and ciphertext (c1, c2)
        NTL::ZZ k = NTL::RandomBnd(q - 1) + 1;
        NTL::ZZ c1 = NTL::PowerMod(key->alpha, k, key->p);
        NTL::ZZ c2 = NTL::MulMod(m, NTL::PowerMod(key->beta, k, key->p), key->p);
        out << current_size << '-' << c1 << '-' << c2 << '\n';
    }
    return out.str();
}

std::string EncryptionEngine::decrypt(
    const std::string& ciphertext,
    const crypto::PrivateKey& private_key
) const {
    auto* key = dynamic_cast<const PrivateKey*>(&private_key);
    if (key == nullptr) {
        throw std::invalid_argument("invalid ElGamal private key");
    }
    std::istringstream in(ciphertext);
    std::ostringstream out;

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) {
            continue;
        }

        const std::size_t sep1 = line.find('-');
        if (sep1 == std::string::npos) {
            throw std::runtime_error("invalid ElGamal ciphertext block");
        }
        const std::size_t sep2 = line.find('-', sep1 + 1);
        if (sep2 == std::string::npos) {
            throw std::runtime_error("invalid ElGamal ciphertext block");
        }

        const long block_size = std::stol(line.substr(0, sep1));
        if (block_size < 0) {
            throw std::runtime_error("invalid ElGamal block size");
        }

        NTL::ZZ c1, c2;
        std::istringstream c1_stream(line.substr(sep1 + 1, sep2 - sep1 - 1));
        std::istringstream c2_stream(line.substr(sep2 + 1));
        if (!(c1_stream >> c1) || !(c2_stream >> c2)) {
            throw std::runtime_error("invalid ElGamal ciphertext value");
        }
        // Normalize the ciphertext value so that tampered input cannot
        // trigger an NTL error inside PowerMod/InvMod.
        c1 = c1 % key->p;
        if (c1 < 0) {
            c1 += key->p;
        }
        // Decrypt: m = c2 / c1^a  (mod p)
        NTL::ZZ s = NTL::PowerMod(c1, key->a, key->p);
        if (s == 0) {
            throw std::runtime_error("invalid ElGamal ciphertext value");
        }
        NTL::ZZ s_inv = NTL::InvMod(s, key->p);
        NTL::ZZ m = NTL::MulMod(c2, s_inv, key->p);

        std::vector<unsigned char> buffer(block_size);
        NTL::BytesFromZZ(buffer.data(), m, block_size);
        out.write(reinterpret_cast<const char*>(buffer.data()), block_size);
    }
    return out.str();
}

/*
    SignatureEngine Implementation
*/

std::string SignatureEngine::sign(const std::string& message, const crypto::PrivateKey& private_key) const {
    auto* key = dynamic_cast<const PrivateKey*>(&private_key);
    if (key == nullptr) {
        throw std::invalid_argument("invalid ElGamal private key");
    }
    
    const std::string digest = umbra::hash::sha256(message);

    NTL::ZZ hash_zz = NTL::ZZFromBytes(
        reinterpret_cast<const unsigned char*>(digest.data()),
        static_cast<long>(digest.size())
    );

    // alpha is a generator of the quadratic-residue subgroup of order q,
    // therefore all signature exponents are reduced modulo q.
    NTL::ZZ order = (key->p - 1) / 2;
    hash_zz = hash_zz % order;

    // Generate signature (r, s): pick nonce k with gcd(k, q) = 1
    NTL::ZZ k, r, s;
    while (true) {
        k = NTL::RandomBnd(order - 1) + 1;
        if (NTL::GCD(k, order) != 1) continue;

        r = NTL::PowerMod(key->alpha, k, key->p);
        // s = k^{-1} * (hash - a * r) mod q
        NTL::ZZ ar = NTL::MulMod(key->a, r, order);
        NTL::ZZ diff = (hash_zz - ar + order) % order;
        s = NTL::MulMod(NTL::InvMod(k, order), diff, order);

        if (s != 0) break;
    }

    std::ostringstream out;
    out << r << '\n' << s;
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
    NTL::ZZ r, s;
    std::istringstream sig_stream(signature);
    if (!(sig_stream >> r >> s)) {
        return false;
    }

    const std::string expected_digest = umbra::hash::sha256(message);

    NTL::ZZ hash_zz = NTL::ZZFromBytes(
        reinterpret_cast<const unsigned char*>(expected_digest.data()),
        static_cast<long>(expected_digest.size())
    );

    NTL::ZZ order = (key->p - 1) / 2;
    hash_zz = hash_zz % order;

    // r comes from the signature text; when the signature is checked
    // against a foreign public key it may be >= p, so reduce it before
    // using it as a base of PowerMod (the exponent r stays unchanged).
    NTL::ZZ r_base = r % key->p;
    if (r_base < 0) {
        r_base += key->p;
    }

    // Check alpha^{hash} ≡ beta^r * r^s (mod p)
    NTL::ZZ left  = NTL::PowerMod(key->alpha, hash_zz, key->p);
    NTL::ZZ right = NTL::MulMod(
        NTL::PowerMod(key->beta, r, key->p),
        NTL::PowerMod(r_base, s, key->p),
        key->p
    );

    return left == right;
}

}