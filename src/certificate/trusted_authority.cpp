#include "trusted_authority.h"

#include <utility>

namespace umbra::certificate {

/*
    TrustedAuthority Implementation
*/

TrustedAuthority::TrustedAuthority(
    const std::string& authority_name,
    crypto::CryptoType algorithm,
    long modulus_bits
) : authority_name(authority_name), algorithm(algorithm) {
    // The TA signs certificates with its own signature key pair.
    auto engine = umbra::crypto::create_encryption_engine(algorithm);
    const long bits = (modulus_bits == 0) ? default_key_bits(algorithm)
                                          : modulus_bits;
    auto keypair = engine->generate_keypair(bits);
    publick_key = std::move(keypair.public_key);
    private_key = std::move(keypair.private_key);
}

void TrustedAuthority::register_user(UserInfo& info) {
    registered_users.push_back(info);
}

Certificate TrustedAuthority::grant_certificate(
    std::string& id,
    std::string ver_alice,
    KeyPurpose purpose
) {
    // s = sig(TA 的私钥, ID(Alice) || ver_Alice)
    auto engine = umbra::crypto::create_signature_engine(algorithm);
    const std::string payload = id + '\n' + ver_alice;
    const std::string signature = engine->sign(payload, *private_key);
    return Certificate(
        authority_name,
        id,
        std::move(ver_alice),
        signature,
        algorithm,
        purpose
    );
}

}
