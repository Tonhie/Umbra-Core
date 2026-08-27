#pragma once

#include "../crypto/crypto_engine.h"
#include "certificate.h"

namespace umbra::certificate {

struct UserInfo {
    std::string id;
    std::string name;
    std::string email;
    std::string ver_alice;
    UserInfo(
        std::string& id,
        std::string& name,
        std::string& email
    ) : id(id), name(name), email(email) {}
};

class TrustedAuthority {
private:
    std::string authority_name;
    std::unique_ptr<crypto::PublicKey> publick_key;
    std::unique_ptr<crypto::PrivateKey> private_key;
    // flag1 of the certificates issued by this TA: 0=RSA, 1=Elgamal
    crypto::CryptoType algorithm;
    std::vector<UserInfo> registered_users;
public:
    TrustedAuthority(
        const std::string& authority_name,
        crypto::CryptoType algorithm = crypto::CryptoType::RSA,
        long modulus_bits = 0
    );
    void register_user(UserInfo& info);
    Certificate grant_certificate(
        std::string& id,
        std::string ver_alice,
        KeyPurpose purpose = KeyPurpose::Signature
    );
    crypto::CryptoType Algorithm() const { return algorithm; }
    const crypto::PublicKey& public_key() const { return *publick_key; }
};

}
