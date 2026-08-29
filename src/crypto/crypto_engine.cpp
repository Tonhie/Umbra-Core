#include "crypto_engine.h"
#include "rsa_engine.h"
#include "elgamal_engine.h"

namespace umbra::crypto {
    
std::unique_ptr<EncryptionEngine> create_encryption_engine(CryptoType type) {
    switch (type) {
    case CryptoType::RSA:
        return std::make_unique<rsa::EncryptionEngine>();

    case CryptoType::Elgamal:
        return std::make_unique<elgamal::EncryptionEngine>();
    }

    throw std::invalid_argument("unsupported crypto type");
}

std::unique_ptr<SignatureEngine> create_signature_engine(CryptoType type) {
    switch (type) {
    case CryptoType::RSA:
        return std::make_unique<rsa::SignatureEngine>();

    case CryptoType::Elgamal:
        return std::make_unique<elgamal::SignatureEngine>();
    }

    throw std::invalid_argument("unsupported crypto type");
}

}