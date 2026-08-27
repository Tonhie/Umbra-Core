#include "crypto/elgamal_engine.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

namespace {

std::string read_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("failed to open input file: " + path.string());
    }

    return std::string(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );
}

void write_file(const std::filesystem::path& path, const std::string& content) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("failed to open output file: " + path.string());
    }

    file.write(content.data(), static_cast<std::streamsize>(content.size()));
}

bool files_equal(const std::filesystem::path& left, const std::filesystem::path& right) {
    return read_file(left) == read_file(right);
}

int expect_file_round_trip(
    umbra::crypto::EncryptionEngine& engine,
    const umbra::crypto::Keypair& keypair,
    const std::filesystem::path& plaintext_path,
    const std::filesystem::path& output_dir
) {
    const std::string plaintext = read_file(plaintext_path);
    const std::string ciphertext =
        engine.encrypt(plaintext, *keypair.public_key);
    const std::string decrypted =
        engine.decrypt(ciphertext, *keypair.private_key);

    const std::filesystem::path ciphertext_path =
        output_dir / (plaintext_path.filename().string() + ".ciphertext");
    const std::filesystem::path decrypted_path =
        output_dir / (plaintext_path.filename().string() + ".decrypted");

    write_file(ciphertext_path, ciphertext);
    write_file(decrypted_path, decrypted);

    if (!files_equal(plaintext_path, decrypted_path)) {
        std::cerr << "ElGamal file comparison failed\n"
                  << "expected: " << plaintext_path << '\n'
                  << "actual:   " << decrypted_path << '\n';
        return 1;
    }

    std::cout << "ElGamal file comparison passed: " << plaintext_path.filename().string() << '\n'
              << "ciphertext: " << ciphertext_path << '\n'
              << "decrypted:  " << decrypted_path << '\n';
    return 0;
}

} // namespace

int main() {
    const std::filesystem::path fixture_dir =
        std::filesystem::path(UMBRA_SOURCE_DIR) / "tests" / "crypto" / "fixtures";
    const std::filesystem::path output_dir =
        std::filesystem::path(UMBRA_BINARY_DIR) / "test_outputs" / "crypto" / "elgamal_engine";
    std::filesystem::create_directories(output_dir);

    auto engine = umbra::crypto::create_encryption_engine(umbra::crypto::CryptoType::Elgamal);
    auto signer = umbra::crypto::create_signature_engine(umbra::crypto::CryptoType::Elgamal);

    auto keypair = engine->generate_keypair(256);
    const std::vector<std::filesystem::path> plaintext_files = {
        fixture_dir / "elgamal_plaintext.txt",
    };

    for (const auto& plaintext_file : plaintext_files) {
        if (expect_file_round_trip(*engine, keypair, plaintext_file, output_dir) != 0) {
            return 1;
        }
    }

    std::cout << "ElGamal engine file tests passed\n";

    // --- Signature tests ---

    std::cout << "\nRunning ElGamal signature tests...\n";

    const std::string message = "The quick brown fox jumps over the lazy dog";
    const std::string signature =
        signer->sign(message, *keypair.private_key);

    // Round-trip: valid signature must verify
    if (!signer->verify(message, signature, *keypair.public_key)) {
        std::cerr << "FAIL: valid signature did not verify\n";
        return 1;
    }
    std::cout << "PASS: sign + verify round-trip\n";

    // Tampered message must not verify
    const std::string tampered = message + "!";
    if (signer->verify(tampered, signature, *keypair.public_key)) {
        std::cerr << "FAIL: tampered message incorrectly verified\n";
        return 1;
    }
    std::cout << "PASS: tampered message rejected\n";

    // Wrong signature must not verify
    const std::string other_sig =
        signer->sign("some other message", *keypair.private_key);
    if (signer->verify(message, other_sig, *keypair.public_key)) {
        std::cerr << "FAIL: wrong signature incorrectly verified\n";
        return 1;
    }
    std::cout << "PASS: wrong signature rejected\n";

    // Wrong key must not verify
    const auto other_keypair = engine->generate_keypair(256);
    if (signer->verify(message, signature, *other_keypair.public_key)) {
        std::cerr << "FAIL: wrong key incorrectly verified\n";
        return 1;
    }
    std::cout << "PASS: wrong key rejected\n";

    std::cout << "\nElGamal signature tests passed\n";
    return 0;
}
