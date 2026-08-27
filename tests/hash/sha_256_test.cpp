#include "hash/sha_256.h"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

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

int test_convenience_functions() {
    const std::string input = "abc";

    const std::string expected_hex =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    std::string result_hex = umbra::hash::sha256_hex(input);
    if (result_hex != expected_hex) {
        std::cerr << "SHA-256 hex mismatch\n"
                  << "expected: " << expected_hex << '\n'
                  << "got:      " << result_hex << '\n';
        return 1;
    }
    std::cout << "SHA-256 hex (\"abc\") passed\n";

    auto raw = umbra::hash::sha256_raw(input);
    std::string binary = umbra::hash::sha256(input);
    if (binary.size() != 32 || std::memcmp(raw.data(), binary.data(), 32) != 0) {
        std::cerr << "SHA-256 raw/binary mismatch\n";
        return 1;
    }
    std::cout << "SHA-256 raw/binary consistency passed\n";

    return 0;
}

int test_streaming_equivalent() {
    const std::string input = "The quick brown fox jumps over the lazy dog";

    std::string one_shot = umbra::hash::sha256_hex(input);

    umbra::hash::Sha256 hasher;
    hasher.update("The quick brown fox");
    hasher.update(" jumps over the lazy dog");
    std::string streaming = hasher.digest_hex();

    if (one_shot != streaming) {
        std::cerr << "SHA-256 streaming mismatch\n"
                  << "one-shot:  " << one_shot << '\n'
                  << "streaming: " << streaming << '\n';
        return 1;
    }
    std::cout << "SHA-256 streaming consistency passed\n";

    return 0;
}

int test_empty() {
    const std::string expected =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    std::string result = umbra::hash::sha256_hex("");
    if (result != expected) {
        std::cerr << "SHA-256 empty string mismatch\n"
                  << "expected: " << expected << '\n'
                  << "got:      " << result << '\n';
        return 1;
    }
    std::cout << "SHA-256 empty string passed\n";
    return 0;
}

int test_reset() {
    umbra::hash::Sha256 h;
    h.update("hello");
    std::string first = h.digest_hex();

    h.reset();
    h.update("hello");
    std::string second = h.digest_hex();

    if (first != second) {
        std::cerr << "SHA-256 reset mismatch\n";
        return 1;
    }
    std::cout << "SHA-256 reset passed\n";
    return 0;
}

int test_long_message() {
    std::string input(10000, 'A');
    std::string result = umbra::hash::sha256_hex(input);
    if (result.size() != 64) {
        std::cerr << "SHA-256 long message bad output length\n";
        return 1;
    }
    std::cout << "SHA-256 long message (" << input.size() << " bytes) passed\n";
    return 0;
}

} // namespace

int main() {
    int failures = 0;

    std::cout << "=== SHA-256 Tests ===\n";

    failures += test_convenience_functions();
    failures += test_streaming_equivalent();
    failures += test_empty();
    failures += test_reset();
    failures += test_long_message();

    if (failures > 0) {
        std::cerr << "\n" << failures << " test(s) FAILED\n";
        return 1;
    }

    std::cout << "\nAll SHA-256 tests PASSED\n";
    return 0;
}
