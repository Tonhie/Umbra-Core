#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace umbra::hash {

/**
 * Convenience functions – one-shot SHA-256 over an entire message.
 * Returns the raw 32-byte digest.
 */
std::string sha256(const std::string& message);

/** As sha256() but returns a std::array. */
std::array<uint8_t, 32> sha256_raw(const std::string& message);

/** As sha256() but returns a lowercase 64-char hex string. */
std::string sha256_hex(const std::string& message);

/**
 * Streaming SHA-256 (FIPS 180-4).
 *
 * Supports incremental update() calls followed by a final digest().
 * Call reset() to reuse the instance for a new message.
 */
class Sha256 {
public:
    Sha256() { reset(); }

    Sha256& update(const uint8_t* data, size_t len);
    Sha256& update(const std::string& data);

    /** Returns the 32-byte digest as a std::string. */
    std::string digest();
    /** Returns the 32-byte digest as a std::array. */
    std::array<uint8_t, 32> digest_raw();
    /** Returns the digest as a lowercase 64-char hex string. */
    std::string digest_hex();

    /** Resets the internal state for a new message. */
    void reset();

private:
    void transform(const uint8_t* chunk);  // processes one 64-byte block

    std::array<uint32_t, 8> h_;    // current hash value (H0…H7)
    std::array<uint8_t, 64> buf_;  // partial block buffer
    uint64_t total_;               // total bytes fed so far
    size_t buf_len_;               // bytes used in buf_
};

} // namespace umbra::hash
