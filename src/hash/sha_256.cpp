#include "sha_256.h"

#include <cstring>
#include <iomanip>
#include <sstream>

namespace umbra::hash {

// Round constants – first 32 bits of the fractional parts of the cube roots
// of the first 64 primes.
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// --- SHA-256 logical functions (FIPS 180-4 §4.1.2) ---
static inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static inline uint32_t s0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
static inline uint32_t s1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }
static inline uint32_t S0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
static inline uint32_t S1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }

static inline uint32_t bswap32(uint32_t x) {
    return ((x & 0xff000000) >> 24) | ((x & 0x00ff0000) >> 8)
         | ((x & 0x0000ff00) << 8)  | ((x & 0x000000ff) << 24);
}

// Initialize with the fractional parts of the square roots of the first 8 primes.
void Sha256::reset() {
    h_ = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    buf_.fill(0);
    total_ = 0;
    buf_len_ = 0;
}

// Core compression function – processes one 512-bit (64-byte) message block.
void Sha256::transform(const uint8_t* chunk) {
    uint32_t w[64];  // message schedule

    // First 16 words: copy chunk in big-endian
    for (int i = 0; i < 16; ++i) {
        const uint8_t* p = chunk + i * 4;
        w[i] = (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16)
             | (static_cast<uint32_t>(p[2]) << 8)  | static_cast<uint32_t>(p[3]);
    }
    // Extend to 64 words via the message schedule recurrence
    for (int i = 16; i < 64; ++i) {
        w[i] = s1(w[i - 2]) + w[i - 7] + s0(w[i - 15]) + w[i - 16];
    }

    uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
    uint32_t e = h_[4], f = h_[5], g = h_[6], hval = h_[7];

    // 64 rounds
    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = hval + S1(e) + ch(e, f, g) + K[i] + w[i];
        uint32_t t2 = S0(a) + maj(a, b, c);
        hval = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    // Davies-Meyer feed-forward
    h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
    h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += hval;
}

Sha256& Sha256::update(const uint8_t* data, size_t len) {
    total_ += len;
    while (len > 0) {
        size_t space = 64 - buf_len_;
        size_t take = len < space ? len : space;
        std::memcpy(buf_.data() + buf_len_, data, take);
        buf_len_ += take;
        data += take;
        len -= take;
        // Fire the compression function whenever a full block is ready
        if (buf_len_ == 64) {
            transform(buf_.data());
            buf_len_ = 0;
        }
    }
    return *this;
}

Sha256& Sha256::update(const std::string& data) {
    return update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

std::array<uint8_t, 32> Sha256::digest_raw() {
    // Merkle-Damgård padding: append 1 bit, then zeros, then 64-bit length in bits
    uint64_t bits = total_ * 8;
    buf_[buf_len_++] = 0x80;        // 1 bit (followed by zeros)
    if (buf_len_ > 56) {            // no room for length – pad current block & start fresh
        std::memset(buf_.data() + buf_len_, 0, 64 - buf_len_);
        transform(buf_.data());
        buf_len_ = 0;
    }
    std::memset(buf_.data() + buf_len_, 0, 56 - buf_len_);
    // Append 64-bit message length (big-endian)
    for (int i = 0; i < 8; ++i) {
        buf_[56 + i] = static_cast<uint8_t>(bits >> (56 - i * 8));
    }
    transform(buf_.data());

    std::array<uint8_t, 32> out;
    for (int i = 0; i < 8; ++i) {
        out[i * 4 + 0] = static_cast<uint8_t>(h_[i] >> 24);
        out[i * 4 + 1] = static_cast<uint8_t>(h_[i] >> 16);
        out[i * 4 + 2] = static_cast<uint8_t>(h_[i] >> 8);
        out[i * 4 + 3] = static_cast<uint8_t>(h_[i]);
    }
    return out;
}

std::string Sha256::digest() {
    auto raw = digest_raw();
    return std::string(reinterpret_cast<char*>(raw.data()), raw.size());
}

std::string Sha256::digest_hex() {
    auto raw = digest_raw();
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto b : raw) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

std::string sha256(const std::string& message) {
    return Sha256().update(message).digest();
}

std::array<uint8_t, 32> sha256_raw(const std::string& message) {
    return Sha256().update(message).digest_raw();
}

std::string sha256_hex(const std::string& message) {
    return Sha256().update(message).digest_hex();
}

} // namespace umbra::hash
