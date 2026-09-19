#include "pearl_blake3.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

namespace pearl_blake3 {
namespace {

constexpr std::array<uint32_t, 8> IV = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
};

constexpr std::array<size_t, 16> MSG_PERMUTATION = {
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
};

uint32_t load32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

void store32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

inline uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32u - n));
}

void g(uint32_t* s, size_t a, size_t b, size_t c, size_t d, uint32_t mx, uint32_t my) {
    s[a] = s[a] + s[b] + mx;
    s[d] = rotr32(s[d] ^ s[a], 16);
    s[c] += s[d];
    s[b] = rotr32(s[b] ^ s[c], 12);
    s[a] = s[a] + s[b] + my;
    s[d] = rotr32(s[d] ^ s[a], 8);
    s[c] += s[d];
    s[b] = rotr32(s[b] ^ s[c], 7);
}

void round(uint32_t* s, const uint32_t* m, const std::array<size_t, 16>& schedule) {
    g(s, 0, 4, 8, 12, m[schedule[0]], m[schedule[1]]);
    g(s, 1, 5, 9, 13, m[schedule[2]], m[schedule[3]]);
    g(s, 2, 6, 10, 14, m[schedule[4]], m[schedule[5]]);
    g(s, 3, 7, 11, 15, m[schedule[6]], m[schedule[7]]);
    g(s, 0, 5, 10, 15, m[schedule[8]], m[schedule[9]]);
    g(s, 1, 6, 11, 12, m[schedule[10]], m[schedule[11]]);
    g(s, 2, 7, 8, 13, m[schedule[12]], m[schedule[13]]);
    g(s, 3, 4, 9, 14, m[schedule[14]], m[schedule[15]]);
}

std::array<uint32_t, 16> compress(const std::array<uint32_t, 8>& cv,
                                  const std::array<uint32_t, 16>& message,
                                  uint64_t counter,
                                  uint32_t block_len,
                                  uint32_t flags) {
    std::array<uint32_t, 16> s = {
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
        IV[0], IV[1], IV[2], IV[3],
        static_cast<uint32_t>(counter), static_cast<uint32_t>(counter >> 32),
        block_len, flags
    };

    std::array<size_t, 16> schedule{};
    for (size_t i = 0; i < schedule.size(); ++i) schedule[i] = i;
    for (size_t r = 0; r < 7; ++r) {
        round(s.data(), message.data(), schedule);
        if (r != 6) {
            std::array<size_t, 16> next{};
            for (size_t i = 0; i < 16; ++i) next[i] = schedule[MSG_PERMUTATION[i]];
            schedule = next;
        }
    }

    for (size_t i = 0; i < 8; ++i) {
        s[i] ^= s[i + 8];
        s[i + 8] ^= cv[i];
    }
    return s;
}

std::array<uint32_t, 8> key_words(const Hash& key) {
    std::array<uint32_t, 8> words{};
    for (size_t i = 0; i < words.size(); ++i) words[i] = load32(key.data() + i * 4);
    return words;
}

Hash state_hash(const std::array<uint32_t, 16>& state) {
    Hash out{};
    for (size_t i = 0; i < 8; ++i) store32(out.data() + i * 4, state[i]);
    return out;
}

Hash cv_hash(const std::array<uint32_t, 8>& cv) {
    Hash out{};
    for (size_t i = 0; i < 8; ++i) store32(out.data() + i * 4, cv[i]);
    return out;
}

std::array<uint32_t, 8> state_cv(const std::array<uint32_t, 16>& state) {
    std::array<uint32_t, 8> out{};
    for (size_t i = 0; i < 8; ++i) out[i] = state[i];
    return out;
}

Hash hash_chunk_mode(const uint8_t* data, size_t length, uint64_t chunk_index,
                     const std::array<uint32_t, 8>& cv_key,
                     uint32_t base_flags, bool root) {
    std::array<uint32_t, 8> cv = cv_key;
    const size_t blocks = std::max<size_t>(1, (length + BLOCK_LEN - 1) / BLOCK_LEN);

    for (size_t block = 0; block < blocks; ++block) {
        const size_t offset = block * BLOCK_LEN;
        const size_t block_len = offset < length ? std::min(BLOCK_LEN, length - offset) : 0;
        std::array<uint8_t, BLOCK_LEN> block_bytes{};
        if (block_len != 0) std::memcpy(block_bytes.data(), data + offset, block_len);
        std::array<uint32_t, 16> message{};
        for (size_t i = 0; i < message.size(); ++i) message[i] = load32(block_bytes.data() + i * 4);

        uint32_t flags = base_flags;
        if (block == 0) flags |= CHUNK_START;
        if (block + 1 == blocks) flags |= CHUNK_END;
        if (root && block + 1 == blocks) flags |= ROOT;
        const auto state = compress(cv, message, chunk_index, static_cast<uint32_t>(block_len), flags);
        cv = state_cv(state);
        if (root && block + 1 == blocks) return state_hash(state);
    }
    return cv_hash(cv);
}

Hash parent_mode(const Hash& left, const Hash& right,
                 const std::array<uint32_t, 8>& cv_key,
                 uint32_t base_flags, bool root) {
    std::array<uint8_t, BLOCK_LEN> message{};
    std::memcpy(message.data(), left.data(), 32);
    std::memcpy(message.data() + 32, right.data(), 32);
    std::array<uint32_t, 16> words{};
    for (size_t i = 0; i < 16; ++i) words[i] = load32(message.data() + i * 4);
    const auto state = compress(cv_key, words, 0, BLOCK_LEN, base_flags | PARENT | (root ? ROOT : 0));
    return state_hash(state);
}

Hash keyed_hash_impl(const uint8_t* data, size_t length, const Hash& key) {
    const auto cv_key = key_words(key);
    if (length <= CHUNK_LEN) return hash_chunk_mode(data, length, 0, cv_key, KEYED_HASH, true);

    const size_t chunks = (length + CHUNK_LEN - 1) / CHUNK_LEN;
    std::vector<Hash> layer;
    layer.reserve(chunks);
    for (size_t i = 0; i < chunks; ++i) {
        const size_t offset = i * CHUNK_LEN;
        const size_t chunk_len = std::min(CHUNK_LEN, length - offset);
        layer.push_back(hash_chunk_mode(data + offset, chunk_len, i, cv_key, KEYED_HASH, false));
    }
    while (layer.size() > 2) {
        std::vector<Hash> next;
        next.reserve((layer.size() + 1) / 2);
        for (size_t i = 0; i < layer.size(); i += 2) {
            if (i + 1 == layer.size()) next.push_back(layer[i]);
            else next.push_back(parent_mode(layer[i], layer[i + 1], cv_key, KEYED_HASH, false));
        }
        layer.swap(next);
    }
    return parent_mode(layer[0], layer[1], cv_key, KEYED_HASH, true);
}

} // namespace

Hash hash(const uint8_t* data, size_t length) {
    // Unkeyed BLAKE3 uses the IV as the initial chaining value and no mode flag.
    const auto cv_key = IV;
    if (length <= CHUNK_LEN) return hash_chunk_mode(data, length, 0, cv_key, 0, true);
    const size_t chunks = (length + CHUNK_LEN - 1) / CHUNK_LEN;
    std::vector<Hash> layer;
    layer.reserve(chunks);
    for (size_t i = 0; i < chunks; ++i) {
        const size_t offset = i * CHUNK_LEN;
        const size_t chunk_len = std::min(CHUNK_LEN, length - offset);
        layer.push_back(hash_chunk_mode(data + offset, chunk_len, i, cv_key, 0, false));
    }
    while (layer.size() > 2) {
        std::vector<Hash> next;
        next.reserve((layer.size() + 1) / 2);
        for (size_t i = 0; i < layer.size(); i += 2) {
            if (i + 1 == layer.size()) next.push_back(layer[i]);
            else next.push_back(parent_mode(layer[i], layer[i + 1], cv_key, 0, false));
        }
        layer.swap(next);
    }
    return parent_mode(layer[0], layer[1], cv_key, 0, true);
}

Hash keyed_hash(const uint8_t* data, size_t length, const Hash& key) {
    return keyed_hash_impl(data, length, key);
}

Hash chunk_cv(const uint8_t* data, size_t length, uint64_t chunk_index, const Hash& key) {
    return hash_chunk_mode(data, length, chunk_index, key_words(key), KEYED_HASH, false);
}

Hash parent_cv(const Hash& left, const Hash& right, const Hash& key, bool root) {
    return parent_mode(left, right, key_words(key), KEYED_HASH, root);
}

} // namespace pearl_blake3
