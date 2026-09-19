#ifndef NODE_POWHASH_PEARL_BLAKE3_H
#define NODE_POWHASH_PEARL_BLAKE3_H

// Portable BLAKE3 primitives used by the Pearl V3 verifier.
// The compression layout follows the public-domain BLAKE3 reference C API
// (BLAKE3 1.3.x).  Pearl uses keyed mode for all Merkle/commitment hashes.

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace pearl_blake3 {

using Hash = std::array<uint8_t, 32>;

constexpr size_t BLOCK_LEN = 64;
constexpr size_t CHUNK_LEN = 1024;

constexpr uint32_t CHUNK_START = 1;
constexpr uint32_t CHUNK_END = 2;
constexpr uint32_t PARENT = 4;
constexpr uint32_t ROOT = 8;
constexpr uint32_t KEYED_HASH = 16;

Hash hash(const uint8_t* data, size_t length);
Hash keyed_hash(const uint8_t* data, size_t length, const Hash& key);

Hash chunk_cv(const uint8_t* data, size_t length, uint64_t chunk_index, const Hash& key);
Hash parent_cv(const Hash& left, const Hash& right, const Hash& key, bool root);

inline Hash hash(const std::vector<uint8_t>& data) {
    return hash(data.data(), data.size());
}

inline Hash keyed_hash(const std::vector<uint8_t>& data, const Hash& key) {
    return keyed_hash(data.data(), data.size(), key);
}

} // namespace pearl_blake3

#endif
