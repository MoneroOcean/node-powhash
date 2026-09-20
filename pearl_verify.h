#ifndef NODE_POWHASH_PEARL_VERIFY_H
#define NODE_POWHASH_PEARL_VERIFY_H

// Pearl V3 verification semantics are ported from upstream commit
// 5b09d844e4069440933722c51495ac24a7bb4886.

#include "pearl_blake3.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pearl_verify {

// Plain V3 proofs are currently small enough to fit comfortably in the pool's
// synchronous verification path.  This is also a parser allocation boundary;
// encoded input is rejected before it is decoded.
constexpr size_t MAX_PROOF_BYTES = 8u * 1024u * 1024u;
constexpr size_t MAX_BASE64_CHARS = ((MAX_PROOF_BYTES + 2u) / 3u) * 4u;

struct PatternInfo {
    std::array<uint32_t, 3> stride{};
    std::array<uint32_t, 3> length{};
    std::array<uint8_t, 6> bytes{};
    uint32_t count = 0;
    uint32_t maximum = 0;
};

struct ConfigInfo {
    uint32_t m = 0;
    uint32_t n = 0;
    uint32_t k = 0;
    uint16_t rank = 0;
    uint16_t experts = 0;
    uint16_t top_k = 0;
    uint16_t expert_index = 0;
    uint32_t t_rows = 0;
    uint32_t t_cols = 0;
    // Rank-128-equivalent work factor used for the inclusive target check:
    // rows_pattern.count * cols_pattern.count * floor(k / rank) * 128.
    uint32_t adjustment_factor = 0;
    bool moe = false;
    PatternInfo rows_pattern;
    PatternInfo cols_pattern;
};

struct VerifyResult {
    bool valid = false;
    bool full = false;
    bool candidate = false;
    pearl_blake3::Hash jackpot{};
    pearl_blake3::Hash proof_id{};
    std::vector<uint8_t> solution_data;
    ConfigInfo config;
    std::string error;
};

// Verifies a serialized V3 plain proof against a serialized 76-byte header and
// a little-endian, full-width 256-bit base share target.  The target is scaled
// by the authoritative rank-penalized V3 work factor
// (h*w*floor(k/rank)*128).  Overflow of the full-width share-target scaling is
// treated as an unusable target: the proof remains valid, but candidate is
// false rather than saturating to an all-winning bound.  Invalid input returns
// false and never throws through this interface.
bool verify_v3(const uint8_t* header, size_t header_length,
               const uint8_t* proof, size_t proof_length,
               const uint8_t* target, size_t target_length,
               VerifyResult* result);

// Verifies the bounded, public/commitment portion of a V3 proof and returns
// versioned canonical solution data.  This intentionally omits signed-strip
// extraction and the GEMM/jackpot calculation, but shares all parsing, shape,
// configuration, tree-size, keyed-root, and MoE routing checks with verify_v3.
bool prepare_v3(const uint8_t* header, size_t header_length,
                const uint8_t* proof, size_t proof_length,
                VerifyResult* result);

// Strict standard-base64 decoder for the optional JavaScript string form.
// The output is bounded to MAX_PROOF_BYTES and is cleared on failure.
bool decode_base64(const char* encoded, size_t encoded_length,
                   std::string* error, std::vector<uint8_t>* output);

} // namespace pearl_verify

#endif
