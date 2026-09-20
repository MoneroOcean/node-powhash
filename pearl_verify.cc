#include "pearl_verify.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <exception>
#include <limits>
#include <utility>
#include <vector>

namespace pearl_verify {
namespace {

using pearl_blake3::Hash;

constexpr uint64_t CHUNK = pearl_blake3::CHUNK_LEN;
constexpr uint64_t MAX_VECTOR_ITEMS = MAX_PROOF_BYTES;
constexpr uint64_t MAX_PATTERN_ITEMS = 256;
constexpr uint64_t MAX_EXPERTS = 1024;
constexpr uint64_t MAX_M = 1u << 24;
constexpr uint64_t MAX_N = 1u << 24;
constexpr uint64_t MAX_K = 1u << 16;

bool same_hash(const Hash& a, const Hash& b) {
    uint8_t different = 0;
    for (size_t i = 0; i < a.size(); ++i) different |= static_cast<uint8_t>(a[i] ^ b[i]);
    return different == 0;
}

bool checked_add_u64(uint64_t a, uint64_t b, uint64_t* out) {
    if (b > std::numeric_limits<uint64_t>::max() - a) return false;
    *out = a + b;
    return true;
}

bool checked_mul_u64(uint64_t a, uint64_t b, uint64_t* out) {
    if (a != 0 && b > std::numeric_limits<uint64_t>::max() / a) return false;
    *out = a * b;
    return true;
}

bool padded_bytes(uint64_t raw, uint64_t* out) {
    if (raw == 0) {
        *out = 0;
        return true;
    }
    uint64_t with_rounding = 0;
    if (!checked_add_u64(raw, CHUNK - 1, &with_rounding)) return false;
    *out = (with_rounding / CHUNK) * CHUNK;
    return true;
}

class Reader {
public:
    Reader(const uint8_t* data, size_t length) : data_(data), length_(length) {}

    size_t remaining() const { return length_ - position_; }
    size_t position() const { return position_; }
    const std::string& error() const { return error_; }

    bool read_u8(uint8_t* out) {
        if (remaining() < 1) return fail("truncated byte");
        *out = data_[position_++];
        return true;
    }

    bool read_u16(uint16_t* out) {
        if (remaining() < 2) return fail("truncated u16");
        *out = static_cast<uint16_t>(data_[position_]) |
               static_cast<uint16_t>(data_[position_ + 1]) << 8;
        position_ += 2;
        return true;
    }

    bool read_u32(uint32_t* out) {
        if (remaining() < 4) return fail("truncated u32");
        *out = static_cast<uint32_t>(data_[position_]) |
               static_cast<uint32_t>(data_[position_ + 1]) << 8 |
               static_cast<uint32_t>(data_[position_ + 2]) << 16 |
               static_cast<uint32_t>(data_[position_ + 3]) << 24;
        position_ += 4;
        return true;
    }

    bool read_u64(uint64_t* out) {
        if (remaining() < 8) return fail("truncated u64");
        uint64_t value = 0;
        for (unsigned i = 0; i < 8; ++i) value |= static_cast<uint64_t>(data_[position_ + i]) << (8 * i);
        position_ += 8;
        *out = value;
        return true;
    }

    bool read_bytes(uint8_t* out, size_t count) {
        if (count > remaining()) return fail("truncated byte array");
        if (count != 0) std::memcpy(out, data_ + position_, count);
        position_ += count;
        return true;
    }

    bool read_hash(Hash* out) { return read_bytes(out->data(), out->size()); }

    bool fail(const char* message) {
        if (error_.empty()) error_ = message;
        return false;
    }

private:
    const uint8_t* data_;
    size_t length_;
    size_t position_ = 0;
    std::string error_;
};

struct Merkle {
    std::vector<std::array<uint8_t, pearl_blake3::CHUNK_LEN>> leaves;
    std::vector<uint64_t> leaf_indices;
    uint64_t total_leaves = 0;
    Hash root{};
    std::vector<Hash> siblings;
};

struct MatrixProof {
    Merkle proof;
    std::vector<uint64_t> rows;
};

struct MoeProof {
    uint64_t experts = 0;
    uint64_t top_k = 0;
    uint16_t expert_index = 0;
    std::vector<uint32_t> routing_offsets;
    std::vector<uint64_t> inner_a_rows;
    Merkle routing;
};

struct PlainProof {
    uint64_t m = 0;
    uint64_t n = 0;
    uint64_t k = 0;
    uint64_t noise_rank = 0;
    MatrixProof a;
    MatrixProof bt;
    bool has_moe = false;
    MoeProof moe;
    bool legacy_dense = false;
};

struct PreparedProof {
    PlainProof proof;
    ConfigInfo config;
    Hash job_key{};
    Hash root_a{};
    Hash root_b{};
    Hash root_routing{};
    Hash solution_id{};
    uint64_t total_b_cols = 0;
    uint32_t m = 0;
    uint32_t n = 0;
    uint32_t k = 0;
    uint16_t rank = 0;
};

template <typename T>
bool start_vector(Reader* reader, uint64_t* count, size_t item_size, const char* label) {
    if (!reader->read_u64(count)) return false;
    if (*count > MAX_VECTOR_ITEMS || (*count != 0 && item_size > reader->remaining() / *count)) {
        return reader->fail(label);
    }
    return true;
}

bool read_hash_vector(Reader* reader, std::vector<Hash>* output, const char* label) {
    uint64_t count = 0;
    if (!start_vector<Hash>(reader, &count, sizeof(Hash), label)) return false;
    output->clear();
    output->reserve(static_cast<size_t>(count));
    for (uint64_t i = 0; i < count; ++i) {
        Hash value{};
        if (!reader->read_hash(&value)) return false;
        output->push_back(value);
    }
    return true;
}

bool read_u64_vector(Reader* reader, std::vector<uint64_t>* output, const char* label) {
    uint64_t count = 0;
    if (!start_vector<uint64_t>(reader, &count, sizeof(uint64_t), label)) return false;
    output->clear();
    output->reserve(static_cast<size_t>(count));
    for (uint64_t i = 0; i < count; ++i) {
        uint64_t value = 0;
        if (!reader->read_u64(&value)) return false;
        output->push_back(value);
    }
    return true;
}

bool read_u32_vector(Reader* reader, std::vector<uint32_t>* output, const char* label) {
    uint64_t count = 0;
    if (!start_vector<uint32_t>(reader, &count, sizeof(uint32_t), label)) return false;
    output->clear();
    output->reserve(static_cast<size_t>(count));
    for (uint64_t i = 0; i < count; ++i) {
        uint32_t value = 0;
        if (!reader->read_u32(&value)) return false;
        output->push_back(value);
    }
    return true;
}

bool read_leaf_vector(Reader* reader,
                      std::vector<std::array<uint8_t, pearl_blake3::CHUNK_LEN>>* output,
                      const char* label) {
    uint64_t count = 0;
    if (!start_vector<std::array<uint8_t, pearl_blake3::CHUNK_LEN>>(
            reader, &count, pearl_blake3::CHUNK_LEN, label)) return false;
    output->clear();
    output->reserve(static_cast<size_t>(count));
    for (uint64_t i = 0; i < count; ++i) {
        // Upstream serde_chunk_vec encodes each fixed chunk as a byte slice.
        uint64_t length = 0;
        if (!reader->read_u64(&length)) return false;
        if (length != pearl_blake3::CHUNK_LEN) {
            return reader->fail("leaf_data item is not a 1024-byte BLAKE3 chunk");
        }
        std::array<uint8_t, pearl_blake3::CHUNK_LEN> value{};
        if (!reader->read_bytes(value.data(), value.size())) return false;
        output->push_back(value);
    }
    return true;
}

bool read_merkle(Reader* reader, Merkle* output) {
    if (!read_leaf_vector(reader, &output->leaves, "leaf_data length exceeds proof bounds")) return false;
    if (!read_u64_vector(reader, &output->leaf_indices, "leaf_indices length exceeds proof bounds")) return false;
    if (!reader->read_u64(&output->total_leaves)) return false;
    if (!reader->read_hash(&output->root)) return false;
    if (!read_hash_vector(reader, &output->siblings, "siblings length exceeds proof bounds")) return false;
    return true;
}

bool read_matrix(Reader* reader, MatrixProof* output) {
    if (!read_merkle(reader, &output->proof)) return false;
    return read_u64_vector(reader, &output->rows, "row_indices length exceeds proof bounds");
}

bool parse_plain(const uint8_t* data, size_t length, PlainProof* output, bool* legacy, std::string* error) {
    if (data == nullptr || length == 0 || length > MAX_PROOF_BYTES) {
        *error = "proof length is outside the bounded V3 range";
        return false;
    }
    Reader reader(data, length);
    if (!reader.read_u64(&output->m) || !reader.read_u64(&output->n) ||
        !reader.read_u64(&output->k) || !reader.read_u64(&output->noise_rank) ||
        !read_matrix(&reader, &output->a) || !read_matrix(&reader, &output->bt)) {
        *error = reader.error();
        return false;
    }

    output->has_moe = false;
    output->legacy_dense = false;
    if (reader.remaining() == 0) {
        // V1 dense blobs omitted the trailing serde Option tag.  V3 keeps this
        // compatibility accepted, but the canonical identity appends 0x00.
        output->legacy_dense = true;
        *legacy = true;
        return true;
    }

    uint8_t option_tag = 0;
    if (!reader.read_u8(&option_tag)) {
        *error = reader.error();
        return false;
    }
    if (option_tag == 0) {
        output->has_moe = false;
    } else if (option_tag == 1) {
        output->has_moe = true;
        if (!reader.read_u64(&output->moe.experts) || !reader.read_u64(&output->moe.top_k) ||
            !reader.read_u16(&output->moe.expert_index) ||
            !read_u32_vector(&reader, &output->moe.routing_offsets, "routing offsets length exceeds proof bounds") ||
            !read_u64_vector(&reader, &output->moe.inner_a_rows, "inner A rows length exceeds proof bounds") ||
            !read_merkle(&reader, &output->moe.routing)) {
            *error = reader.error();
            return false;
        }
    } else {
        *error = "invalid serde Option tag";
        return false;
    }
    if (reader.remaining() != 0) {
        *error = "trailing bytes after PlainProof";
        return false;
    }
    *legacy = false;
    return true;
}

bool validate_merkle_shape(const Merkle& proof, std::string* error) {
    if (proof.total_leaves == 0) {
        *error = "Merkle proof has no leaves";
        return false;
    }
    if (proof.leaf_indices.empty() || proof.leaf_indices.size() != proof.leaves.size()) {
        *error = "Merkle leaf indices/data are empty or mismatched";
        return false;
    }
    for (size_t i = 0; i < proof.leaf_indices.size(); ++i) {
        if (proof.leaf_indices[i] >= proof.total_leaves) {
            *error = "Merkle leaf index is outside total_leaves";
            return false;
        }
        if (i != 0 && proof.leaf_indices[i - 1] >= proof.leaf_indices[i]) {
            *error = "Merkle leaf indices are not strictly sorted";
            return false;
        }
    }
    return true;
}

struct MerkleNode {
    uint64_t index;
    Hash value;
};

bool compute_merkle_root(const Merkle& proof, const Hash& key, Hash* output, std::string* error) {
    if (!validate_merkle_shape(proof, error)) return false;
    std::vector<MerkleNode> current;
    current.reserve(proof.leaves.size());
    for (size_t i = 0; i < proof.leaves.size(); ++i) {
        current.push_back({proof.leaf_indices[i], pearl_blake3::chunk_cv(
            proof.leaves[i].data(), proof.leaves[i].size(), proof.leaf_indices[i], key)});
    }
    size_t sibling_position = 0;
    uint64_t level_length = proof.total_leaves;
    if (level_length == 1) {
        if (current.size() != 1 || current[0].index != 0 || !proof.siblings.empty()) {
            *error = "invalid single-leaf Merkle proof";
            return false;
        }
        // Pearl's MerkleTree hashes a <=1024-byte tree as a complete keyed
        // BLAKE3 root (including ROOT), rather than exposing the non-root
        // chunk chaining value used for multi-leaf trees.
        *output = pearl_blake3::keyed_hash(
            proof.leaves[0].data(), proof.leaves[0].size(), key);
        return true;
    }

    while (level_length > 2) {
        std::vector<MerkleNode> next;
        next.reserve((current.size() + 1) / 2 + proof.siblings.size());
        for (size_t i = 0; i < current.size(); ++i) {
            const uint64_t index = current[i].index;
            if ((index & 1u) != 0 && i > 0 && current[i - 1].index == index - 1) continue;
            const Hash left = current[i].value;
            Hash right{};
            bool have_right = false;
            if ((index & 1u) == 0) {
                if (i + 1 < current.size() && current[i + 1].index == index + 1) {
                    right = current[i + 1].value;
                    have_right = true;
                } else if (index + 1 < level_length) {
                    if (sibling_position >= proof.siblings.size()) {
                        *error = "Merkle proof is missing a sibling";
                        return false;
                    }
                    right = proof.siblings[sibling_position++];
                    have_right = true;
                }
            } else {
                if (sibling_position >= proof.siblings.size()) {
                    *error = "Merkle proof is missing a left sibling";
                    return false;
                }
                right = left;
                next.push_back({index / 2, pearl_blake3::parent_cv(
                    proof.siblings[sibling_position++], right, key, false)});
                continue;
            }
            if (have_right) {
                next.push_back({index / 2, pearl_blake3::parent_cv(left, right, key, false)});
            } else {
                next.push_back({index / 2, left});
            }
        }
        current.swap(next);
        // Avoid overflowing level_length + 1 for hostile wire values.
        level_length = level_length / 2 + level_length % 2;
    }

    Hash left{};
    Hash right{};
    bool have_left = false;
    bool have_right = false;
    for (const auto& node : current) {
        if (node.index == 0) {
            left = node.value;
            have_left = true;
        } else if (node.index == 1) {
            right = node.value;
            have_right = true;
        } else {
            *error = "Merkle level has an invalid node index";
            return false;
        }
    }
    if (!have_left) {
        if (sibling_position >= proof.siblings.size()) {
            *error = "Merkle proof is missing the final left node";
            return false;
        }
        left = proof.siblings[sibling_position++];
    }
    if (!have_right) {
        if (sibling_position >= proof.siblings.size()) {
            *error = "Merkle proof is missing the final right node";
            return false;
        }
        right = proof.siblings[sibling_position++];
    }
    if (sibling_position != proof.siblings.size()) {
        *error = "Merkle proof has trailing siblings (consumed " +
                std::to_string(sibling_position) + " of " +
                std::to_string(proof.siblings.size()) + ")";
        return false;
    }
    *output = pearl_blake3::parent_cv(left, right, key, true);
    return true;
}

bool extract_bytes(const Merkle& proof, uint64_t total_bytes, uint64_t start,
                   size_t length, std::vector<uint8_t>* output, std::string* error) {
    uint64_t end = 0;
    if (!checked_add_u64(start, static_cast<uint64_t>(length), &end) || end > total_bytes) {
        *error = "requested bytes exceed the committed matrix";
        return false;
    }
    output->assign(length, 0);
    size_t copied = 0;
    for (size_t i = 0; i < proof.leaf_indices.size(); ++i) {
        uint64_t leaf_start = 0;
        if (!checked_mul_u64(proof.leaf_indices[i], CHUNK, &leaf_start)) {
            *error = "Merkle leaf byte offset overflow";
            return false;
        }
        uint64_t leaf_end = 0;
        if (!checked_add_u64(leaf_start, CHUNK, &leaf_end)) {
            *error = "Merkle leaf byte end overflow";
            return false;
        }
        if (leaf_start >= end) break;
        if (start >= leaf_end) continue;
        const uint64_t copy_start = std::max(start, leaf_start);
        const uint64_t copy_end = std::min(end, leaf_end);
        const size_t count = static_cast<size_t>(copy_end - copy_start);
        const size_t output_offset = static_cast<size_t>(copy_start - start);
        const size_t leaf_offset = static_cast<size_t>(copy_start - leaf_start);
        std::memcpy(output->data() + output_offset, proof.leaves[i].data() + leaf_offset, count);
        copied += count;
    }
    if (copied != length) {
        *error = "Merkle proof does not cover the requested bytes";
        return false;
    }
    return true;
}

bool pattern_from_list(const std::vector<uint64_t>& input, PatternInfo* output,
                       uint32_t* offset, std::string* error) {
    if (input.empty() || input.size() > MAX_PATTERN_ITEMS) {
        *error = "pattern has an unsupported number of indices";
        return false;
    }
    std::vector<uint32_t> normalized;
    normalized.reserve(input.size());
    uint64_t first = input[0];
    if (first > std::numeric_limits<uint32_t>::max()) {
        *error = "pattern offset exceeds u32";
        return false;
    }
    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] > std::numeric_limits<uint32_t>::max() ||
            (i != 0 && input[i - 1] >= input[i])) {
            *error = "pattern indices are not sorted u32 values";
            return false;
        }
        normalized.push_back(static_cast<uint32_t>(input[i] - first));
    }
    if (normalized[0] != 0) {
        *error = "pattern does not start at zero after normalization";
        return false;
    }

    std::vector<std::pair<uint32_t, uint32_t>> shapes;
    std::vector<uint32_t> p = normalized;
    while (p.size() > 1) {
        bool found = false;
        for (size_t period = 1; period < p.size(); ++period) {
            if (p.size() % period != 0) continue;
            const uint32_t stride = p[period];
            bool periodic = true;
            for (size_t i = 0; i + period < p.size(); ++i) {
                if (static_cast<uint64_t>(p[i]) + stride != p[i + period]) {
                    periodic = false;
                    break;
                }
            }
            if (periodic) {
                shapes.emplace_back(stride, static_cast<uint32_t>(p.size() / period));
                p.resize(period);
                found = true;
                break;
            }
        }
        if (!found) {
            *error = "pattern is not periodic";
            return false;
        }
    }
    if (shapes.size() > 3) {
        *error = "pattern needs more than three dimensions";
        return false;
    }
    std::reverse(shapes.begin(), shapes.end());
    uint64_t period = shapes.empty() ? 1 : static_cast<uint64_t>(shapes.back().first) * shapes.back().second;
    while (shapes.size() < 3) {
        if (period > std::numeric_limits<uint32_t>::max()) {
            *error = "pattern period overflows u32";
            return false;
        }
        shapes.emplace_back(static_cast<uint32_t>(period), 1);
    }

    uint64_t min_stride = 1;
    bool is_done = false;
    uint64_t count = 1;
    for (size_t i = 0; i < 3; ++i) {
        const uint64_t stride = shapes[i].first;
        const uint64_t length = shapes[i].second;
        if (stride == 0 || length == 0 || stride % min_stride != 0) {
            *error = "pattern contains an invalid stride";
            return false;
        }
        const uint64_t factor = stride / min_stride;
        if (factor == 0 || factor > 256 || length > 256 ||
            min_stride > (1u << 24) / (factor * length)) {
            *error = "pattern exceeds canonical bounds";
            return false;
        }
        if (length == 1 || is_done) {
            if (factor != 1 || length != 1) {
                *error = "pattern has a non-canonical trailing dimension";
                return false;
            }
            is_done = true;
        } else if (factor == 1 && min_stride != 1) {
            *error = "pattern splits a single stride";
            return false;
        }
        output->stride[i] = static_cast<uint32_t>(stride);
        output->length[i] = static_cast<uint32_t>(length);
        output->bytes[2 * i] = static_cast<uint8_t>(factor - 1);
        output->bytes[2 * i + 1] = static_cast<uint8_t>(length - 1);
        if (!checked_mul_u64(count, length, &count) || count > MAX_PATTERN_ITEMS) {
            *error = "pattern has too many indices";
            return false;
        }
        if (!checked_mul_u64(min_stride, factor * length, &min_stride)) {
            *error = "pattern stride overflow";
            return false;
        }
    }
    if (count != input.size()) {
        *error = "pattern shape does not round-trip its index count";
        return false;
    }
    output->count = static_cast<uint32_t>(count);
    output->maximum = normalized.back();
    *offset = static_cast<uint32_t>(first);

    // This is the inverse of PeriodicPattern::to_list and also checks that
    // the generated sequence is exactly the source sequence.
    std::vector<uint32_t> generated(1, 0);
    for (size_t i = 0; i < 3; ++i) {
        std::vector<uint32_t> next;
        next.reserve(generated.size() * output->length[i]);
        for (uint32_t j = 0; j < output->length[i]; ++j) {
            for (uint32_t value : generated) {
                const uint64_t candidate = static_cast<uint64_t>(value) +
                                           static_cast<uint64_t>(j) * output->stride[i];
                if (candidate > std::numeric_limits<uint32_t>::max()) {
                    *error = "pattern index overflows u32";
                    return false;
                }
                next.push_back(static_cast<uint32_t>(candidate));
            }
        }
        generated.swap(next);
    }
    if (generated != normalized) {
        *error = "pattern is not canonical";
        return false;
    }
    return true;
}

bool offset_is_valid(const PatternInfo& pattern, uint32_t offset) {
    for (size_t i = pattern.stride.size(); i-- > 0;) {
        const uint64_t period = static_cast<uint64_t>(pattern.stride[i]) * pattern.length[i];
        if (period == 0) return false;
        offset = static_cast<uint32_t>(offset % period);
        if (offset >= pattern.stride[i]) return false;
    }
    return true;
}

bool expected_leaves(uint64_t rows, uint64_t cols, uint64_t* output) {
    uint64_t bytes = 0;
    uint64_t padded = 0;
    if (!checked_mul_u64(rows, cols, &bytes) || !padded_bytes(bytes, &padded)) return false;
    *output = padded / CHUNK;
    return true;
}

bool check_tree_size(const Merkle& proof, uint64_t expected, const char* label, std::string* error) {
    if (proof.total_leaves != expected) {
        *error = std::string(label) + " Merkle total_leaves does not match dimensions";
        return false;
    }
    return validate_merkle_shape(proof, error);
}

bool u32_from_u64(uint64_t value, uint32_t* out, const char* label, std::string* error) {
    if (value > std::numeric_limits<uint32_t>::max()) {
        *error = label;
        return false;
    }
    *out = static_cast<uint32_t>(value);
    return true;
}

bool sanity_check(const PlainProof& proof, const PatternInfo& rows, uint32_t t_rows,
                  const PatternInfo& cols, uint32_t t_cols, uint32_t total_b_cols,
                  std::string* error) {
    const uint64_t m = proof.m;
    const uint64_t n = proof.n;
    const uint64_t k = proof.k;
    const uint64_t rank = proof.noise_rank;
    const uint64_t h = rows.count;
    const uint64_t w = cols.count;
    // The production V3 softfork applies the rank work-factor rule only to
    // ranks at or above the 128 baseline.  Keep the upstream shape checks too.
    if (m > MAX_M || n > MAX_N || k > MAX_K || rank < 128 || rank > 1024 ||
        (rank & (rank - 1)) != 0 || rank % 16 != 0) {
        *error = "V3 dimensions or noise rank are outside public bounds";
        return false;
    }
    if (k % 64 != 0 || k < 1024 || k < 16 * rank || k > 4 * rank * rank) {
        *error = "V3 common dimension/rank constraints failed";
        return false;
    }
    const uint64_t dot = k - (k % rank);
    if (dot % 8 != 0 || h % 2 != 0 || w % 2 != 0 || h * w < 32 || h * w > 256) {
        *error = "V3 tile or dot-product constraints failed";
        return false;
    }
    if ((h + w) * dot > (1u << 22)) {
        *error = "V3 worker input bound exceeded";
        return false;
    }
    if (static_cast<uint64_t>(t_rows) + rows.maximum >= m ||
        static_cast<uint64_t>(t_cols) + cols.maximum >= n ||
        m == 0 || n == 0) {
        *error = "V3 pattern offset exceeds matrix dimensions";
        return false;
    }
    if (!proof.has_moe) return true;

    const MoeProof& moe = proof.moe;
    if (moe.experts == 0 || moe.top_k == 0 || moe.experts > MAX_EXPERTS ||
        moe.top_k >= moe.experts || moe.expert_index >= moe.experts ||
        moe.routing_offsets.size() != moe.experts ||
        proof.bt.rows.size() >= proof.n ||
        static_cast<uint64_t>(proof.n) * moe.experts > MAX_N) {
        *error = "MoE public configuration constraints failed";
        return false;
    }
    uint64_t routing_entries = 0;
    if (!checked_mul_u64(m, moe.top_k, &routing_entries) || routing_entries > UINT32_MAX ||
        moe.routing_offsets.empty() || moe.routing_offsets.back() != routing_entries) {
        *error = "MoE routing entry count is invalid";
        return false;
    }
    for (size_t i = 0; i < moe.routing_offsets.size(); ++i) {
        if (i != 0 && moe.routing_offsets[i - 1] > moe.routing_offsets[i]) {
            *error = "MoE routing offsets are not monotonic";
            return false;
        }
        if (moe.routing_offsets[i] > routing_entries ||
            (i != 0 && static_cast<uint64_t>(moe.routing_offsets[i] - moe.routing_offsets[i - 1]) > m) ||
            (i == 0 && moe.routing_offsets[i] > m)) {
            *error = "MoE routing offset exceeds its per-expert bound";
            return false;
        }
    }
    const uint64_t expert_start = moe.expert_index == 0 ? 0 : moe.routing_offsets[moe.expert_index - 1];
    const uint64_t expert_end = moe.routing_offsets[moe.expert_index];
    if (moe.inner_a_rows.size() != proof.a.rows.size() || rows.count != moe.inner_a_rows.size()) {
        *error = "MoE inner and outer A row counts differ";
        return false;
    }
    if (proof.a.rows.size() != rows.count) {
        *error = "A row count does not match rows pattern";
        return false;
    }
    for (size_t i = 0; i < proof.a.rows.size(); ++i) {
        if (proof.a.rows[i] >= m || moe.inner_a_rows[i] >= expert_end - expert_start ||
            expert_start + moe.inner_a_rows[i] >= routing_entries ||
            expert_start + moe.inner_a_rows[i] >= expert_end) {
            *error = "MoE A/routing index is outside the selected expert region";
            return false;
        }
    }
    const uint64_t column_offset = static_cast<uint64_t>(moe.expert_index) * proof.n;
    for (uint64_t index : proof.bt.rows) {
        if (index < column_offset || index >= column_offset + proof.n) {
            *error = "MoE B row is outside the selected expert columns";
            return false;
        }
    }
    if (moe.experts * proof.n > MAX_N) {
        *error = "MoE total columns exceed 24-bit bound";
        return false;
    }
    for (size_t i = 1; i < proof.a.rows.size(); ++i) {
        if (proof.a.rows[i - 1] >= proof.a.rows[i] || moe.inner_a_rows[i - 1] >= moe.inner_a_rows[i]) {
            *error = "MoE A rows are not strictly sorted";
            return false;
        }
    }
    (void)total_b_cols;
    return true;
}

uint32_t load_u32(const uint8_t* data) {
    return static_cast<uint32_t>(data[0]) |
           static_cast<uint32_t>(data[1]) << 8 |
           static_cast<uint32_t>(data[2]) << 16 |
           static_cast<uint32_t>(data[3]) << 24;
}

void store_u32(uint8_t* data, uint32_t value) {
    data[0] = static_cast<uint8_t>(value);
    data[1] = static_cast<uint8_t>(value >> 8);
    data[2] = static_cast<uint8_t>(value >> 16);
    data[3] = static_cast<uint8_t>(value >> 24);
}

std::vector<uint8_t> make_config_bytes(uint32_t k, uint16_t rank,
                                       const PatternInfo& rows, const PatternInfo& cols,
                                       bool moe, uint16_t experts, uint16_t top_k) {
    std::vector<uint8_t> bytes(52, 0);
    store_u32(bytes.data(), k);
    bytes[4] = static_cast<uint8_t>(rank);
    bytes[5] = static_cast<uint8_t>(rank >> 8);
    // MMAType::Int7xInt7ToInt32 is enum value zero.
    std::memcpy(bytes.data() + 8, rows.bytes.data(), rows.bytes.size());
    std::memcpy(bytes.data() + 14, cols.bytes.data(), cols.bytes.size());
    if (moe) {
        bytes[20] = static_cast<uint8_t>(experts);
        bytes[21] = static_cast<uint8_t>(experts >> 8);
        bytes[22] = static_cast<uint8_t>(top_k);
        bytes[23] = static_cast<uint8_t>(top_k >> 8);
    }
    return bytes;
}

Hash hash_concat(const uint8_t* first, size_t first_length,
                 const uint8_t* second, size_t second_length) {
    std::vector<uint8_t> bytes;
    bytes.reserve(first_length + second_length);
    bytes.insert(bytes.end(), first, first + first_length);
    bytes.insert(bytes.end(), second, second + second_length);
    return pearl_blake3::hash(bytes);
}

Hash bind_root(const Hash& root, uint32_t dimension, const Hash& salt) {
    std::array<uint8_t, 64> message{};
    std::memcpy(message.data(), root.data(), root.size());
    store_u32(message.data() + 32, dimension);
    return pearl_blake3::keyed_hash(message.data(), message.size(), salt);
}

const Hash SEED_SALT_A = {
    0x82, 0x49, 0x40, 0x6c, 0xa0, 0xed, 0x15, 0x16,
    0x96, 0x16, 0xf6, 0x92, 0xfc, 0xf0, 0x76, 0xf8,
    0x92, 0xdb, 0xdb, 0x2a, 0x70, 0x23, 0xb8, 0x52,
    0xf0, 0xd4, 0x77, 0x19, 0xc3, 0x90, 0x01, 0x7b
};

const Hash SEED_SALT_B = {
    0x11, 0x30, 0x06, 0x32, 0xec, 0x63, 0x01, 0xca,
    0x2b, 0xe2, 0xaf, 0x71, 0x8b, 0x3f, 0x4d, 0x4f,
    0x1a, 0xe9, 0xc6, 0x39, 0x88, 0xe8, 0xcc, 0x04,
    0x48, 0x44, 0x30, 0x1d, 0x71, 0xb8, 0x9a, 0xa9
};

const Hash SEED_LABEL_A = {
    'A', '_', 't', 'e', 'n', 's', 'o', 'r',
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
};

const Hash SEED_LABEL_B = {
    'B', '_', 't', 'e', 'n', 's', 'o', 'r',
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
};

bool random_hash(uint64_t index, const Hash& seed, const Hash& key,
                 unsigned prepend_index, Hash* output, std::string* error) {
    if (prepend_index > 1 || index >= static_cast<uint64_t>(INT32_MAX)) {
        *error = "noise hash index exceeds signed V3 bounds";
        return false;
    }
    std::array<uint8_t, 64> message{};
    const int32_t value = static_cast<int32_t>(index + 1);
    store_u32(message.data() + prepend_index * 4, static_cast<uint32_t>(value));
    std::memcpy(message.data() + 32, seed.data(), seed.size());
    *output = pearl_blake3::keyed_hash(message.data(), message.size(), key);
    return true;
}

bool uniform_row(uint64_t row, uint32_t rank, const Hash& seed, const Hash& key,
                 std::vector<int16_t>* output, std::string* error) {
    uint64_t start = 0;
    uint64_t end = 0;
    if (!checked_mul_u64(row, rank, &start) || !checked_add_u64(start, rank, &end)) {
        *error = "uniform noise index overflow";
        return false;
    }
    const uint64_t first_block = start / 32;
    const uint64_t last_block = (end + 31) / 32;
    output->clear();
    output->reserve(rank);
    for (uint64_t block = first_block; block < last_block; ++block) {
        Hash random{};
        if (!random_hash(block, seed, key, 0, &random, error)) return false;
        for (size_t byte = 0; byte < random.size(); ++byte) {
            const uint64_t index = block * 32 + byte;
            if (index >= start && index < end) {
                output->push_back(static_cast<int16_t>(static_cast<int>(random[byte] & 63u) - 32));
            }
        }
    }
    if (output->size() != rank) {
        *error = "uniform noise row has the wrong length";
        return false;
    }
    return true;
}

uint32_t mul_hi_u32(uint32_t a, uint32_t b) {
    return static_cast<uint32_t>((static_cast<uint64_t>(a) * b) >> 32);
}

bool permutation(uint32_t k, uint32_t rank, const Hash& seed, const Hash& key,
                 std::vector<std::pair<uint32_t, uint32_t>>* output, std::string* error) {
    output->clear();
    output->resize(k);
    const uint32_t mask = rank - 1;
    for (uint32_t i = 0; i < k; ++i) {
        Hash random{};
        if ((i % 8) == 0 && !random_hash(i / 8, seed, key, 1, &random, error)) return false;
        // Keep the hash for the current eight entries without a second keyed
        // call.  The fixed-size cache is reconstructed per group below.
        if ((i % 8) == 0) {
            for (uint32_t j = 0; j < 8 && i + j < k; ++j) {
                const uint32_t random_value = load_u32(random.data() + j * 4);
                const uint32_t first = random_value & mask;
                const uint32_t second = first ^ (1u + mul_hi_u32(mask, random_value));
                (*output)[i + j] = {first, second};
            }
            i += 7;
        }
    }
    return true;
}

bool signed_strips(const Merkle& proof, const std::vector<uint64_t>& indices,
                   uint64_t k, size_t strip_length, uint64_t total_bytes,
                   std::vector<std::vector<int16_t>>* output, std::string* error) {
    output->clear();
    output->reserve(indices.size());
    for (uint64_t index : indices) {
        uint64_t start = 0;
        if (!checked_mul_u64(index, k, &start)) {
            *error = "matrix strip offset overflow";
            return false;
        }
        std::vector<uint8_t> bytes;
        if (!extract_bytes(proof, total_bytes, start, strip_length, &bytes, error)) return false;
        std::vector<int16_t> strip;
        strip.reserve(bytes.size());
        for (uint8_t byte : bytes) {
            const int value = byte < 128 ? byte : static_cast<int>(byte) - 256;
            if (value < -64 || value > 64) {
                *error = "matrix strip value is outside [-64, 64]";
                return false;
            }
            strip.push_back(static_cast<int16_t>(value));
        }
        output->push_back(std::move(strip));
    }
    return true;
}

bool compute_jackpot(const PlainProof& proof, const ConfigInfo& config,
                     const Hash& a_noise_seed, const Hash& b_noise_seed,
                     const std::vector<std::vector<int16_t>>& secret_a,
                     const std::vector<std::vector<int16_t>>& secret_b,
                     Hash* jackpot_hash, std::string* error) {
    const uint32_t h = config.rows_pattern.count;
    const uint32_t w = config.cols_pattern.count;
    const uint32_t k = config.k;
    const uint32_t rank = config.rank;
    std::vector<std::vector<int16_t>> noise_a(h, std::vector<int16_t>(k));
    std::vector<std::vector<int16_t>> noise_b(w, std::vector<int16_t>(k));
    std::vector<std::pair<uint32_t, uint32_t>> perm_a;
    std::vector<std::pair<uint32_t, uint32_t>> perm_b;
    if (!permutation(k, rank, SEED_LABEL_A, a_noise_seed, &perm_a, error) ||
        !permutation(k, rank, SEED_LABEL_B, b_noise_seed, &perm_b, error)) return false;

    const std::vector<uint64_t>& a_indices = proof.a.rows;
    const std::vector<uint64_t>& b_indices = proof.bt.rows;
    if (a_indices.size() != h || b_indices.size() != w ||
        secret_a.size() != h || secret_b.size() != w) {
        *error = "matrix strip count does not match the public pattern";
        return false;
    }
    for (uint32_t i = 0; i < h; ++i) {
        std::vector<int16_t> uniform;
        if (!uniform_row(a_indices[i], rank, SEED_LABEL_A, a_noise_seed, &uniform, error)) return false;
        for (uint32_t l = 0; l < k; ++l) {
            const auto pair = perm_a[l];
            noise_a[i][l] = static_cast<int16_t>(uniform[pair.first] - uniform[pair.second]);
        }
    }
    for (uint32_t i = 0; i < w; ++i) {
        std::vector<int16_t> uniform;
        if (!uniform_row(b_indices[i], rank, SEED_LABEL_B, b_noise_seed, &uniform, error)) return false;
        for (uint32_t l = 0; l < k; ++l) {
            const auto pair = perm_b[l];
            noise_b[i][l] = static_cast<int16_t>(uniform[pair.first] - uniform[pair.second]);
        }
    }

    std::vector<int64_t> accum(static_cast<size_t>(h) * w, 0);
    std::array<uint32_t, 16> jackpot{};
    const uint32_t dot = k - (k % rank);
    for (uint32_t ll = rank; ll <= dot; ll += rank) {
        const uint32_t begin = ll - rank;
        for (uint32_t u = 0; u < h; ++u) {
            for (uint32_t v = 0; v < w; ++v) {
                int64_t& value = accum[static_cast<size_t>(u) * w + v];
                for (uint32_t l = begin; l < ll; ++l) {
                    const int64_t a = secret_a[u][l] + noise_a[u][l];
                    const int64_t b = secret_b[v][l] + noise_b[v][l];
                    value += a * b;
                }
            }
        }
        uint32_t xored_tile = 0;
        for (int64_t value : accum) xored_tile ^= static_cast<uint32_t>(value);
        const uint32_t tid = ((ll / rank) - 1) % 16;
        jackpot[tid] = (jackpot[tid] << 13) | (jackpot[tid] >> 19);
        jackpot[tid] ^= xored_tile;
    }

    std::array<uint8_t, 64> message{};
    for (size_t i = 0; i < jackpot.size(); ++i) store_u32(message.data() + i * 4, jackpot[i]);
    *jackpot_hash = pearl_blake3::keyed_hash(message.data(), message.size(), a_noise_seed);
    return true;
}

bool scale_target(const uint8_t* target, uint64_t factor, Hash* output) {
    if (output == nullptr) return false;
    output->fill(0);
    uint64_t carry = 0;
    for (size_t i = 0; i < 8; ++i) {
        const uint32_t input = load_u32(target + i * 4);
        // factor is checked to fit u32 before reaching this function, so the
        // product plus carry is strictly below 2^64 and needs no wider type.
        const uint64_t product = static_cast<uint64_t>(input) * factor + carry;
        store_u32(output->data() + i * 4, static_cast<uint32_t>(product));
        carry = product >> 32;
    }
    // A full-width pool share target is not a compact consensus target.  If
    // scaling it does not fit in 256 bits, the share target is unusable; do
    // not saturate it to U256::MAX, which would make every jackpot a winner.
    return carry == 0;
}

bool little_endian_le(const Hash& value, const Hash& bound) {
    for (size_t i = value.size(); i-- > 0;) {
        if (value[i] != bound[i]) return value[i] < bound[i];
    }
    return true;
}

bool verify_routing(const PlainProof& proof, uint64_t routing_bytes,
                    std::string* error) {
    const MoeProof& moe = proof.moe;
    const uint64_t start = moe.expert_index == 0 ? 0 : moe.routing_offsets[moe.expert_index - 1];
    for (size_t i = 0; i < moe.inner_a_rows.size(); ++i) {
        uint64_t entry = 0;
        if (!checked_add_u64(start, moe.inner_a_rows[i], &entry) ||
            !checked_mul_u64(entry, sizeof(uint32_t), &entry)) {
            *error = "routing byte offset overflow";
            return false;
        }
        std::vector<uint8_t> bytes;
        if (!extract_bytes(moe.routing, routing_bytes, entry, sizeof(uint32_t), &bytes, error)) return false;
        const uint32_t route = load_u32(bytes.data());
        if (route != proof.a.rows[i]) {
            *error = "routing value does not match the committed outer A row";
            return false;
        }
    }
    return true;
}

void append_u64(std::vector<uint8_t>* output, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) {
        output->push_back(static_cast<uint8_t>(value >> (8 * i)));
    }
}

void append_u32(std::vector<uint8_t>* output, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) {
        output->push_back(static_cast<uint8_t>(value >> (8 * i)));
    }
}

void append_hash(std::vector<uint8_t>* output, const Hash& value) {
    output->insert(output->end(), value.begin(), value.end());
}

Hash make_solution_id(const uint8_t* header, size_t header_length,
                      const PreparedProof& prepared) {
    // Every field below has a fixed width, and every variable-length vector is
    // preceded by an explicit u64 count.  The domain prefix keeps this digest
    // separate from all existing Pearl commitments and proof_id values.
    static const uint8_t DOMAIN[] = {
        'P', 'e', 'a', 'r', 'l', 'H', 'a', 's', 'h',
        ' ', 'V', '3', ' ', 's', 'o', 'l', 'u', 't', 'i', 'o', 'n', ' ', 'i', 'd', ' ', 'v', '1'
    };
    const PlainProof& proof = prepared.proof;
    std::vector<uint8_t> tuple;
    tuple.reserve(256 + (proof.a.rows.size() + proof.bt.rows.size() +
                         proof.moe.routing_offsets.size()) * sizeof(uint64_t));
    tuple.insert(tuple.end(), DOMAIN, DOMAIN + sizeof(DOMAIN));
    tuple.insert(tuple.end(), header, header + header_length);
    append_u64(&tuple, proof.m);
    append_u64(&tuple, proof.n);
    append_u64(&tuple, proof.k);
    append_u64(&tuple, proof.noise_rank);
    append_hash(&tuple, prepared.root_a);
    append_hash(&tuple, prepared.root_b);
    tuple.push_back(proof.has_moe ? 1 : 0);

    append_u64(&tuple, proof.a.rows.size());
    for (uint64_t row : proof.a.rows) append_u64(&tuple, row);
    append_u64(&tuple, proof.bt.rows.size());
    for (uint64_t row : proof.bt.rows) append_u64(&tuple, row);

    if (proof.has_moe) {
        append_u64(&tuple, proof.moe.experts);
        append_u64(&tuple, proof.moe.top_k);
        append_u64(&tuple, proof.moe.expert_index);
        append_u64(&tuple, proof.moe.routing_offsets.size());
        for (uint32_t offset : proof.moe.routing_offsets) append_u32(&tuple, offset);
        append_u64(&tuple, proof.moe.inner_a_rows.size());
        for (uint64_t row : proof.moe.inner_a_rows) append_u64(&tuple, row);
        append_hash(&tuple, prepared.root_routing);
    }
    return pearl_blake3::hash(tuple);
}

bool prepare_impl(const uint8_t* header, size_t header_length,
                  const uint8_t* proof_bytes, size_t proof_length,
                  PreparedProof* prepared, std::string* error) {
    if (prepared == nullptr || error == nullptr) return false;
    *prepared = PreparedProof{};
    if (header == nullptr || header_length != 76) {
        *error = "header must be 76 bytes";
        return false;
    }

    PlainProof proof;
    bool legacy = false;
    if (!parse_plain(proof_bytes, proof_length, &proof, &legacy, error)) return false;
    uint32_t m = 0, n = 0, k = 0;
    if (!u32_from_u64(proof.m, &m, "m exceeds u32", error) ||
        !u32_from_u64(proof.n, &n, "n exceeds u32", error) ||
        !u32_from_u64(proof.k, &k, "k exceeds u32", error) ||
        proof.noise_rank > UINT16_MAX) {
        if (error->empty()) *error = "noise rank exceeds u16";
        return false;
    }
    const uint16_t rank = static_cast<uint16_t>(proof.noise_rank);

    uint64_t total_b_cols64 = proof.n;
    uint16_t experts = 0;
    uint16_t top_k = 0;
    uint16_t expert_index = 0;
    std::vector<uint64_t> rows_for_pattern;
    std::vector<uint64_t> cols_for_pattern;
    if (proof.has_moe) {
        if (proof.moe.experts > UINT16_MAX || proof.moe.top_k > UINT16_MAX) {
            *error = "MoE dimensions exceed u16 wire bounds";
            return false;
        }
        experts = static_cast<uint16_t>(proof.moe.experts);
        top_k = static_cast<uint16_t>(proof.moe.top_k);
        expert_index = proof.moe.expert_index;
        if (!checked_mul_u64(proof.n, proof.moe.experts, &total_b_cols64) || total_b_cols64 > UINT32_MAX) {
            *error = "MoE total B columns overflow u32";
            return false;
        }
        rows_for_pattern = proof.moe.inner_a_rows;
        const uint64_t column_offset = static_cast<uint64_t>(expert_index) * proof.n;
        cols_for_pattern.reserve(proof.bt.rows.size());
        for (uint64_t index : proof.bt.rows) {
            if (index < column_offset || index - column_offset > UINT32_MAX) {
                *error = "MoE B index is below or beyond its expert offset";
                return false;
            }
            cols_for_pattern.push_back(index - column_offset);
        }
    } else {
        rows_for_pattern = proof.a.rows;
        cols_for_pattern = proof.bt.rows;
    }
    if (total_b_cols64 > UINT32_MAX) {
        *error = "total B columns exceed u32";
        return false;
    }
    uint32_t t_rows = 0, t_cols = 0;
    PatternInfo rows_pattern, cols_pattern;
    if (!pattern_from_list(rows_for_pattern, &rows_pattern, &t_rows, error) ||
        !pattern_from_list(cols_for_pattern, &cols_pattern, &t_cols, error)) return false;
    if (!offset_is_valid(rows_pattern, t_rows) || !offset_is_valid(cols_pattern, t_cols)) {
        *error = "pattern offset is not valid for its periodic shape";
        return false;
    }
    if (!sanity_check(proof, rows_pattern, t_rows, cols_pattern, t_cols,
                      static_cast<uint32_t>(total_b_cols64), error)) return false;

    uint64_t expected_a = 0, expected_b = 0;
    if (!expected_leaves(proof.m, proof.k, &expected_a) ||
        !expected_leaves(total_b_cols64, proof.k, &expected_b) ||
        !check_tree_size(proof.a.proof, expected_a, "A", error) ||
        !check_tree_size(proof.bt.proof, expected_b, "B", error)) return false;
    uint64_t routing_bytes = 0;
    if (proof.has_moe) {
        uint64_t routing_raw = 0;
        if (!checked_mul_u64(proof.m, proof.moe.top_k, &routing_raw) ||
            !checked_mul_u64(routing_raw, sizeof(uint32_t), &routing_raw) ||
            !padded_bytes(routing_raw, &routing_bytes)) {
            *error = "MoE routing byte length overflow";
            return false;
        }
        const uint64_t expected_routing = routing_bytes / CHUNK;
        if (!check_tree_size(proof.moe.routing, expected_routing, "routing", error)) return false;
    }

    const std::vector<uint8_t> config_bytes = make_config_bytes(
        k, rank, rows_pattern, cols_pattern, proof.has_moe, experts, top_k);
    const Hash job_key = hash_concat(header, header_length, config_bytes.data(), config_bytes.size());
    Hash root_a{}, root_b{}, root_routing{};
    if (!compute_merkle_root(proof.a.proof, job_key, &root_a, error) ||
        !same_hash(root_a, proof.a.proof.root)) {
        if (error->empty()) *error = "A Merkle root mismatch";
        return false;
    }
    if (!compute_merkle_root(proof.bt.proof, job_key, &root_b, error) ||
        !same_hash(root_b, proof.bt.proof.root)) {
        if (error->empty()) *error = "B Merkle root mismatch";
        return false;
    }
    if (proof.has_moe) {
        if (!compute_merkle_root(proof.moe.routing, job_key, &root_routing, error) ||
            !same_hash(root_routing, proof.moe.routing.root)) {
            if (error->empty()) *error = "routing Merkle root mismatch";
            return false;
        }
        if (!verify_routing(proof, routing_bytes, error)) return false;
    }

    const uint32_t dot = k - (k % rank);
    uint64_t factor = 0;
    if (!checked_mul_u64(rows_pattern.count, cols_pattern.count, &factor) ||
        !checked_mul_u64(factor, static_cast<uint64_t>(dot / rank), &factor) ||
        !checked_mul_u64(factor, 128, &factor) || factor == 0 || factor > UINT32_MAX) {
        *error = "difficulty adjustment factor overflow";
        return false;
    }
    const uint32_t adjustment_factor = static_cast<uint32_t>(factor);
    const ConfigInfo config{m, n, k, rank, experts, top_k, expert_index, t_rows, t_cols,
                            adjustment_factor, proof.has_moe, rows_pattern, cols_pattern};

    prepared->proof = std::move(proof);
    prepared->config = config;
    prepared->job_key = job_key;
    prepared->root_a = root_a;
    prepared->root_b = root_b;
    prepared->root_routing = root_routing;
    prepared->solution_id = make_solution_id(header, header_length, *prepared);
    prepared->total_b_cols = total_b_cols64;
    prepared->m = m;
    prepared->n = n;
    prepared->k = k;
    prepared->rank = rank;
    prepared->proof.legacy_dense = legacy;
    return true;
}

bool verify_impl(const uint8_t* header, size_t header_length,
                 const uint8_t* proof_bytes, size_t proof_length,
                 const uint8_t* target, size_t target_length,
                 VerifyResult* result) {
    if (result == nullptr) return false;
    *result = VerifyResult{};
    if (header == nullptr || header_length != 76 || target == nullptr || target_length != 32) {
        result->error = "header must be 76 bytes and target must be 32 bytes";
        return false;
    }

    PreparedProof prepared;
    if (!prepare_impl(header, header_length, proof_bytes, proof_length,
                      &prepared, &result->error)) return false;
    const PlainProof& proof = prepared.proof;
    const ConfigInfo& config = prepared.config;
    const size_t dot = static_cast<size_t>(prepared.k - (prepared.k % prepared.rank));
    uint64_t a_bytes = 0, b_bytes = 0;
    if (!checked_mul_u64(proof.m, proof.k, &a_bytes) ||
        !checked_mul_u64(prepared.total_b_cols, proof.k, &b_bytes)) {
        result->error = "matrix byte length overflow";
        return false;
    }
    std::vector<std::vector<int16_t>> secret_a, secret_b;
    if (!signed_strips(proof.a.proof, proof.a.rows, proof.k, dot, a_bytes, &secret_a, &result->error) ||
        !signed_strips(proof.bt.proof, proof.bt.rows, proof.k, dot, b_bytes, &secret_b, &result->error)) return false;

    Hash bound_a = bind_root(prepared.root_a, prepared.m, SEED_SALT_A);
    Hash bound_b = bind_root(prepared.root_b, prepared.n, SEED_SALT_B);
    Hash hash_activations = bound_a;
    if (proof.has_moe) {
        std::vector<uint8_t> offsets;
        offsets.reserve(proof.moe.routing_offsets.size() * sizeof(uint32_t));
        for (uint32_t value : proof.moe.routing_offsets) {
            const uint8_t bytes[4] = {
                static_cast<uint8_t>(value), static_cast<uint8_t>(value >> 8),
                static_cast<uint8_t>(value >> 16), static_cast<uint8_t>(value >> 24)
            };
            offsets.insert(offsets.end(), bytes, bytes + sizeof(bytes));
        }
        uint64_t padded_offset_bytes = 0;
        if (!padded_bytes(offsets.size(), &padded_offset_bytes) || padded_offset_bytes > MAX_PROOF_BYTES) {
            result->error = "MoE offset commitment is too large";
            return false;
        }
        offsets.resize(static_cast<size_t>(padded_offset_bytes), 0);
        const Hash hash_offsets = pearl_blake3::keyed_hash(offsets, prepared.job_key);
        const Hash hash_routing = hash_concat(prepared.root_routing.data(), 32,
                                              hash_offsets.data(), hash_offsets.size());
        hash_activations = hash_concat(bound_a.data(), 32, hash_routing.data(), 32);
    }
    const Hash b_noise_seed = hash_concat(prepared.job_key.data(), 32, bound_b.data(), 32);
    const Hash a_noise_seed = hash_concat(b_noise_seed.data(), 32, hash_activations.data(), 32);
    if (!compute_jackpot(proof, config, a_noise_seed, b_noise_seed, secret_a, secret_b,
                         &result->jackpot, &result->error)) return false;

    Hash target_bound{};
    const bool target_usable = scale_target(target, config.adjustment_factor, &target_bound);
    result->candidate = target_usable && little_endian_le(result->jackpot, target_bound);
    result->valid = true;
    result->config = config;
    result->solution_id = prepared.solution_id;

    std::vector<uint8_t> canonical;
    canonical.reserve(header_length + proof_length + (proof.legacy_dense ? 1 : 0));
    canonical.insert(canonical.end(), header, header + header_length);
    canonical.insert(canonical.end(), proof_bytes, proof_bytes + proof_length);
    if (proof.legacy_dense) canonical.push_back(0);
    result->proof_id = pearl_blake3::hash(canonical);
    result->error.clear();
    return true;
}

bool solution_id_impl(const uint8_t* header, size_t header_length,
                      const uint8_t* proof_bytes, size_t proof_length,
                      VerifyResult* result) {
    if (result == nullptr) return false;
    *result = VerifyResult{};
    if (header == nullptr || header_length != 76) {
        result->error = "header must be 76 bytes";
        return false;
    }
    PreparedProof prepared;
    if (!prepare_impl(header, header_length, proof_bytes, proof_length,
                      &prepared, &result->error)) return false;
    result->valid = true;
    result->solution_id = prepared.solution_id;
    result->config = prepared.config;
    result->error.clear();
    return true;
}

int base64_value(uint8_t value) {
    if (value >= 'A' && value <= 'Z') return value - 'A';
    if (value >= 'a' && value <= 'z') return value - 'a' + 26;
    if (value >= '0' && value <= '9') return value - '0' + 52;
    if (value == '+') return 62;
    if (value == '/') return 63;
    return -1;
}

} // namespace

bool decode_base64(const char* encoded, size_t encoded_length,
                   std::string* error, std::vector<uint8_t>* output) {
    if (error == nullptr || output == nullptr) return false;
    output->clear();
    if (encoded == nullptr || encoded_length == 0 || encoded_length > MAX_BASE64_CHARS ||
        encoded_length % 4 != 0) {
        *error = "base64 proof length is outside the bounded V3 range";
        return false;
    }
    size_t padding = 0;
    if (encoded[encoded_length - 1] == '=') ++padding;
    if (encoded_length > 1 && encoded[encoded_length - 2] == '=') ++padding;
    if (padding > 2) {
        *error = "invalid base64 padding";
        return false;
    }
    const size_t decoded_length = (encoded_length / 4) * 3 - padding;
    if (decoded_length == 0 || decoded_length > MAX_PROOF_BYTES) {
        *error = "decoded base64 proof exceeds the 8 MiB bound";
        return false;
    }
    for (size_t i = 0; i < encoded_length; i += 4) {
        const bool final_group = i + 4 == encoded_length;
        const uint8_t c0 = static_cast<uint8_t>(encoded[i]);
        const uint8_t c1 = static_cast<uint8_t>(encoded[i + 1]);
        const uint8_t c2 = static_cast<uint8_t>(encoded[i + 2]);
        const uint8_t c3 = static_cast<uint8_t>(encoded[i + 3]);
        const int v0 = base64_value(c0);
        const int v1 = base64_value(c1);
        const bool p2 = c2 == '=';
        const bool p3 = c3 == '=';
        if (v0 < 0 || v1 < 0 || (!p2 && base64_value(c2) < 0) || (!p3 && base64_value(c3) < 0) ||
            (!final_group && (p2 || p3)) || (p2 && !p3) || (p2 && (v1 & 15) != 0) ||
            (!p2 && p3 && (base64_value(c2) & 3) != 0)) {
            *error = "invalid or non-canonical base64";
            output->clear();
            return false;
        }
    }
    // Validate the complete encoding before reserving/allocating the decoded
    // proof buffer.  A hostile, invalid string therefore cannot force the
    // maximum bounded allocation merely by reaching the size cap.
    output->reserve(decoded_length);
    for (size_t i = 0; i < encoded_length; i += 4) {
        const uint8_t c0 = static_cast<uint8_t>(encoded[i]);
        const uint8_t c1 = static_cast<uint8_t>(encoded[i + 1]);
        const uint8_t c2 = static_cast<uint8_t>(encoded[i + 2]);
        const uint8_t c3 = static_cast<uint8_t>(encoded[i + 3]);
        const bool p2 = c2 == '=';
        const bool p3 = c3 == '=';
        const int v0 = base64_value(c0);
        const int v1 = base64_value(c1);
        const int v2 = p2 ? 0 : base64_value(c2);
        const int v3 = p3 ? 0 : base64_value(c3);
        output->push_back(static_cast<uint8_t>((v0 << 2) | (v1 >> 4)));
        if (!p2) output->push_back(static_cast<uint8_t>((v1 << 4) | (v2 >> 2)));
        if (!p3) output->push_back(static_cast<uint8_t>((v2 << 6) | v3));
    }
    if (output->size() != decoded_length) {
        *error = "base64 decoded length mismatch";
        output->clear();
        return false;
    }
    return true;
}

bool verify_v3(const uint8_t* header, size_t header_length,
               const uint8_t* proof, size_t proof_length,
               const uint8_t* target, size_t target_length,
               VerifyResult* result) {
    if (result == nullptr) return false;
    try {
        return verify_impl(header, header_length, proof, proof_length,
                           target, target_length, result);
    } catch (const std::exception& exception) {
        *result = VerifyResult{};
        result->error = std::string("verification failed closed: ") + exception.what();
        return false;
    } catch (...) {
        *result = VerifyResult{};
        result->error = "verification failed closed: unexpected exception";
        return false;
    }
}

bool pearl_v3_solution_id(const uint8_t* header, size_t header_length,
                          const uint8_t* proof, size_t proof_length,
                          VerifyResult* result) {
    if (result == nullptr) return false;
    try {
        return solution_id_impl(header, header_length, proof, proof_length, result);
    } catch (const std::exception& exception) {
        *result = VerifyResult{};
        result->error = std::string("verification failed closed: ") + exception.what();
        return false;
    } catch (...) {
        *result = VerifyResult{};
        result->error = "verification failed closed: unexpected exception";
        return false;
    }
}

} // namespace pearl_verify
