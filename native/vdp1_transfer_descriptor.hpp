#pragma once
// Stage66: ROM-free model of the statically identified Saturn VDP1 transfer
// descriptor. This parser consumes only synthetic/test-provided bytes; it
// neither loads original assets nor emulates the SH-2's unsafe edge cases.
#include <cstddef>
#include <cstdint>
#include <limits>

namespace thor2 {
namespace vdp1 {

constexpr std::size_t kTransferDescriptorBytes = 8;
constexpr std::uint32_t kTransferBlockBytes = 32;
constexpr std::uint32_t kVdp1VramBase = 0x25C00000u;
constexpr std::uint32_t kVdp1VramBytes = 512u * 1024u;

struct TransferDescriptor {
    std::uint32_t source_address;
    std::uint16_t destination_slot;
    // The SH-2 copier loads this word with MOV.W, which sign-extends it.
    std::int16_t block_count;
};

struct TransferCopyPlan {
    std::uint32_t source_address;
    std::uint32_t destination_address;
    std::uint32_t payload_bytes;
    std::int16_t block_count;
};

// Producer-side derivations verified by static cross-reference analysis:
// the source index is an unsigned word scaled by eight, and the block count
// is ((metadata byte +2 & 0x3F) * metadata byte +3) >> 3.
inline std::uint16_t derive_block_count_from_metadata(
    std::uint8_t factor_a, std::uint8_t factor_b) noexcept {
    const std::uint32_t product =
        static_cast<std::uint32_t>(factor_a & 0x3Fu) *
        static_cast<std::uint32_t>(factor_b);
    return static_cast<std::uint16_t>(product >> 3);
}

inline bool compute_source_address(std::uint32_t source_base,
                                   std::uint16_t source_index,
                                   std::uint32_t* out) noexcept {
    if (!out || (source_base & 3u) != 0)
        return false;
    const std::uint32_t offset =
        static_cast<std::uint32_t>(source_index) * 8u;
    if (source_base > std::numeric_limits<std::uint32_t>::max() - offset)
        return false;
    *out = source_base + offset;
    return true;
}

inline std::uint16_t read_be16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(p[0]) << 8) |
        static_cast<std::uint16_t>(p[1]));
}

inline std::uint32_t read_be32(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           static_cast<std::uint32_t>(p[3]);
}

// Parse the Saturn big-endian 8-byte record without relying on host packing
// or endianness. A successful parse does not imply that its count is safe.
inline bool decode_transfer_descriptor(const std::uint8_t* bytes,
                                       std::size_t size,
                                       TransferDescriptor* out) noexcept {
    if (!bytes || !out || size < kTransferDescriptorBytes)
        return false;
    const std::uint16_t raw_count = read_be16(bytes + 6);
    const std::int32_t signed_count =
        (raw_count & 0x8000u) ? static_cast<std::int32_t>(raw_count) - 0x10000
                              : static_cast<std::int32_t>(raw_count);
    *out = TransferDescriptor{
        read_be32(bytes),
        read_be16(bytes + 4),
        static_cast<std::int16_t>(signed_count)
    };
    return true;
}

// Convert a descriptor to a bounded host-side plan. The original copier uses
// a do-while loop over a sign-extended 32-bit working count, so zero/negative
// 16-bit counts would not mean "copy nothing"; they would run until wraparound.
// This defensive helper accepts only finite positive counts and rejects any
// source/destination range that would overflow or exceed the 512-KiB VDP1 VRAM.
inline bool make_transfer_copy_plan(const TransferDescriptor& descriptor,
                                    TransferCopyPlan* out) noexcept {
    if (!out || descriptor.block_count <= 0)
        return false;
    if ((descriptor.source_address & 3u) != 0)
        return false; // source is read as 32-bit words
    const std::uint32_t payload_bytes =
        static_cast<std::uint32_t>(descriptor.block_count) * kTransferBlockBytes;
    if (descriptor.source_address >
        std::numeric_limits<std::uint32_t>::max() - payload_bytes)
        return false;
    const std::uint32_t destination_offset =
        static_cast<std::uint32_t>(descriptor.destination_slot) * 8u;
    if (payload_bytes > kVdp1VramBytes ||
        destination_offset > kVdp1VramBytes - payload_bytes)
        return false;
    *out = TransferCopyPlan{
        descriptor.source_address,
        kVdp1VramBase + destination_offset,
        payload_bytes,
        descriptor.block_count
    };
    return true;
}

}  // namespace vdp1
}  // namespace thor2
