#pragma once
// Stage68: ROM-free layout/cursor model for the two independently advanced
// VDP1 streams. Command-record field semantics intentionally remain opaque.
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace thor2 {
namespace vdp1 {

constexpr std::size_t kVdp1CommandRecordBytes = 32;
using OpaqueVdp1CommandRecord = std::array<std::uint8_t, kVdp1CommandRecordBytes>;
static_assert(sizeof(OpaqueVdp1CommandRecord) == kVdp1CommandRecordBytes,
              "VDP1 command record must remain 32 bytes");

struct RecordStreamCursor {
    std::uint32_t base_address;
    std::uint32_t capacity_bytes;
    std::uint32_t used_bytes;
    std::uint32_t record_count;
    std::uint32_t record_size_bytes;
};

// Reserve one record in a host-side model of a bounded stream. Each stream
// owns its own cursor, count, and stride; this does not access Saturn memory.
inline bool reserve_record_slot(RecordStreamCursor* cursor,
                                std::uint32_t* address_out) noexcept {
    if (!cursor || !address_out || cursor->record_size_bytes == 0)
        return false;
    if (cursor->used_bytes > cursor->capacity_bytes ||
        cursor->record_size_bytes > cursor->capacity_bytes - cursor->used_bytes)
        return false;
    if (cursor->record_count == std::numeric_limits<std::uint32_t>::max())
        return false;
    if (cursor->base_address >
        std::numeric_limits<std::uint32_t>::max() - cursor->used_bytes)
        return false;
    const std::uint32_t address = cursor->base_address + cursor->used_bytes;
    if (address > std::numeric_limits<std::uint32_t>::max() -
                      cursor->record_size_bytes)
        return false;
    *address_out = address;
    cursor->used_bytes += cursor->record_size_bytes;
    ++cursor->record_count;
    return true;
}

}  // namespace vdp1
}  // namespace thor2
