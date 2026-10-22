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
constexpr std::uint16_t kVdp1CommandTerminatorWord = 0x8000u;
constexpr std::uint32_t kVdp1CommandTerminatorStorageBytes = 4u;
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

// Model the observed submit-gate predicate. A negative signed status is
// consumed (reset to zero) before checking the descriptor count, so even a
// zero-count gate pass clears the status. This does not perform the copy.
inline bool begin_transfer_submit(std::int8_t* status,
                                 std::uint16_t descriptor_count) noexcept {
    if (!status || *status >= 0)
        return false;
    *status = 0;
    return descriptor_count != 0;
}

// The command-list upload path computes signed_word_count * 32 + 2 bytes.
// Reject values whose high bit would make the original signed-word count
// negative instead of silently reproducing a malformed length.
inline bool command_upload_size_bytes(std::uint16_t command_count,
                                      std::uint32_t* size_out) noexcept {
    if (!size_out ||
        command_count > static_cast<std::uint16_t>(
                            std::numeric_limits<std::int16_t>::max()))
        return false;
    const std::uint32_t count = command_count;
    if (count > (std::numeric_limits<std::uint32_t>::max() - 2u) /
                    static_cast<std::uint32_t>(kVdp1CommandRecordBytes))
        return false;
    *size_out = count * static_cast<std::uint32_t>(kVdp1CommandRecordBytes) + 2u;
    return true;
}

// Reserve raw bytes without changing the logical record count. This models
// the 4-byte command terminator storage after the last 32-byte command record.
inline bool reserve_raw_bytes(RecordStreamCursor* cursor,
                              std::uint32_t byte_count,
                              std::uint32_t* address_out) noexcept {
    if (!cursor || !address_out || byte_count == 0)
        return false;
    if (cursor->used_bytes > cursor->capacity_bytes ||
        byte_count > cursor->capacity_bytes - cursor->used_bytes)
        return false;
    if (cursor->base_address >
        std::numeric_limits<std::uint32_t>::max() - cursor->used_bytes)
        return false;
    const std::uint32_t address = cursor->base_address + cursor->used_bytes;
    if (address > std::numeric_limits<std::uint32_t>::max() - byte_count)
        return false;
    *address_out = address;
    cursor->used_bytes += byte_count;
    return true;
}

// Reserve one record and increment the logical count. Each stream owns its
// own cursor, count, and stride; this does not access Saturn memory.
inline bool reserve_record_slot(RecordStreamCursor* cursor,
                                std::uint32_t* address_out) noexcept {
    if (!cursor || cursor->record_size_bytes == 0 ||
        cursor->record_count == std::numeric_limits<std::uint32_t>::max())
        return false;
    if (!reserve_raw_bytes(cursor, cursor->record_size_bytes, address_out))
        return false;
    ++cursor->record_count;
    return true;
}

}  // namespace vdp1
}  // namespace thor2
