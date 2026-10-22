// Stage68 synthetic tests for independent VDP1 command/transfer streams.
#include "vdp1_stream_layout.hpp"
#include "vdp1_transfer_descriptor.hpp"
#include <cassert>
#include <cstdint>
#include <limits>

using namespace thor2::vdp1;

int main() {
    static_assert(kVdp1CommandRecordBytes == 32, "command stride");
    static_assert(kTransferDescriptorBytes == 8, "transfer descriptor stride");
    static_assert(kVdp1CommandTerminatorWord == 0x8000u, "VDP1 end marker");
    static_assert(kVdp1CommandTerminatorStorageBytes == 4u, "end marker storage stride");

    RecordStreamCursor commands{0x06010000u, 68u, 0u, 0u,
                                static_cast<std::uint32_t>(kVdp1CommandRecordBytes)};
    RecordStreamCursor transfers{0x06020000u, 16u, 0u, 0u,
                                 static_cast<std::uint32_t>(kTransferDescriptorBytes)};
    std::uint32_t command_address = 0;
    std::uint32_t transfer_address = 0;

    assert(reserve_record_slot(&commands, &command_address));
    assert(command_address == 0x06010000u);
    assert(commands.used_bytes == 32u && commands.record_count == 1u);

    assert(reserve_record_slot(&transfers, &transfer_address));
    assert(transfer_address == 0x06020000u);
    assert(transfers.used_bytes == 8u && transfers.record_count == 1u);

    assert(reserve_record_slot(&commands, &command_address));
    assert(command_address == 0x06010020u);
    assert(commands.used_bytes == 64u && commands.record_count == 2u);
    // The end marker occupies four bytes after the final command record but
    // does not increment the logical count of 32-byte command records.
    assert(!reserve_record_slot(&commands, &command_address));
    assert(reserve_raw_bytes(&commands, kVdp1CommandTerminatorStorageBytes,
                             &command_address));
    assert(command_address == 0x06010040u);
    assert(commands.used_bytes == 68u && commands.record_count == 2u);
    assert(!reserve_raw_bytes(&commands, 1u, &command_address));

    assert(reserve_record_slot(&transfers, &transfer_address));
    assert(transfer_address == 0x06020008u);
    assert(transfers.used_bytes == 16u && transfers.record_count == 2u);
    assert(!reserve_record_slot(&transfers, &transfer_address));

    // The cursors remain independent: filling one stream does not consume the
    // capacity or count of the other stream.
    assert(commands.record_count == 2u);
    assert(transfers.record_count == 2u);

    RecordStreamCursor invalid_stride{0x06030000u, 32u, 0u, 0u, 0u};
    assert(!reserve_record_slot(&invalid_stride, &command_address));
    RecordStreamCursor bad_usage{0x06030000u, 8u, 9u, 0u, 8u};
    assert(!reserve_record_slot(&bad_usage, &command_address));
    RecordStreamCursor address_overflow{0xFFFFFFE0u, 32u, 0u, 0u, 32u};
    assert(!reserve_record_slot(&address_overflow, &command_address));
    RecordStreamCursor count_overflow{0x06040000u, 32u, 0u,
                                      std::numeric_limits<std::uint32_t>::max(), 32u};
    assert(!reserve_record_slot(&count_overflow, &command_address));

    OpaqueVdp1CommandRecord opaque{};
    opaque[0] = 0xA5u;
    opaque[31] = 0x5Au;
    assert(opaque.size() == 32u && opaque[0] == 0xA5u && opaque[31] == 0x5Au);
    return 0;
}
