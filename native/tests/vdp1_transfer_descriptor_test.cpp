// Stage66 synthetic tests for the VDP1 transfer descriptor contract.
// No original game bytes, resources, or executable are used.
#include "vdp1_transfer_descriptor.hpp"
#include <array>
#include <cassert>
#include <cstdint>
#include <limits>

using namespace thor2::vdp1;

int main() {
    static_assert(kTransferDescriptorBytes == 8, "descriptor width");
    static_assert(kTransferBlockBytes == 32, "copy block width");
    static_assert(kVdp1VramBytes == 512u * 1024u, "VDP1 VRAM size");

    // Big-endian source pointer, unsigned destination slot, signed count.
    const std::array<std::uint8_t, 8> bytes{{
        0x06, 0x09, 0x12, 0x34, 0x12, 0x34, 0x00, 0x03
    }};
    TransferDescriptor descriptor{};
    assert(decode_transfer_descriptor(bytes.data(), bytes.size(), &descriptor));
    assert(descriptor.source_address == 0x06091234u);
    assert(descriptor.destination_slot == 0x1234u);
    assert(descriptor.block_count == 3);

    TransferCopyPlan plan{};
    assert(make_transfer_copy_plan(descriptor, &plan));
    assert(plan.source_address == 0x06091234u);
    assert(plan.destination_address == 0x25C091A0u); // 0x25C00000 + 0x1234*8
    assert(plan.payload_bytes == 96u);
    assert(plan.block_count == 3);

    // A one-block transfer ending exactly at the end of VDP1 VRAM is valid.
    descriptor.destination_slot = 0xFFFCu;
    descriptor.block_count = 1;
    assert(make_transfer_copy_plan(descriptor, &plan));
    assert(plan.destination_address == 0x25C7FFE0u);
    assert(plan.destination_address + plan.payload_bytes == 0x25C80000u);

    // The next 8-byte slot cannot hold a full 32-byte payload.
    descriptor.destination_slot = 0xFFFFu;
    assert(!make_transfer_copy_plan(descriptor, &plan));

    // Signed MOV.W semantics matter: zero and high-bit-set counts are unsafe.
    descriptor.destination_slot = 0;
    descriptor.block_count = 0;
    assert(!make_transfer_copy_plan(descriptor, &plan));
    const std::array<std::uint8_t, 8> negative_count{{
        0x06, 0x09, 0x12, 0x34, 0x00, 0x00, 0xFF, 0xFF
    }};
    assert(decode_transfer_descriptor(negative_count.data(),
                                      negative_count.size(), &descriptor));
    assert(descriptor.block_count == -1);
    assert(!make_transfer_copy_plan(descriptor, &plan));
    const std::array<std::uint8_t, 8> minimum_count{{
        0x06, 0x09, 0x12, 0x34, 0x00, 0x00, 0x80, 0x00
    }};
    assert(decode_transfer_descriptor(minimum_count.data(),
                                      minimum_count.size(), &descriptor));
    assert(descriptor.block_count == std::numeric_limits<std::int16_t>::min());
    assert(!make_transfer_copy_plan(descriptor, &plan));

    // Reject malformed inputs, unaligned longword sources and address overflow.
    assert(!decode_transfer_descriptor(nullptr, bytes.size(), &descriptor));
    assert(!decode_transfer_descriptor(bytes.data(), 7, &descriptor));
    assert(!decode_transfer_descriptor(bytes.data(), bytes.size(), nullptr));

    // Both helpers are fail-closed: failed calls must not partially overwrite
    // an existing caller-owned output structure.
    TransferDescriptor descriptor_sentinel{0xDEADBEEFu, 0xBEEFu, 123};
    assert(!decode_transfer_descriptor(bytes.data(), 7, &descriptor_sentinel));
    assert(descriptor_sentinel.source_address == 0xDEADBEEFu);
    assert(descriptor_sentinel.destination_slot == 0xBEEFu);
    assert(descriptor_sentinel.block_count == 123);

    TransferCopyPlan plan_sentinel{0xDEADBEEFu, 0xCAFEBABEu, 777, 9};
    descriptor = TransferDescriptor{0x06091235u, 0, 1};
    assert(!make_transfer_copy_plan(descriptor, &plan_sentinel));
    assert(plan_sentinel.source_address == 0xDEADBEEFu);
    assert(plan_sentinel.destination_address == 0xCAFEBABEu);
    assert(plan_sentinel.payload_bytes == 777);
    assert(plan_sentinel.block_count == 9);

    descriptor = TransferDescriptor{0xFFFFFFF0u, 0, 1};
    assert(!make_transfer_copy_plan(descriptor, &plan_sentinel));
    assert(plan_sentinel.source_address == 0xDEADBEEFu);
    assert(plan_sentinel.destination_address == 0xCAFEBABEu);
    assert(plan_sentinel.payload_bytes == 777);
    assert(plan_sentinel.block_count == 9);

    // A multi-block payload must fit in VRAM; count stays signed-positive.
    descriptor = TransferDescriptor{0x06091234u, 0, 2};
    assert(make_transfer_copy_plan(descriptor, &plan));
    assert(plan.payload_bytes == 64u);
    descriptor = TransferDescriptor{0x06091234u, 0xFFFFu, 2};
    assert(!make_transfer_copy_plan(descriptor, &plan));

    // Exact VRAM-sized payload at offset zero is valid; one block more is not.
    descriptor = TransferDescriptor{0x06091234u, 0, 16384};
    assert(make_transfer_copy_plan(descriptor, &plan));
    assert(plan.payload_bytes == kVdp1VramBytes);
    assert(plan.destination_address == kVdp1VramBase);
    descriptor.block_count = 16385;
    assert(!make_transfer_copy_plan(descriptor, &plan));

    return 0;
}
