// Stage68 end-to-end producer/consumer contract tests.
// All values are synthetic; no original game data or executable is used.
#include "vdp1_transfer_pipeline.hpp"
#include <array>
#include <cassert>
#include <cstdint>

using namespace thor2::vdp1;

int main() {
    // Producer field derivation -> 8-byte Saturn record -> consumer decode.
    const TransferProducerInputs ordinary{
        0x06090000u, 0x1234u, 0x0100u, 0x3Fu, 0x10u
    };
    TransferDescriptor descriptor{};
    assert(derive_transfer_descriptor(ordinary, &descriptor));
    assert(descriptor.source_address == 0x060991A0u);
    assert(descriptor.destination_slot == 0x0100u);
    assert(descriptor.block_count == 126);

    std::array<std::uint8_t, kTransferDescriptorBytes> encoded{};
    assert(encode_transfer_descriptor(descriptor, encoded.data(), encoded.size()));
    const std::array<std::uint8_t, 8> expected{{
        0x06, 0x09, 0x91, 0xA0, 0x01, 0x00, 0x00, 0x7E
    }};
    assert(encoded == expected);

    TransferDescriptor decoded{};
    assert(decode_transfer_descriptor(encoded.data(), encoded.size(), &decoded));
    assert(decoded.source_address == descriptor.source_address);
    assert(decoded.destination_slot == descriptor.destination_slot);
    assert(decoded.block_count == descriptor.block_count);

    TransferCopyPlan plan{};
    assert(build_safe_transfer_plan(ordinary, &descriptor, &plan));
    assert(plan.source_address == 0x060991A0u);
    assert(plan.destination_address == 0x25C00800u);
    assert(plan.payload_bytes == 126u * kTransferBlockBytes);
    assert(plan.payload_bytes == 4032u);

    // The source factor is masked to six bits. Max count is 2008 blocks,
    // or 64,256 bytes, which remains representable in the signed descriptor.
    const TransferProducerInputs maximum{
        0x06000000u, 0xFFFFu, 0u, 0xFFu, 0xFFu
    };
    assert(derive_transfer_descriptor(maximum, &descriptor));
    assert(descriptor.source_address == 0x0607FFF8u);
    assert(descriptor.block_count == 2008);
    assert(make_transfer_copy_plan(descriptor, &plan));
    assert(plan.payload_bytes == 64256u);

    // Exact end-of-VRAM fit is accepted; moving one destination slot past it
    // is rejected. 0xE0A0 * 8 + 64256 == 512 KiB.
    TransferProducerInputs end_fit = maximum;
    end_fit.destination_slot = 0xE0A0u;
    assert(build_safe_transfer_plan(end_fit, &descriptor, &plan));
    assert(plan.destination_address == 0x25C70500u);
    assert(plan.destination_address + plan.payload_bytes == 0x25C80000u);
    TransferProducerInputs overrun = end_fit;
    overrun.destination_slot = 0xE0A1u;
    const TransferDescriptor descriptor_before = descriptor;
    const TransferCopyPlan plan_before = plan;
    assert(!build_safe_transfer_plan(overrun, &descriptor, &plan));
    assert(descriptor.source_address == descriptor_before.source_address);
    assert(descriptor.destination_slot == descriptor_before.destination_slot);
    assert(descriptor.block_count == descriptor_before.block_count);
    assert(plan.destination_address == plan_before.destination_address);
    assert(plan.payload_bytes == plan_before.payload_bytes);

    // A zero derived count is possible from the observed arithmetic formula.
    // Preserve it in the descriptor model, but do not treat it as a safe copy.
    const TransferProducerInputs zero_count{
        0x06090000u, 0u, 0u, 1u, 7u
    };
    assert(derive_transfer_descriptor(zero_count, &descriptor));
    assert(descriptor.block_count == 0);
    assert(encode_transfer_descriptor(descriptor, encoded.data(), encoded.size()));
    assert(encoded[6] == 0 && encoded[7] == 0);
    assert(decode_transfer_descriptor(encoded.data(), encoded.size(), &decoded));
    assert(decoded.block_count == 0);
    assert(!make_transfer_copy_plan(decoded, &plan));
    assert(!build_safe_transfer_plan(zero_count, &descriptor, &plan));

    // Invalid source alignment/overflow and null output are rejected.
    const TransferProducerInputs unaligned{
        0x06090001u, 1u, 0u, 8u, 8u
    };
    assert(!derive_transfer_descriptor(unaligned, &descriptor));
    const TransferProducerInputs overflow{
        0xFFFFFFF8u, 1u, 0u, 8u, 8u
    };
    assert(!derive_transfer_descriptor(overflow, &descriptor));
    assert(!derive_transfer_descriptor(ordinary, nullptr));
    assert(!build_safe_transfer_plan(ordinary, nullptr, &plan));
    assert(!build_safe_transfer_plan(ordinary, &descriptor, nullptr));

    // Encoder validates output before writing; failure leaves bytes intact.
    encoded.fill(0xA5);
    assert(!encode_transfer_descriptor(descriptor, encoded.data(), 7));
    for (const auto byte : encoded) assert(byte == 0xA5);
    assert(!encode_transfer_descriptor(descriptor, nullptr, encoded.size()));

    // The signed field round-trips as a 16-bit two's-complement value.
    const TransferDescriptor negative{
        0x06091234u, 0xFFFFu, static_cast<std::int16_t>(-1)
    };
    assert(encode_transfer_descriptor(negative, encoded.data(), encoded.size()));
    assert(encoded[6] == 0xFF && encoded[7] == 0xFF);
    assert(decode_transfer_descriptor(encoded.data(), encoded.size(), &decoded));
    assert(decoded.block_count == -1);
    assert(!make_transfer_copy_plan(decoded, &plan));

    return 0;
}
