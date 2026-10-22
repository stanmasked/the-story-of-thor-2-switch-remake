#pragma once
// Stage68: end-to-end ROM-free model of VDP1 producer-to-copier inputs.
// Only caller-supplied synthetic field values are consumed; no game image,
// memory capture, emulator or proprietary resource is loaded.
#include "vdp1_transfer_descriptor.hpp"
#include <cstddef>
#include <cstdint>
#include <limits>

namespace thor2 {
namespace vdp1 {

struct TransferProducerInputs {
    std::uint32_t source_base;
    std::uint16_t source_index;
    std::uint16_t destination_slot;
    std::uint8_t factor_a;
    std::uint8_t factor_b;
};

// Model the fields written by the statically identified producer.
// A zero derived count is intentionally preserved here: the static analysis
// has not proved an invariant that excludes it in normal game data.
inline bool derive_transfer_descriptor(const TransferProducerInputs& inputs,
                                       TransferDescriptor* out) noexcept {
    if (!out)
        return false;
    std::uint32_t source_address = 0;
    if (!compute_source_address(inputs.source_base, inputs.source_index,
                                &source_address))
        return false;
    const std::uint16_t count =
        derive_block_count_from_metadata(inputs.factor_a, inputs.factor_b);
    if (count > static_cast<std::uint16_t>(
                    std::numeric_limits<std::int16_t>::max()))
        return false;
    *out = TransferDescriptor{
        source_address, inputs.destination_slot, static_cast<std::int16_t>(count)
    };
    return true;
}

// Encode the three fields in Saturn's big-endian memory order: u32 source,
// u16 destination slot, i16 count. The signed count is serialized as its
// 16-bit two's-complement representation; validation belongs to the consumer.
inline bool encode_transfer_descriptor(const TransferDescriptor& descriptor,
                                       std::uint8_t* bytes,
                                       std::size_t size) noexcept {
    if (!bytes || size < kTransferDescriptorBytes)
        return false;
    const std::uint32_t source = descriptor.source_address;
    const std::uint16_t destination = descriptor.destination_slot;
    const std::uint16_t count =
        static_cast<std::uint16_t>(descriptor.block_count);
    bytes[0] = static_cast<std::uint8_t>(source >> 24);
    bytes[1] = static_cast<std::uint8_t>(source >> 16);
    bytes[2] = static_cast<std::uint8_t>(source >> 8);
    bytes[3] = static_cast<std::uint8_t>(source);
    bytes[4] = static_cast<std::uint8_t>(destination >> 8);
    bytes[5] = static_cast<std::uint8_t>(destination);
    bytes[6] = static_cast<std::uint8_t>(count >> 8);
    bytes[7] = static_cast<std::uint8_t>(count);
    return true;
}

// Convenience path for consumers that require a bounded, finite copy.
// Outputs are committed only on success. This is a defensive host-side
// contract, not a claim that the original Saturn code performs these checks.
inline bool build_safe_transfer_plan(const TransferProducerInputs& inputs,
                                     TransferDescriptor* descriptor_out,
                                     TransferCopyPlan* plan_out) noexcept {
    if (!descriptor_out || !plan_out)
        return false;
    TransferDescriptor descriptor{};
    if (!derive_transfer_descriptor(inputs, &descriptor))
        return false;
    TransferCopyPlan plan{};
    if (!make_transfer_copy_plan(descriptor, &plan))
        return false;
    *descriptor_out = descriptor;
    *plan_out = plan;
    return true;
}

}  // namespace vdp1
}  // namespace thor2
