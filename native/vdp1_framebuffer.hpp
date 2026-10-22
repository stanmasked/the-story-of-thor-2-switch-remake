#pragma once
// Stage61 original-asset-free native framebuffer inspection core.
// Pure C++17, independent of SDL, libnx and copyrighted Sega Saturn assets.
// Compatible with future host/Switch renderer integration; does not render.
//
// A CPU-memory dump only accesses the VDP1 DRAW framebuffer (256 KiB).
// It does NOT prove what the DISPLAY framebuffer contained or that VDP1
// executed. TVMR/FBCR are write-only: a register mirror must come from
// emulator internals or verified captured writes, not an ordinary read.
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace thor2 {
namespace vdp1 {

constexpr std::size_t kFrameBytes = 256u * 1024u;
constexpr std::size_t kRegisterMirrorBytes = 32u;

struct FrameMode {
    unsigned mode;
    unsigned width;
    unsigned height;
    unsigned bits_per_pixel;
    bool vblank_erase;
    bool manual_switch;
    bool switch_trigger;
};

enum class PixelClass {
    transparent_zero,
    indexed8_or_control,
    rgb555_candidate,
    palette_or_shadow_control,
};

struct Pixel {
    PixelClass category;
    std::uint16_t raw_code;
};

struct Counts {
    std::size_t transparent_zero = 0;
    std::size_t indexed8_or_control = 0;
    std::size_t rgb555_candidate = 0;
    std::size_t palette_or_shadow_control = 0;
    std::size_t total() const {
        return transparent_zero + indexed8_or_control +
               rgb555_candidate + palette_or_shadow_control;
    }
};

inline std::uint16_t be16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((static_cast<unsigned>(p[0]) << 8) |
                                      static_cast<unsigned>(p[1]));
}

inline FrameMode parse_mode(const std::uint8_t* regs, std::size_t size) {
    if (!regs || size != kRegisterMirrorBytes)
        throw std::invalid_argument("exact 32-byte VDP1 write-register mirror required");
    const unsigned tvmr = be16(regs);
    const unsigned fbcr = be16(regs + 2);
    if ((tvmr & ~0xFu) || (fbcr & ~0x1Fu))
        throw std::invalid_argument("reserved VDP1 TVMR/FBCR bits");
    const unsigned mode = tvmr & 7u;
    unsigned width = 512, height = 256, bits = 16;
    switch (mode) {
    case 0:
    case 2:
    case 4:
        break;
    case 1:
        width = 1024;
        bits = 8;
        break;
    case 3:
        height = 512;
        bits = 8;
        break;
    default:
        throw std::invalid_argument("prohibited TVMR framebuffer mode");
    }
    const bool vbe = (tvmr & 8u) != 0;
    const bool fcm = (fbcr & 2u) != 0;
    const bool fct = (fbcr & 1u) != 0;
    const bool die = (fbcr & 8u) != 0;
    if ((vbe && !(fcm && fct)) || (!vbe && !fcm && fct) ||
        ((mode == 2 || mode == 3 || mode == 4) && die))
        throw std::invalid_argument("prohibited TVMR/FBCR switching combination");
    if (static_cast<std::size_t>(width) * height * (bits / 8u) != kFrameBytes)
        throw std::logic_error("VDP1 buffer geometry is not 256 KiB");
    return FrameMode{mode, width, height, bits, vbe, fcm, fct};
}

inline Pixel inspect_private(const std::uint8_t* frame, std::size_t byte_count,
                             const FrameMode& mode, unsigned x, unsigned y) {
    if (!frame || byte_count != kFrameBytes)
        throw std::invalid_argument("full 256-KiB VDP1 drawing frame required");
    if (x >= mode.width || y >= mode.height)
        throw std::out_of_range("pixel position outside framebuffer");
    if (!((mode.width == 512 && mode.height == 256 && mode.bits_per_pixel == 16) ||
          (mode.width == 1024 && mode.height == 256 && mode.bits_per_pixel == 8) ||
          (mode.width == 512 && mode.height == 512 && mode.bits_per_pixel == 8)))
        throw std::invalid_argument("unsupported VDP1 framebuffer geometry");
    const std::size_t at = (static_cast<std::size_t>(y) * mode.width + x) *
                           (mode.bits_per_pixel / 8u);
    const std::uint16_t code =
        mode.bits_per_pixel == 8 ? frame[at] : be16(frame + at);
    if (code == 0)
        return {PixelClass::transparent_zero, code};
    if (mode.bits_per_pixel == 8)
        return {PixelClass::indexed8_or_control, code};
    return {(code & 0x8000u) ? PixelClass::rgb555_candidate :
                               PixelClass::palette_or_shadow_control, code};
}

inline Counts summarize_private(const std::uint8_t* frame, std::size_t size,
                                const FrameMode& mode) {
    if (!frame || size != kFrameBytes)
        throw std::invalid_argument("full private framebuffer required");
    Counts result;
    for (unsigned y = 0; y < mode.height; ++y) {
        for (unsigned x = 0; x < mode.width; ++x) {
            const Pixel p = inspect_private(frame, size, mode, x, y);
            switch (p.category) {
            case PixelClass::transparent_zero: ++result.transparent_zero; break;
            case PixelClass::indexed8_or_control: ++result.indexed8_or_control; break;
            case PixelClass::rgb555_candidate: ++result.rgb555_candidate; break;
            case PixelClass::palette_or_shadow_control:
                ++result.palette_or_shadow_control;
                break;
            }
        }
    }
    return result;
}

}  // namespace vdp1
}  // namespace thor2
