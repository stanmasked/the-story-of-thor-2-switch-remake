#pragma once
// Stage63: host-testable 4:3 software surface presenter for libnx's linear RGBA8 FB.
// Surface words are authored as 0xRRGGBBAA. libnx RGBA8 stores R in the low byte,
// so convert explicitly rather than memcpy-ing host-native 32-bit words.
// Caller must pair framebufferBegin/framebufferEnd and pass stride in pixels.
#include "../software_renderer.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace thor2::platform {

constexpr std::uint32_t pack_rgba8_for_libnx(std::uint32_t rgba) {
    const std::uint32_t r = (rgba >> 24) & 0xffu;
    const std::uint32_t g = (rgba >> 16) & 0xffu;
    const std::uint32_t b = (rgba >> 8) & 0xffu;
    const std::uint32_t a = rgba & 0xffu;
    return r | (g << 8) | (b << 16) | (a << 24);
}

inline bool present_rgba8(const sandbox::Surface& source,
                          std::uint32_t* framebuffer,
                          std::size_t framebuffer_pixels,
                          int width, int height, std::size_t stride_pixels) {
    if (!framebuffer || width < 4 || height < 3 ||
        stride_pixels < static_cast<std::size_t>(width) ||
        static_cast<std::size_t>(height) >
            std::numeric_limits<std::size_t>::max() / stride_pixels)
        return false;
    const std::size_t required = stride_pixels * static_cast<std::size_t>(height);
    if (required > framebuffer_pixels ||
        source.pixels().size() !=
            static_cast<std::size_t>(sandbox::kScreenWidth * sandbox::kScreenHeight))
        return false;

    const std::uint32_t opaque_black = pack_rgba8_for_libnx(sandbox::rgba(0,0,0,255));
    std::fill(framebuffer, framebuffer + required, opaque_black);

    // Preserve the source 4:3 aspect ratio, center it, and use nearest-neighbor
    // scaling. At 1280x720 this gives 960x720 and 160-pixel pillarboxes.
    int out_width = width;
    int out_height = (out_width * 3) / 4;
    if (out_height > height) {
        out_height = height;
        out_width = (out_height * 4) / 3;
    }
    out_width = std::max(1, out_width);
    out_height = std::max(1, out_height);
    const int offset_x = (width - out_width) / 2;
    const int offset_y = (height - out_height) / 2;
    const auto& pixels = source.pixels();

    for (int y = 0; y < out_height; ++y) {
        const int sy = (y * sandbox::kScreenHeight) / out_height;
        for (int x = 0; x < out_width; ++x) {
            const int sx = (x * sandbox::kScreenWidth) / out_width;
            const std::size_t src =
                static_cast<std::size_t>(sy * sandbox::kScreenWidth + sx);
            const std::size_t dst =
                static_cast<std::size_t>(offset_y + y) * stride_pixels +
                static_cast<std::size_t>(offset_x + x);
            framebuffer[dst] = pack_rgba8_for_libnx(pixels[src]);
        }
    }
    return true;
}

}  // namespace thor2::platform
