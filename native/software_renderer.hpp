#pragma once
// Stage62: pixel framebuffer renderer using ONLY procedurally colored rectangles.
// This is a host/Switch-portable software rasterizer, not restored game art.
// Pixel words are 0xRRGGBBAA. No OpenGL/SDL, files or Sega assets.
#include "gameplay.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace thor2::sandbox {

constexpr std::uint32_t rgba(std::uint8_t r, std::uint8_t g,
                             std::uint8_t b, std::uint8_t a = 255) {
    return (static_cast<std::uint32_t>(r) << 24) |
           (static_cast<std::uint32_t>(g) << 16) |
           (static_cast<std::uint32_t>(b) << 8) |
           static_cast<std::uint32_t>(a);
}

constexpr std::uint32_t kFloorA = rgba(25, 40, 49);
constexpr std::uint32_t kFloorB = rgba(30, 48, 55);
constexpr std::uint32_t kWall = rgba(82, 97, 105);
constexpr std::uint32_t kWallEdge = rgba(126, 142, 145);
constexpr std::uint32_t kHero = rgba(234, 192, 92);
constexpr std::uint32_t kHeroHighlight = rgba(255, 235, 147);
constexpr std::uint32_t kCrystal = rgba(96, 225, 224);
constexpr std::uint32_t kCrystalFrame = rgba(49, 144, 159);
constexpr std::uint32_t kExitLocked = rgba(112, 69, 103);
constexpr std::uint32_t kExitOpen = rgba(94, 197, 120);
constexpr std::uint32_t kHud = rgba(17, 26, 34);
constexpr std::uint32_t kHudEmpty = rgba(75, 91, 101);

class Surface {
public:
    Surface() : pixels_(static_cast<std::size_t>(kScreenWidth * kScreenHeight),
                         rgba(0, 0, 0)) {}
    static constexpr int width() { return kScreenWidth; }
    static constexpr int height() { return kScreenHeight; }

    std::uint32_t pixel(int x, int y) const {
        if (x < 0 || y < 0 || x >= kScreenWidth || y >= kScreenHeight)
            throw std::out_of_range("pixel outside surface");
        return pixels_[static_cast<std::size_t>(y * kScreenWidth + x)];
    }

    const std::vector<std::uint32_t>& pixels() const { return pixels_; }

    void clear(std::uint32_t color) {
        std::fill(pixels_.begin(), pixels_.end(), color);
    }

    void rect(int x, int y, int width, int height, std::uint32_t color) {
        if (width <= 0 || height <= 0) return;
        // Renderer only accepts moderate game-relative coordinates, so
        // signed integer rectangle sums are safe (never untrusted ISO data).
        if (x < -8192 || x > 8192 || y < -8192 || y > 8192 ||
            width > 8192 || height > 8192)
            throw std::invalid_argument("rectangle outside safe coordinate range");
        const int x0 = std::max(0, x), x1 = std::min(kScreenWidth, x + width);
        const int y0 = std::max(0, y), y1 = std::min(kScreenHeight, y + height);
        for (int yy = y0; yy < y1; ++yy) {
            for (int xx = x0; xx < x1; ++xx)
                pixels_[static_cast<std::size_t>(yy * kScreenWidth + xx)] = color;
        }
    }

    std::uint64_t fnv1a() const {
        std::uint64_t h = 14695981039346656037ull;
        for (std::uint32_t pixel : pixels_) {
            for (unsigned shift = 0; shift < 32; shift += 8) {
                h ^= (pixel >> shift) & 255u;
                h *= 1099511628211ull;
            }
        }
        return h;
    }

private:
    std::vector<std::uint32_t> pixels_;
};

inline void render(const Game& game, Surface& surface) {
    const auto cam = game.camera();
    surface.clear(kFloorA);

    const int tx0 = cam.x / kTile;
    const int ty0 = cam.y / kTile;
    const int tx1 = std::min(kMapWidth, (cam.x + kScreenWidth + kTile - 1) / kTile);
    const int ty1 = std::min(kMapHeight, (cam.y + kScreenHeight + kTile - 1) / kTile);
    for (int y = ty0; y < ty1; ++y) {
        for (int x = tx0; x < tx1; ++x) {
            const int px = x * kTile - cam.x;
            const int py = y * kTile - cam.y;
            surface.rect(px, py, kTile, kTile,
                         ((x + y) & 1) ? kFloorB : kFloorA);
            if (game.blocked_tile(x, y)) {
                surface.rect(px, py, kTile, kTile, kWall);
                surface.rect(px, py, kTile, 2, kWallEdge);
            }
        }
    }

    // Goal beacon and collectibles are original synthetic rectangles.
    const int exit_x = kGoalTileX * kTile - cam.x;
    const int exit_y = kGoalTileY * kTile - cam.y;
    const std::uint32_t goal_color =
        game.collected() == kCrystalCount ? kExitOpen : kExitLocked;
    surface.rect(exit_x + 1, exit_y + 1, kTile - 2, kTile - 2, goal_color);
    surface.rect(exit_x + 5, exit_y + 5, 6, 6, kHud);

    for (const auto& crystal : game.state().crystals) {
        if (crystal.collected) continue;
        const int x = crystal.tile_x * kTile - cam.x;
        const int y = crystal.tile_y * kTile - cam.y;
        surface.rect(x + 3, y + 3, 10, 10, kCrystalFrame);
        surface.rect(x + 5, y + 5, 6, 6, kCrystal);
    }

    const int hx = game.state().x - cam.x;
    const int hy = game.state().y - cam.y;
    surface.rect(hx, hy, kActorSide, kActorSide, kHero);
    // Two facial pixels and shoulder band distinguish placeholder actor.
    surface.rect(hx + 3, hy + 3, 2, 2, kHud);
    surface.rect(hx + 8, hy + 3, 2, 2, kHud);
    surface.rect(hx + 2, hy + 1, 8, 1, kHeroHighlight);

    // A fixed HUD is independent of world camera.
    surface.rect(0, 0, 88, 12, kHud);
    for (int i = 0; i < kCrystalCount; ++i) {
        surface.rect(6 + i * 15, 3, 9, 6,
                     i < game.collected() ? kCrystal : kHudEmpty);
    }
    if (game.state().won)
        surface.rect(58, 3, 23, 6, kExitOpen);
}

}  // namespace thor2::sandbox
