#pragma once
// Stage62: ORIGINAL-ASSET-FREE deterministic gameplay sandbox.
// Gameplay logic is not reconstructed from The Story of Thor 2. All tiles,
// geometry, collectibles and rules below are synthetic test fixtures.
// No SDL, libnx, clock, filesystem, floats, ROM or original-game dependencies.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace thor2::sandbox {

constexpr int kTile = 16;
constexpr int kMapWidth = 48;
constexpr int kMapHeight = 30;
constexpr int kScreenWidth = 320;
constexpr int kScreenHeight = 240;
constexpr int kActorSide = 12;
constexpr int kCrystalCount = 3;
constexpr int kCardinalStep = 3;
constexpr int kDiagonalStep = 2;
constexpr int kGoalTileX = 43;
constexpr int kGoalTileY = 26;
constexpr std::uint32_t kFixedTicksPerSecond = 60;

struct Input {
    bool left = false;
    bool right = false;
    bool up = false;
    bool down = false;
    bool interact = false;
    bool restart = false;
};

struct Camera {
    int x = 0;
    int y = 0;
};

struct Crystal {
    int tile_x;
    int tile_y;
    bool collected = false;
};

struct State {
    int x = 2 * kTile + 2;
    int y = 2 * kTile + 2;
    std::array<Crystal, kCrystalCount> crystals{{
        {5, 4, false}, {15, 10, false}, {32, 23, false}
    }};
    std::uint64_t ticks = 0;
    bool won = false;
    bool interact_held = false;
};

class Game {
public:
    Game() {
        for (int y = 0; y < kMapHeight; ++y) {
            for (int x = 0; x < kMapWidth; ++x) {
                const bool outer = (x == 0 || y == 0 ||
                                    x == kMapWidth - 1 || y == kMapHeight - 1);
                // Artificial test-room walls with deliberately placed gaps.
                const bool column_a = (x == 8 && y >= 3 && y <= 16 && y != 10);
                const bool column_b = (x == 22 && y >= 10 && y <= 24 && y != 14);
                const bool corridor = (y == 20 && x >= 9 && x <= 33 && x != 15);
                walls_[static_cast<std::size_t>(y * kMapWidth + x)] =
                    static_cast<std::uint8_t>(outer || column_a || column_b || corridor);
            }
        }
    }

    const State& state() const { return state_; }

    bool blocked_tile(int x, int y) const {
        if (x < 0 || y < 0 || x >= kMapWidth || y >= kMapHeight)
            return true;
        return walls_[static_cast<std::size_t>(y * kMapWidth + x)] != 0;
    }

    int collected() const {
        return static_cast<int>(std::count_if(
            state_.crystals.begin(), state_.crystals.end(),
            [](const Crystal& c) { return c.collected; }));
    }

    bool collides_at(int x, int y) const {
        // Actor covers a 12x12 AABB in world-pixel coordinates.
        if (x < 0 || y < 0 ||
            x > kMapWidth * kTile - kActorSide ||
            y > kMapHeight * kTile - kActorSide)
            return true;
        const int x0 = x / kTile, x1 = (x + kActorSide - 1) / kTile;
        const int y0 = y / kTile, y1 = (y + kActorSide - 1) / kTile;
        return blocked_tile(x0, y0) || blocked_tile(x1, y0) ||
               blocked_tile(x0, y1) || blocked_tile(x1, y1);
    }

    void reset() { state_ = State{}; }

    void tick(const Input& input) {
        if (input.restart) {
            reset();
            return;
        }
        if (state_.won) {
            ++state_.ticks;
            state_.interact_held = input.interact;
            return;
        }
        const int h = static_cast<int>(input.right) - static_cast<int>(input.left);
        const int v = static_cast<int>(input.down) - static_cast<int>(input.up);
        const int speed = (h && v) ? kDiagonalStep : kCardinalStep;

        // One-pixel swept movement on each axis avoids tunneling and permits
        // sliding along a wall. Fixed integer steps ensure deterministic CI.
        for (int i = 0; i < speed && h; ++i) {
            if (collides_at(state_.x + h, state_.y)) break;
            state_.x += h;
        }
        for (int i = 0; i < speed && v; ++i) {
            if (collides_at(state_.x, state_.y + v)) break;
            state_.y += v;
        }

        for (auto& crystal : state_.crystals) {
            if (crystal.collected) continue;
            const int cx = crystal.tile_x * kTile + kTile / 2;
            const int cy = crystal.tile_y * kTile + kTile / 2;
            // Pickup if player's 12x12 AABB overlaps an 8x8 object.
            if (state_.x < cx + 4 && state_.x + kActorSide > cx - 4 &&
                state_.y < cy + 4 && state_.y + kActorSide > cy - 4)
                crystal.collected = true;
        }
        const int px = state_.x + kActorSide / 2;
        const int py = state_.y + kActorSide / 2;
        const int gx = kGoalTileX * kTile + kTile / 2;
        const int gy = kGoalTileY * kTile + kTile / 2;
        const int diff_x = px - gx, diff_y = py - gy;
        const bool near_goal = diff_x * diff_x + diff_y * diff_y <= 22 * 22;
        if (input.interact && !state_.interact_held &&
            near_goal && collected() == kCrystalCount)
            state_.won = true;
        state_.interact_held = input.interact;
        ++state_.ticks;
    }

    Camera camera() const {
        const int desired_x = state_.x + kActorSide / 2 - kScreenWidth / 2;
        const int desired_y = state_.y + kActorSide / 2 - kScreenHeight / 2;
        return {
            std::clamp(desired_x, 0, kMapWidth * kTile - kScreenWidth),
            std::clamp(desired_y, 0, kMapHeight * kTile - kScreenHeight)
        };
    }

    // State hash deliberately includes only logical gameplay, not images or
    // platform details. Stable across x86/ARM and replay frame rates.
    std::uint64_t state_hash() const {
        std::uint64_t h = 14695981039346656037ull;
        auto mix = [&h](std::uint64_t value) {
            for (unsigned i = 0; i < 8; ++i) {
                h ^= (value >> (8 * i)) & 255u;
                h *= 1099511628211ull;
            }
        };
        mix(static_cast<std::uint64_t>(state_.x));
        mix(static_cast<std::uint64_t>(state_.y));
        mix(state_.ticks);
        mix(state_.won);
        mix(state_.interact_held);
        for (const auto& c : state_.crystals) mix(c.collected);
        return h;
    }

private:
    std::array<std::uint8_t, kMapWidth * kMapHeight> walls_{};
    State state_{};
};

}  // namespace thor2::sandbox
