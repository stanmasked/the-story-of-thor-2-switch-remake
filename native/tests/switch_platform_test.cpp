// Stage63 host tests for platform input and RGBA8 framebuffer presentation.
// All graphics and input are synthetic; no libnx or original game resources.
#include "platform/input_mapping.hpp"
#include "platform/framebuffer_presenter.hpp"
#include "platform/fixed_step_clock.hpp"
#include "platform/input_accumulator.hpp"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

using thor2::sandbox::Game;
using thor2::sandbox::Surface;
using thor2::sandbox::rgba;
using thor2::platform::ButtonMasks;
using thor2::platform::map_buttons;
using thor2::platform::pack_rgba8_for_libnx;
using thor2::platform::present_rgba8;
using thor2::platform::InputAccumulator;

int main() {
    constexpr std::uint64_t LEFT = 1ull << 0;
    constexpr std::uint64_t RIGHT = 1ull << 1;
    constexpr std::uint64_t UP = 1ull << 2;
    constexpr std::uint64_t DOWN = 1ull << 3;
    constexpr std::uint64_t ACTION = 1ull << 4;
    constexpr std::uint64_t RESTART = 1ull << 5;
    constexpr std::uint64_t QUIT = 1ull << 6;
    const ButtonMasks masks{LEFT, RIGHT, UP, DOWN, ACTION, RESTART, QUIT};

    {
        const auto m = map_buttons(LEFT | DOWN | ACTION, 0, masks);
        assert(m.gameplay.left && m.gameplay.down && m.gameplay.interact);
        assert(!m.gameplay.right && !m.gameplay.up);
        assert(!m.gameplay.restart && !m.quit);
    }
    {
        // Restart and quit are edge-triggered; held-only bits do not repeat.
        const auto m = map_buttons(RESTART | QUIT, 0, masks);
        assert(!m.gameplay.restart && !m.quit);
        const auto d = map_buttons(0, RESTART | QUIT, masks);
        assert(d.gameplay.restart && d.quit);
    }
    {
        const auto m = map_buttons(LEFT | RIGHT | UP | DOWN, 0, masks);
        Game game;
        const int x = game.state().x, y = game.state().y;
        game.tick(m.gameplay);
        assert(game.state().x == x && game.state().y == y);
    }
    {
        thor2::platform::FixedStepClock clock(600, 60, 5);
        assert(clock.valid());
        assert(clock.step_ticks() == 10);
        clock.reset(0);
        assert(clock.advance(0) == 0);
        assert(clock.advance(9) == 0);
        assert(clock.advance(10) == 1);
        assert(clock.advance(35) == 2); // 25 ticks elapsed, 2 steps + 5 carried.
        assert(clock.advance(40) == 1); // carried remainder completes next step.
        const auto dropped_before_stall = clock.dropped_ticks();
        assert(clock.advance(1040) == 5); // 1000-tick stall is bounded to 150.
        assert(clock.dropped_ticks() > dropped_before_stall);
        clock.reset(9000);
        assert(clock.advance(9000) == 0);
        assert(clock.advance(9010) == 1);
    }
    {
        thor2::platform::FixedStepClock invalid_zero_frequency(0);
        thor2::platform::FixedStepClock invalid_rate(600, 0);
        thor2::platform::FixedStepClock invalid_catchup(600, 60, 0);
        assert(!invalid_zero_frequency.valid());
        assert(!invalid_rate.valid());
        assert(!invalid_catchup.valid());
        assert(invalid_zero_frequency.advance(100) == 0);
    }
    {
        // Constant gameplay input must produce the same state at 30, 60 and
        // 120 Hz render-loop cadences when all runs cover the same elapsed time.
        const auto run_for_one_second = [](std::uint64_t render_interval) {
            Game game;
            thor2::platform::FixedStepClock clock(6000, 60, 5);
            InputAccumulator input;
            assert(clock.valid());
            clock.reset(0);
            thor2::sandbox::Input held{};
            held.right = true;
            for (std::uint64_t now = render_interval; now <= 6000;
                 now += render_interval) {
                input.sample(held);
                const auto steps = clock.advance(now);
                for (std::uint32_t i = 0; i < steps; ++i)
                    game.tick(input.consume_tick());
            }
            assert(game.state().ticks == 60);
            return game.state_hash();
        };
        const auto hash_30hz = run_for_one_second(200);
        const auto hash_60hz = run_for_one_second(100);
        const auto hash_120hz = run_for_one_second(50);
        assert(hash_30hz == hash_60hz);
        assert(hash_60hz == hash_120hz);
    }
    {
        // A brief interaction sampled between fixed ticks must survive until
        // one simulation tick, even if the button is released before consume.
        InputAccumulator input;
        thor2::sandbox::Input pressed{};
        pressed.left = true;
        pressed.interact = true;
        pressed.restart = true;
        input.sample(pressed);
        thor2::sandbox::Input released{};
        input.sample(released);
        assert(input.has_pending_edge());
        const auto tick = input.consume_tick();
        assert(!tick.left && tick.interact && tick.restart);
        assert(!input.has_pending_edge());
        const auto next = input.consume_tick();
        assert(!next.interact && !next.restart);
    }
    {
        // Latest held directions are used, while a restart edge waits for a
        // tick if the render loop advanced before the fixed-step deadline.
        InputAccumulator input;
        thor2::sandbox::Input direction{};
        direction.right = true;
        input.sample(direction);
        thor2::sandbox::Input restart{};
        restart.restart = true;
        input.sample(restart);
        const auto tick = input.consume_tick();
        assert(!tick.right && tick.restart);
        assert(!input.has_pending_edge());
    }
    {
        assert(pack_rgba8_for_libnx(rgba(0x12,0x34,0x56,0x78)) == 0x78563412u);
        assert(pack_rgba8_for_libnx(rgba(255,0,0,255)) == 0xff0000ffu);
        assert(pack_rgba8_for_libnx(rgba(0,0,0,255)) == 0xff000000u);
    }
    {
        Surface src;
        src.clear(rgba(0x12,0x34,0x56,0x78));
        std::vector<std::uint32_t> dst(1284u * 720u, 0xdeadbeefu);
        assert(present_rgba8(src,dst.data(),dst.size(),1280,720,1284));
        // 4:3 source in 16:9 output: 960x720 centered, 160px side bars.
        assert(dst[0] == 0xff000000u);
        assert(dst[static_cast<std::size_t>(160)] == 0x78563412u);
        assert(dst[static_cast<std::size_t>(1119)] == 0x78563412u);
        assert(dst[static_cast<std::size_t>(1120)] == 0xff000000u);
        assert(dst[static_cast<std::size_t>(719) * 1284u + 160u] == 0x78563412u);
        // Padding beyond visible width must remain black.
        assert(dst[1279] == 0xff000000u);
        assert(dst[1280] == 0xff000000u);
        assert(dst[1283] == 0xff000000u);
        assert(dst[static_cast<std::size_t>(719) * 1284u + 1283u] == 0xff000000u);
    }
    {
        Surface src;
        src.clear(rgba(0,0,0,255));
        src.rect(0,0,1,1,rgba(255,0,0,255));
        src.rect(319,239,1,1,rgba(0,255,0,255));
        std::vector<std::uint32_t> dst(640u * 480u);
        assert(present_rgba8(src,dst.data(),dst.size(),640,480,640));
        assert(dst[0] == 0xff0000ffu);
        assert(dst[static_cast<std::size_t>(479) * 640u + 639u] == 0xff00ff00u);
    }
    {
        Surface src;
        std::vector<std::uint32_t> dst(1280u * 720u);
        assert(!present_rgba8(src,nullptr,dst.size(),1280,720,1280));
        assert(!present_rgba8(src,dst.data(),dst.size(),1280,720,1279));
        assert(!present_rgba8(src,dst.data(),100,1280,720,1280));
        assert(!present_rgba8(src,dst.data(),dst.size(),3,720,1280));
        assert(!present_rgba8(src,dst.data(),dst.size(),1280,2,1280));
        assert(!present_rgba8(src,dst.data(),dst.size(),9000,720,9000));
    }
    {
        // The actual framebuffer output must use the packed libnx byte order,
        // not the host renderer's 0xRRGGBBAA word representation.
        Surface src;
        src.clear(rgba(255,0,0,255));
        std::vector<std::uint32_t> dst(320u * 240u);
        assert(present_rgba8(src,dst.data(),dst.size(),320,240,320));
        assert(dst[static_cast<std::size_t>(120) * 320u + 160u] == 0xff0000ffu);
    }
    return 0;
}
