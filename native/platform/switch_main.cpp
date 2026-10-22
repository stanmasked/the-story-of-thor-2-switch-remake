// Stage63: first libnx frontend for the original-asset-free C++ gameplay sandbox.
// Built with devkitPro/libnx into an NRO. Not yet the original Saturn game.
#include <switch.h>
#include <cstddef>
#include <cstdint>

#include "gameplay.hpp"
#include "software_renderer.hpp"
#include "platform/input_mapping.hpp"
#include "platform/fixed_step_clock.hpp"
#include "platform/framebuffer_presenter.hpp"

namespace {
constexpr u32 kFramebufferWidth = 1280;
constexpr u32 kFramebufferHeight = 720;

const thor2::platform::ButtonMasks kButtons{
    HidNpadButton_AnyLeft,
    HidNpadButton_AnyRight,
    HidNpadButton_AnyUp,
    HidNpadButton_AnyDown,
    HidNpadButton_A,
    HidNpadButton_B,
    HidNpadButton_Plus
};
}

int main(int, char**) {
    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    PadState pad{};
    padInitializeDefault(&pad);

    Framebuffer framebuffer{};
    Result rc = framebufferCreate(&framebuffer, nwindowGetDefault(),
                                  kFramebufferWidth, kFramebufferHeight,
                                  PIXEL_FORMAT_RGBA_8888, 2);
    if (R_FAILED(rc))
        return 1;
    rc = framebufferMakeLinear(&framebuffer);
    if (R_FAILED(rc)) {
        framebufferClose(&framebuffer);
        return 2;
    }

    thor2::sandbox::Game game;
    thor2::sandbox::Surface surface;
    thor2::platform::FixedStepClock clock(armGetSystemTickFreq());
    if (!clock.valid()) {
        framebufferClose(&framebuffer);
        return 3;
    }
    clock.reset(armGetSystemTick());
    bool restart_pending = false;

    while (appletMainLoop()) {
        padUpdate(&pad);
        const std::uint64_t held = padGetButtons(&pad);
        const std::uint64_t down = padGetButtonsDown(&pad);
        const auto mapped = thor2::platform::map_buttons(held, down, kButtons);
        if (mapped.quit)
            break;

        // The simulation advances at 60 Hz regardless of render-loop cadence.
        // Preserve edge-triggered restart if a render frame has no simulation tick.
        restart_pending = restart_pending || mapped.gameplay.restart;
        const std::uint32_t steps = clock.advance(armGetSystemTick());
        for (std::uint32_t i = 0; i < steps; ++i) {
            auto input = mapped.gameplay;
            input.restart = restart_pending;
            game.tick(input);
            restart_pending = false;
        }
        thor2::sandbox::render(game, surface);

        u32 stride_bytes = 0;
        auto* output = static_cast<std::uint32_t*>(
            framebufferBegin(&framebuffer, &stride_bytes));
        if (!output)
            break;
        const std::size_t stride_pixels = stride_bytes / sizeof(std::uint32_t);
        const bool rendered = thor2::platform::present_rgba8(
            surface, output, stride_pixels * kFramebufferHeight,
            static_cast<int>(kFramebufferWidth),
            static_cast<int>(kFramebufferHeight), stride_pixels);
        framebufferEnd(&framebuffer);
        if (!rendered)
            break;
    }

    framebufferClose(&framebuffer);
    return 0;
}
