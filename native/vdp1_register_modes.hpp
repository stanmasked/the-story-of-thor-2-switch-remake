#pragma once
// VDP1 PTMR plot-trigger mode values from the Sega Saturn VDP1 hardware manual.
#include <cstdint>

namespace thor2 {
namespace vdp1 {

enum class PlotTriggerMode : std::uint16_t {
    idle_at_frame_change = 0,
    start_when_written = 1,
    automatic_at_frame_start = 2,
};

constexpr bool is_valid_plot_trigger_mode(std::uint16_t value) noexcept {
    return value <= static_cast<std::uint16_t>(
                        PlotTriggerMode::automatic_at_frame_start);
}

}  // namespace vdp1
}  // namespace thor2
