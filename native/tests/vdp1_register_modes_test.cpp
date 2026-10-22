// Synthetic checks for the VDP1 PTMR mode reference model.
#include "vdp1_register_modes.hpp"
#include <cassert>
#include <cstdint>

using thor2::vdp1::PlotTriggerMode;
using thor2::vdp1::is_valid_plot_trigger_mode;

int main() {
    static_assert(static_cast<std::uint16_t>(PlotTriggerMode::idle_at_frame_change) == 0u,
                  "PTMR 00b is idle");
    static_assert(static_cast<std::uint16_t>(PlotTriggerMode::start_when_written) == 1u,
                  "PTMR 01b starts on write");
    static_assert(static_cast<std::uint16_t>(PlotTriggerMode::automatic_at_frame_start) == 2u,
                  "PTMR 10b starts automatically at frame start");
    assert(is_valid_plot_trigger_mode(0u));
    assert(is_valid_plot_trigger_mode(1u));
    assert(is_valid_plot_trigger_mode(2u));
    assert(!is_valid_plot_trigger_mode(3u));
    assert(!is_valid_plot_trigger_mode(0xFFFFu));
    return 0;
}
