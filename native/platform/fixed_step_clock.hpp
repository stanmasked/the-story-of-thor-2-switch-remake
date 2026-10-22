#pragma once
// Fixed-step simulation clock shared by platform frontends.
// The caller supplies monotonic hardware ticks and their frequency; this class
// has no libnx dependency, so scheduling behavior can be unit-tested on host.
#include <cstdint>

namespace thor2::platform {

class FixedStepClock {
public:
    explicit FixedStepClock(std::uint64_t tick_frequency,
                            std::uint32_t target_hz = 60,
                            std::uint32_t max_steps_per_frame = 5)
        : frequency_(tick_frequency),
          step_ticks_(target_hz == 0 ? 0 : tick_frequency / target_hz),
          max_frame_delta_(tick_frequency / 4),
          max_steps_per_frame_(max_steps_per_frame),
          valid_(tick_frequency > 0 && target_hz > 0 &&
                 tick_frequency / target_hz > 0 &&
                 max_steps_per_frame > 0) {}

    bool valid() const { return valid_; }
    std::uint64_t step_ticks() const { return step_ticks_; }
    std::uint64_t dropped_ticks() const { return dropped_ticks_; }

    void reset(std::uint64_t now) {
        last_tick_ = now;
        accumulator_ = 0;
        dropped_ticks_ = 0;
        initialized_ = true;
    }

    std::uint32_t advance(std::uint64_t now) {
        if (!valid_) return 0;
        if (!initialized_) {
            reset(now);
            return 0;
        }

        std::uint64_t delta = now >= last_tick_ ? now - last_tick_ : 0;
        last_tick_ = now;

        // Cap stalls at 250 ms, then cap catch-up work per rendered frame.
        // This prevents a slow frame from causing an unbounded catch-up spiral.
        if (delta > max_frame_delta_) {
            dropped_ticks_ += (delta - max_frame_delta_) / step_ticks_;
            delta = max_frame_delta_;
        }
        accumulator_ += delta;

        std::uint32_t steps = 0;
        while (accumulator_ >= step_ticks_ &&
               steps < max_steps_per_frame_) {
            accumulator_ -= step_ticks_;
            ++steps;
        }
        if (accumulator_ >= step_ticks_) {
            dropped_ticks_ += accumulator_ / step_ticks_;
            accumulator_ %= step_ticks_;
        }
        return steps;
    }

private:
    std::uint64_t frequency_;
    std::uint64_t step_ticks_;
    std::uint64_t max_frame_delta_;
    std::uint32_t max_steps_per_frame_;
    bool valid_;
    bool initialized_ = false;
    std::uint64_t last_tick_ = 0;
    std::uint64_t accumulator_ = 0;
    std::uint64_t dropped_ticks_ = 0;
};

}  // namespace thor2::platform
