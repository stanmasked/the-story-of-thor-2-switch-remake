#pragma once
// Fixed-step simulation clock shared by platform frontends.
// The caller supplies monotonic hardware ticks and their frequency; this class
// has no libnx dependency, so scheduling behavior can be unit-tested on host.
#include <cstdint>
#include <limits>

namespace thor2::platform {

class FixedStepClock {
public:
    explicit FixedStepClock(std::uint64_t tick_frequency,
                            std::uint32_t target_hz = 60,
                            std::uint32_t max_steps_per_frame = 5)
        : tick_frequency_(tick_frequency),
          target_hz_(target_hz),
          step_ticks_(target_hz == 0 ? 0 : tick_frequency / target_hz),
          max_frame_delta_(tick_frequency / 4),
          max_steps_per_frame_(max_steps_per_frame),
          valid_(tick_frequency > 0 && target_hz > 0 &&
                 tick_frequency / target_hz > 0 &&
                 tick_frequency <=
                     std::numeric_limits<std::uint64_t>::max() / target_hz &&
                 max_steps_per_frame > 0) {}

    bool valid() const { return valid_; }

    // Nominal whole hardware ticks per simulation step, for diagnostics only.
    // Scheduling uses scaled time so non-divisible frequencies do not drift.
    std::uint64_t step_ticks() const { return step_ticks_; }
    std::uint64_t dropped_ticks() const { return dropped_ticks_; }

    void reset(std::uint64_t now) {
        last_tick_ = now;
        scaled_accumulator_ = 0;
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
        // Scaled units are hardware ticks * target_hz; one simulation step
        // consumes exactly tick_frequency_ units, preserving fractional timing.
        if (delta > max_frame_delta_) {
            const std::uint64_t discarded_delta = delta - max_frame_delta_;
            add_dropped_ticks_(scaled_whole_steps_(discarded_delta));
            delta = max_frame_delta_;
        }

        const std::uint64_t scaled_delta = delta * target_hz_;
        if (scaled_delta >
            std::numeric_limits<std::uint64_t>::max() - scaled_accumulator_) {
            // Saturation is defensive for pathological synthetic frequencies.
            scaled_accumulator_ = std::numeric_limits<std::uint64_t>::max();
        } else {
            scaled_accumulator_ += scaled_delta;
        }

        std::uint32_t steps = 0;
        while (scaled_accumulator_ >= tick_frequency_ &&
               steps < max_steps_per_frame_) {
            scaled_accumulator_ -= tick_frequency_;
            ++steps;
        }
        if (scaled_accumulator_ >= tick_frequency_) {
            add_dropped_ticks_(scaled_accumulator_ / tick_frequency_);
            scaled_accumulator_ %= tick_frequency_;
        }
        return steps;
    }

private:
    std::uint64_t scaled_whole_steps_(std::uint64_t delta) const {
        // Divide first so the calculation remains safe for large elapsed times.
        const std::uint64_t whole_seconds = delta / tick_frequency_;
        const std::uint64_t remainder = delta % tick_frequency_;
        const std::uint64_t max =
            std::numeric_limits<std::uint64_t>::max();
        if (whole_seconds > max / target_hz_)
            return max;
        const std::uint64_t whole_steps = whole_seconds * target_hz_;
        const std::uint64_t fractional_steps =
            (remainder * target_hz_) / tick_frequency_;
        if (fractional_steps > max - whole_steps)
            return max;
        return whole_steps + fractional_steps;
    }

    void add_dropped_ticks_(std::uint64_t count) {
        const std::uint64_t max =
            std::numeric_limits<std::uint64_t>::max();
        dropped_ticks_ = count > max - dropped_ticks_
                             ? max
                             : dropped_ticks_ + count;
    }

    std::uint64_t tick_frequency_;
    std::uint32_t target_hz_;
    std::uint64_t step_ticks_;
    std::uint64_t max_frame_delta_;
    std::uint32_t max_steps_per_frame_;
    bool valid_;
    bool initialized_ = false;
    std::uint64_t last_tick_ = 0;
    std::uint64_t scaled_accumulator_ = 0;
    std::uint64_t dropped_ticks_ = 0;
};

}  // namespace thor2::platform
