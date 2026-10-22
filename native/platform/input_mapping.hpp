#pragma once
// Stage63: testable translation from platform button bitmasks to gameplay input.
// Kept independent of libnx so input semantics can be tested on the host.
#include "../gameplay.hpp"
#include <cstdint>

namespace thor2::platform {

struct ButtonMasks {
    std::uint64_t left = 0;
    std::uint64_t right = 0;
    std::uint64_t up = 0;
    std::uint64_t down = 0;
    std::uint64_t action = 0;
    std::uint64_t restart = 0;
    std::uint64_t quit = 0;
};

struct MappedInput {
    sandbox::Input gameplay{};
    bool quit = false;
};

inline MappedInput map_buttons(std::uint64_t held,
                               std::uint64_t newly_pressed,
                               const ButtonMasks& masks) {
    MappedInput result;
    result.gameplay.left = (held & masks.left) != 0;
    result.gameplay.right = (held & masks.right) != 0;
    result.gameplay.up = (held & masks.up) != 0;
    result.gameplay.down = (held & masks.down) != 0;
    result.gameplay.interact = (held & masks.action) != 0;
    result.gameplay.restart = (newly_pressed & masks.restart) != 0;
    result.quit = (newly_pressed & masks.quit) != 0;
    return result;
}

}  // namespace thor2::platform
