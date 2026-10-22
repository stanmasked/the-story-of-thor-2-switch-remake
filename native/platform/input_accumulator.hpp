#pragma once
// Preserve short button events sampled between fixed simulation ticks.
// This adapter is platform-independent and can be tested without libnx.
#include "../gameplay.hpp"

namespace thor2::platform {

class InputAccumulator {
public:
    void sample(const sandbox::Input& sampled) {
        held_ = sampled;
        if (sampled.interact && !previous_interact_)
            pending_interact_ = true;
        if (sampled.restart)
            pending_restart_ = true;
        previous_interact_ = sampled.interact;
    }

    sandbox::Input consume_tick() {
        sandbox::Input result = held_;
        result.interact = held_.interact || pending_interact_;
        result.restart = pending_restart_;
        pending_interact_ = false;
        pending_restart_ = false;
        return result;
    }

    bool has_pending_edge() const {
        return pending_interact_ || pending_restart_;
    }

private:
    sandbox::Input held_{};
    bool previous_interact_ = false;
    bool pending_interact_ = false;
    bool pending_restart_ = false;
};

}  // namespace thor2::platform
