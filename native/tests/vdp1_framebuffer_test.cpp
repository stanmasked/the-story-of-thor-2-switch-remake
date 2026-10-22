// Stage61 pure host C++17 tests; entirely generated data, no original assets.
#include "vdp1_framebuffer.hpp"
#include <cassert>
#include <cstdint>
#include <stdexcept>
#include <vector>

using thor2::vdp1::FrameMode;
using thor2::vdp1::PixelClass;
using thor2::vdp1::kFrameBytes;
using thor2::vdp1::kRegisterMirrorBytes;
using thor2::vdp1::parse_mode;
using thor2::vdp1::inspect_private;
using thor2::vdp1::summarize_private;

template <typename Fn>
bool raises(Fn fn) {
    try {
        fn();
    } catch (const std::invalid_argument&) {
        return true;
    } catch (const std::out_of_range&) {
        return true;
    }
    return false;
}

std::array<std::uint8_t,kRegisterMirrorBytes>
mirror(std::uint16_t tvmr, std::uint16_t fbcr) {
    std::array<std::uint8_t,kRegisterMirrorBytes> r{};
    r[0] = static_cast<std::uint8_t>(tvmr >> 8);
    r[1] = static_cast<std::uint8_t>(tvmr);
    r[2] = static_cast<std::uint8_t>(fbcr >> 8);
    r[3] = static_cast<std::uint8_t>(fbcr);
    return r;
}

int main() {
    for (unsigned mode = 0; mode < 5; ++mode) {
        const auto bytes = mirror(static_cast<std::uint16_t>(mode), 0);
        const FrameMode m = parse_mode(bytes.data(), bytes.size());
        assert(m.mode == mode);
        assert(static_cast<std::size_t>(m.width) * m.height * m.bits_per_pixel / 8u
               == kFrameBytes);
        assert(m.bits_per_pixel == ((mode == 1 || mode == 3) ? 8u : 16u));
        assert(m.width == (mode == 1 ? 1024u : 512u));
        assert(m.height == (mode == 3 ? 512u : 256u));
        assert(!m.manual_switch && !m.switch_trigger);
    }
    assert(raises([] {
        const auto r = mirror(5, 0);
        parse_mode(r.data(), r.size());
    }));
    assert(raises([] {
        const auto r = mirror(0x100, 0);
        parse_mode(r.data(), r.size());
    }));
    assert(raises([] {
        const auto r = mirror(0, 0x20);
        parse_mode(r.data(), r.size());
    }));
    assert(raises([] {
        const auto r = mirror(0, 1);
        parse_mode(r.data(), r.size());
    }));
    assert(raises([] {
        const auto r = mirror(8, 0);
        parse_mode(r.data(), r.size());
    }));
    assert(raises([] {
        const auto r = mirror(2, 8);
        parse_mode(r.data(), r.size());
    }));
    assert(raises([] {
        const auto r = mirror(4, 8);
        parse_mode(r.data(), r.size());
    }));
    {
        const auto r = mirror(0, 0b10);
        const FrameMode m = parse_mode(r.data(), r.size());
        assert(m.manual_switch && !m.switch_trigger);
    }
    {
        const auto r = mirror(0, 0b11);
        const FrameMode m = parse_mode(r.data(), r.size());
        assert(m.manual_switch && m.switch_trigger);
    }
    {
        const auto r = mirror(8, 0b11);
        const FrameMode m = parse_mode(r.data(), r.size());
        assert(m.vblank_erase && m.manual_switch && m.switch_trigger);
    }
    assert(raises([] {parse_mode(nullptr, 32);}));
    assert(raises([] {
        const auto r = mirror(0, 0);
        parse_mode(r.data(), 16);
    }));
    {
        auto r = mirror(0, 0);
        auto m = parse_mode(r.data(), r.size());
        std::vector<std::uint8_t> raw(kFrameBytes);
        assert(inspect_private(raw.data(), raw.size(), m, 0, 0).category ==
               PixelClass::transparent_zero);
        raw[0] = 0x80; raw[1] = 0x1f;        // synthetic RGB555
        raw[2] = 0x04; raw[3] = 0x20;        // synthetic palette/control
        assert(inspect_private(raw.data(), raw.size(), m, 0, 0).category ==
               PixelClass::rgb555_candidate);
        assert(inspect_private(raw.data(), raw.size(), m, 0, 0).raw_code == 0x801f);
        assert(inspect_private(raw.data(), raw.size(), m, 1, 0).category ==
               PixelClass::palette_or_shadow_control);
        raw[kFrameBytes - 2] = 0x80;
        raw[kFrameBytes - 1] = 0x1f;
        assert(inspect_private(raw.data(), raw.size(), m, 511, 255).raw_code == 0x801f);
        const auto tally = summarize_private(raw.data(), raw.size(), m);
        assert(tally.rgb555_candidate == 2);
        assert(tally.palette_or_shadow_control == 1);
        assert(tally.transparent_zero == 131072 - 3);
        assert(tally.indexed8_or_control == 0);
        assert(tally.total() == 131072);
        assert(raises([&] {inspect_private(raw.data(), raw.size(), m, 512, 0);}));
        assert(raises([&] {inspect_private(raw.data(), raw.size(), m, 0, 256);}));
        assert(raises([&] {inspect_private(raw.data(), 123, m, 0, 0);}));
    }
    {
        auto r = mirror(1, 0);
        auto m = parse_mode(r.data(), r.size());
        std::vector<std::uint8_t> raw(kFrameBytes);
        raw[0] = 0x17;
        raw[1024] = 0x63;
        raw[kFrameBytes - 1] = 0xfe;
        assert(inspect_private(raw.data(), raw.size(), m, 0, 0).raw_code == 0x17);
        assert(inspect_private(raw.data(), raw.size(), m, 0, 1).raw_code == 0x63);
        assert(inspect_private(raw.data(), raw.size(), m, 1023, 255).raw_code == 0xfe);
        const auto tally = summarize_private(raw.data(), raw.size(), m);
        assert(tally.indexed8_or_control == 3);
        assert(tally.transparent_zero == kFrameBytes - 3);
        assert(tally.total() == 262144);
    }
    {
        auto r = mirror(3, 0);
        auto m = parse_mode(r.data(), r.size());
        std::vector<std::uint8_t> raw(kFrameBytes);
        raw[512] = 7;
        assert(inspect_private(raw.data(), raw.size(), m, 0, 1).raw_code == 7);
        assert(inspect_private(raw.data(), raw.size(), m, 511, 511).raw_code == 0);
    }
    {
        auto r = mirror(0, 0);
        auto m = parse_mode(r.data(), r.size());
        std::vector<std::uint8_t> raw(1);
        assert(raises([&] {summarize_private(raw.data(), raw.size(), m);}));
    }
    return 0;
}
