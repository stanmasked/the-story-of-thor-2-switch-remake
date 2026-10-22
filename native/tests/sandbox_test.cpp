// Stage62 native gameplay/renderer tests: all map data and graphics synthetic.
// Strict C++17 assertions; no Sega ROM, original sprite, libnx or SDL.
#include "gameplay.hpp"
#include "software_renderer.hpp"
#include <array>
#include <cassert>
#include <cstdint>
#include <stdexcept>
#include <string>

using namespace thor2::sandbox;

template <typename F>
bool fails(F f) {
    try { f(); }
    catch (const std::invalid_argument&) { return true; }
    catch (const std::out_of_range&) { return true; }
    return false;
}

void approach(Game& g, int tile_x, int tile_y) {
    const int goal_x = tile_x * kTile + 2;
    const int goal_y = tile_y * kTile + 2;
    // Use cardinal input only, with <=2px tolerance for 3px/tick speed.
    int guard = 1024;
    while (std::abs(g.state().x - goal_x) > 2 && --guard) {
        const int previous = g.state().x;
        Input keys;
        keys.left = g.state().x > goal_x;
        keys.right = g.state().x < goal_x;
        g.tick(keys);
        assert(g.state().x != previous && "synthetic path blocked unexpectedly");
    }
    assert(guard > 0);
    guard = 1024;
    while (std::abs(g.state().y - goal_y) > 2 && --guard) {
        const int previous = g.state().y;
        Input keys;
        keys.up = g.state().y > goal_y;
        keys.down = g.state().y < goal_y;
        g.tick(keys);
        assert(g.state().y != previous && "synthetic path blocked unexpectedly");
    }
    assert(guard > 0);
}

void synthetic_route_to_win(Game& g) {
    // Easy-to-review route around two columns and under/over a horizontal wall.
    approach(g, 5, 2);
    approach(g, 5, 4);
    assert(g.collected() == 1);
    approach(g, 5, 2);
    approach(g, 15, 2);
    approach(g, 15, 10);
    assert(g.collected() == 2);
    approach(g, 15, 2);
    approach(g, 43, 2);
    approach(g, 43, 23);
    approach(g, 32, 23);
    assert(g.collected() == 3);
    approach(g, 43, 23);
    approach(g, 43, 26);
    assert(!g.state().won);
    Input action;
    action.interact = true;
    g.tick(action);
    assert(g.state().won);
}

int main() {
    static_assert(kFixedTicksPerSecond == 60, "fixed simulation cadence");
    static_assert(kScreenWidth == 320 && kScreenHeight == 240, "fixed viewport");
    static_assert(kTile == 16 && kActorSide == 12, "tile and actor contract");
    {
        Game g;
        assert(!g.collides_at(g.state().x, g.state().y));
        assert(g.state().ticks == 0);
        assert(g.collected() == 0);
        assert(!g.state().won);
        assert(g.blocked_tile(0, 0));
        assert(g.blocked_tile(kMapWidth - 1, kMapHeight - 1));
        assert(g.blocked_tile(-1, 7));
        assert(g.blocked_tile(kMapWidth, 8));
        assert(!g.blocked_tile(2, 2));
        assert(g.blocked_tile(8, 3));
        assert(!g.blocked_tile(8, 10));
        assert(g.blocked_tile(22, 13));
        assert(!g.blocked_tile(22, 14));
        assert(g.blocked_tile(9, 20));
        assert(!g.blocked_tile(15, 20));
        assert(g.collides_at(-1, 32));
        assert(g.collides_at(32, -1));
        assert(g.collides_at(kMapWidth * kTile, 32));
        assert(g.collides_at(32, kMapHeight * kTile));
    }
    {
        Game g;
        const int x = g.state().x, y = g.state().y;
        Input opposite; opposite.left = opposite.right = true;
        opposite.up = opposite.down = true;
        g.tick(opposite);
        assert(g.state().x == x && g.state().y == y);
        assert(g.state().ticks == 1);
        Input next; next.right = true;
        g.tick(next);
        assert(g.state().x == x + kCardinalStep);
    }
    {
        Game g;
        Input right; right.right = true;
        g.tick(right);
        assert(g.state().x == 2 * kTile + 2 + kCardinalStep);
        assert(g.state().y == 2 * kTile + 2);
    }
    {
        Game g;
        Input diag; diag.down = diag.right = true;
        g.tick(diag);
        assert(g.state().x == 2 * kTile + 2 + kDiagonalStep);
        assert(g.state().y == 2 * kTile + 2 + kDiagonalStep);
    }
    {
        Game g;
        // At tile7 row3 a solid wall at tile8 prevents 3-pixel tunneling.
        approach(g, 7, 2);
        approach(g, 7, 3);
        Input right; right.right = true;
        for (int i = 0; i < 40; ++i) g.tick(right);
        assert(g.state().x + kActorSide <= 8 * kTile);
        assert(!g.collides_at(g.state().x, g.state().y));
    }
    {
        Game g;
        approach(g, 7, 2);
        approach(g, 7, 3);
        const int before_y = g.state().y;
        Input slide; slide.right = slide.down = true;
        for (int i = 0; i < 6; ++i) g.tick(slide);
        // Wall x8 constrains X, but Y must continue along it.
        assert(g.state().y > before_y);
        assert(!g.collides_at(g.state().x, g.state().y));
    }
    {
        Game g;
        const auto snapshot = g.state_hash();
        Input down; down.down = true;
        g.tick(down);
        assert(g.state_hash() != snapshot);
        Input restart; restart.restart = true;
        g.tick(restart);
        assert(g.state_hash() == snapshot);
        assert(g.state().ticks == 0);
    }
    {
        Game a, b;
        for (int i = 0; i < 600; ++i) {
            Input input;
            input.right = i % 13 < 8;
            input.down = i % 17 < 9;
            input.left = i % 71 == 0;
            input.up = i % 47 == 0;
            input.interact = i % 53 == 0;
            a.tick(input);
            b.tick(input);
        }
        assert(a.state_hash() == b.state_hash());
        assert(a.state().x == b.state().x);
        assert(a.state().y == b.state().y);
        assert(a.state().ticks == 600);
    }
    {
        Game g;
        assert(g.camera().x == 0);
        assert(g.camera().y == 0);
        Input interact; interact.interact = true;
        g.tick(interact);
        assert(!g.state().won); // no remote or locked-door win
        synthetic_route_to_win(g);
        assert(g.camera().x >= 0 && g.camera().y >= 0);
        assert(g.camera().x <= kMapWidth * kTile - kScreenWidth);
        assert(g.camera().y <= kMapHeight * kTile - kScreenHeight);
        assert(g.camera().x > 0 && g.camera().y > 0);
        const int x = g.state().x, y = g.state().y;
        Input left; left.left = true;
        g.tick(left);
        assert(g.state().x == x && g.state().y == y); // win freezes player
        assert(g.state().won);
        Input restart; restart.restart = true;
        g.tick(restart);
        assert(!g.state().won && g.collected() == 0);
    }
    {
        Game g;
        Surface s1, s2;
        render(g, s1);
        render(g, s2);
        assert(s1.pixels().size() == kScreenWidth * kScreenHeight);
        assert(s1.fnv1a() == s2.fnv1a());
        assert(s1.pixel(0, 0) == kHud);
        assert(s1.pixel(6, 3) == kHudEmpty);
        const auto cam = g.camera();
        const int hero_x = g.state().x - cam.x;
        const int hero_y = g.state().y - cam.y;
        assert(s1.pixel(hero_x, hero_y + 5) == kHero);
        assert(s1.pixel(hero_x + 3, hero_y + 3) == kHud);
        assert(fails([&] { (void)s1.pixel(-1, 0); }));
        assert(fails([&] { (void)s1.pixel(320, 0); }));
        assert(fails([&] { (void)s1.pixel(0, 240); }));
        const auto hash = s1.fnv1a();
        Input right; right.right = true;
        for (int i = 0; i < 8; ++i) g.tick(right);
        render(g, s2);
        assert(s2.fnv1a() != hash);
        s2.clear(rgba(1, 2, 3));
        assert(s2.pixel(100, 100) == rgba(1, 2, 3));
        s2.rect(-5, -5, 10, 10, kCrystal);
        assert(s2.pixel(0, 0) == kCrystal);
        assert(s2.pixel(5, 5) == rgba(1, 2, 3));
        assert(fails([&] {s2.rect(10000, 0, 2, 2, kHero);}));
        s2.rect(0, 0, 0, 20, kHero);
        s2.rect(0, 0, -1, 1, kHero);
        assert(s2.pixel(0, 0) == kCrystal);
    }
    {
        Game g;
        synthetic_route_to_win(g);
        Surface s;
        render(g, s);
        assert(s.pixel(60, 3) == kExitOpen);
        for (int i = 0; i < 3; ++i)
            assert(s.pixel(6 + 15 * i, 3) == kCrystal);
    }
    return 0;
}
