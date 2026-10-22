// Stage62 original-art-free, host-runnable prototype. Not The Story of Thor 2.
// Build: g++ -std=c++17 -O2 -Wall -Wextra -Werror -pedantic -Inative
//        native/demo/sandbox_cli.cpp -o thor2-sandbox
// Run interactively: ./thor2-sandbox
// Optional scripted frame capture: ./thor2-sandbox --script="d 25;s 10;e 1" --ppm=/tmp/sandbox.ppm
#include "gameplay.hpp"
#include "software_renderer.hpp"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {
using thor2::sandbox::Game;
using thor2::sandbox::Input;
using thor2::sandbox::Surface;
using thor2::sandbox::render;

Input parse_input(const std::string& keys) {
    Input in;
    for (char letter : keys) {
        const char key = static_cast<char>(std::tolower(static_cast<unsigned char>(letter)));
        switch (key) {
        case 'w': in.up = true; break;
        case 'a': in.left = true; break;
        case 's': in.down = true; break;
        case 'd': in.right = true; break;
        case 'e': in.interact = true; break;
        case 'r': in.restart = true; break;
        case '.': break;
        default: throw std::invalid_argument("unsupported keys; use WASD, E, R or .");
        }
    }
    return in;
}

void command(Game& game, const std::string& line) {
    std::istringstream text(line);
    std::string keys, extra;
    unsigned count = 1;
    if (!(text >> keys)) return;
    if (text >> count) {
        if (text >> extra)
            throw std::invalid_argument("one key group and optional tick count expected");
    } else if (!text.eof()) {
        throw std::invalid_argument("invalid tick count");
    }
    if (count < 1 || count > 120)
        throw std::invalid_argument("tick count must be from 1 to 120");
    Input in = parse_input(keys);
    for (unsigned i = 0; i < count; ++i) game.tick(in);
}

void ascii(const Game& game) {
    const auto cam = game.camera();
    const int base_x = cam.x / thor2::sandbox::kTile;
    const int base_y = cam.y / thor2::sandbox::kTile;
    const auto& s = game.state();
    std::cout << "Ticks: " << s.ticks << "  Position: " << s.x << ',' << s.y
              << "  Crystals: " << game.collected() << "/3"
              << (s.won ? "  EXIT UNLOCKED — WON!" : "") << '\n';
    for (int y = base_y; y < base_y + 15; ++y) {
        for (int x = base_x; x < base_x + 20; ++x) {
            char ch = game.blocked_tile(x, y) ? '#' : '.';
            if (x == thor2::sandbox::kGoalTileX &&
                y == thor2::sandbox::kGoalTileY)
                ch = game.collected() == 3 ? 'O' : 'X';
            for (const auto& crystal : s.crystals)
                if (!crystal.collected && x == crystal.tile_x && y == crystal.tile_y)
                    ch = '*';
            if (s.x / thor2::sandbox::kTile == x &&
                s.y / thor2::sandbox::kTile == y)
                ch = '@';
            std::cout << ch;
        }
        std::cout << '\n';
    }
    std::cout << "WASD = move, E = interact by exit, R = reset; "
                 "one group + optional tick count (e.g. 'wd 8'). Q = quit.\n";
}

void ppm(const std::string& path, const Surface& image) {
    if (path.empty()) return;
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("could not create screenshot file");
    out << "P6\n" << Surface::width() << ' ' << Surface::height() << "\n255\n";
    for (const std::uint32_t p : image.pixels()) {
        const char rgb[] = {
            static_cast<char>(p >> 24),
            static_cast<char>((p >> 16) & 255),
            static_cast<char>((p >> 8) & 255)
        };
        out.write(rgb, 3);
    }
    if (!out) throw std::runtime_error("failed to write complete screenshot");
}

}  // namespace

int main(int argc, char** argv) {
    try {
        Game game;
        std::string script, ppm_path;
        bool quiet = false;
        for (int i = 1; i < argc; ++i) {
            const std::string arg(argv[i]);
            if (arg == "--help") {
                std::cout << "thor2-sandbox [--script=\"d 25;s 8\"] "
                             "[--ppm=/tmp/frame.ppm] [--quiet]\n";
                return 0;
            }
            if (arg.rfind("--script=", 0) == 0) script = arg.substr(9);
            else if (arg.rfind("--ppm=", 0) == 0) ppm_path = arg.substr(6);
            else if (arg == "--quiet") quiet = true;
            else throw std::invalid_argument("unknown command-line option");
        }
        if (script.empty()) {
            if (!quiet) ascii(game);
            std::string line;
            while (std::getline(std::cin, line)) {
                if (line == "q" || line == "Q") break;
                try {
                    command(game, line);
                } catch (const std::exception& e) {
                    std::cerr << "Input rejected: " << e.what() << '\n';
                }
                if (!quiet) ascii(game);
            }
        } else {
            std::istringstream steps(script);
            std::string step;
            while (std::getline(steps, step, ';'))
                command(game, step);
            if (!quiet) ascii(game);
        }
        Surface surface;
        render(game, surface);
        ppm(ppm_path, surface);
        std::cout << "sandbox_state_hash=" << game.state_hash()
                  << " screenshot_hash=" << surface.fnv1a() << '\n';
    } catch (const std::exception& e) {
        std::cerr << "Sandbox error: " << e.what() << '\n';
        return 1;
    }
    return 0;
}
