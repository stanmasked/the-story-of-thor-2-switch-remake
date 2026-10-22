"""Static guardrails for the Nintendo Switch libnx Makefile structure.

These checks catch missing recursive build targets and include-path propagation.
They do not replace the actual devkitPro cross-build.
"""
import unittest
from pathlib import Path

MAKEFILE = (Path(__file__).resolve().parents[1] / "Makefile.switch").read_text()


class SwitchMakefileStructureTests(unittest.TestCase):
    def test_uses_libnx_rules(self):
        self.assertIn("include $(DEVKITPRO)/libnx/switch_rules", MAKEFILE)

    def test_outer_and_inner_build_targets_exist(self):
        self.assertIn("all: $(BUILD)", MAKEFILE)
        self.assertIn("all: $(OUTPUT).nro", MAKEFILE)
        self.assertIn("$(OUTPUT).nro: $(OUTPUT).elf $(OUTPUT).nacp", MAKEFILE)
        self.assertIn("$(OUTPUT).elf: $(OFILES)", MAKEFILE)

    def test_source_discovery_and_recursive_make_are_present(self):
        self.assertIn("SOURCES      := native/platform", MAKEFILE)
        self.assertIn("$(wildcard $(dir)/*.cpp)", MAKEFILE)
        self.assertIn("-C $@ -f $(CURDIR)/Makefile.switch", MAKEFILE)

    def test_compiler_flags_include_exported_include_paths(self):
        self.assertIn("CFLAGS = ", MAKEFILE)
        self.assertIn("$(ARCH) $(DEFINES) $(INCLUDE) -D__SWITCH__", MAKEFILE)
        self.assertIn("CXXFLAGS = $(CFLAGS) -std=gnu++17 -fexceptions", MAKEFILE)

    def test_nro_metadata_flags_are_explicit_and_outer_only(self):
        self.assertIn("export NROFLAGS += --nacp=$(TOPDIR)/$(TARGET).nacp", MAKEFILE)
        self.assertEqual(MAKEFILE.count("export NROFLAGS += --nacp="), 1)
        self.assertLess(
            MAKEFILE.index("export LIBPATHS"),
            MAKEFILE.index("export NROFLAGS += --nacp="),
        )
        outer_else = MAKEFILE.index("\nelse\n\n.PHONY: all")
        self.assertLess(MAKEFILE.index("export NROFLAGS += --nacp="), outer_else)
        self.assertIn("APP_TITLE    := Thor2 Native Sandbox", MAKEFILE)
        self.assertIn("APP_AUTHOR   := RIKITU LAB", MAKEFILE)
        self.assertIn("APP_VERSION  := 0.1.0", MAKEFILE)
        self.assertIn("NO_ICON      := 1", MAKEFILE)

    def test_original_game_assets_are_not_packaged(self):
        self.assertIn("DATA         :=", MAKEFILE)
        self.assertNotIn("ROMFS :=", MAKEFILE)
        self.assertNotIn("WILD ARMS", MAKEFILE)
        self.assertNotIn("Saturn.iso", MAKEFILE)


if __name__ == "__main__":
    unittest.main()
