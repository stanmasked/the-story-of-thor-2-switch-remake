"""Exercise the recursive libnx Makefile flow without requiring the SDK.

The fake switch_rules only echo the recipe inputs. This catches make recursion,
source discovery and NACP path propagation bugs, but is not a Switch build test.
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = ROOT / "Makefile.switch"


@unittest.skipUnless(shutil.which("make"), "GNU make is required")
class SwitchMakefileDryRunTests(unittest.TestCase):
    def test_recursive_make_uses_one_root_nacp_path(self):
        with tempfile.TemporaryDirectory(prefix="thor2-makefile-") as tmp:
            root = Path(tmp)
            sdk_rules = root / "fake-sdk" / "libnx" / "switch_rules"
            sdk_rules.parent.mkdir(parents=True)
            (root / "native" / "platform").mkdir(parents=True)
            (root / "native" / "platform" / "switch_main.cpp").write_text(
                "// synthetic source used only to exercise Makefile recursion\n"
            )
            sdk_rules.write_text(
                "%.o: %.cpp\n"
                "\t@echo \"COMPILE $< with $(CXXFLAGS)\"\n"
                "%.elf:\n"
                "\t@echo \"LINK $(OFILES) with $(LDFLAGS) $(LIBPATHS) $(LIBS)\"\n"
                "%.nacp:\n"
                "\t@echo \"NACP $(APP_TITLE) $(APP_AUTHOR) $(APP_VERSION) $(NACPFLAGS)\"\n"
                "%.nro:\n"
                "\t@echo \"NROFLAGS=$(NROFLAGS)\"\n"
            )
            shutil.copy2(MAKEFILE, root / "Makefile.switch")
            env = os.environ.copy()
            env["DEVKITPRO"] = str(root / "fake-sdk")
            result = subprocess.run(
                ["make", "--no-print-directory", "-f", "Makefile.switch"],
                cwd=root,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            output = result.stdout
            self.assertEqual(result.returncode, 0, output)
            self.assertIn("COMPILE", output)
            self.assertIn("NACP Thor2 Native Sandbox RIKITU LAB 0.1.0", output)
            expected = f"NROFLAGS=--nacp={root}/thor2-stage63.nacp"
            self.assertIn(expected, output)
            self.assertEqual(output.count("NROFLAGS="), 1)
            self.assertNotIn("build-switch/thor2-stage63.nacp", output)


if __name__ == "__main__":
    unittest.main()
