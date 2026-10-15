"""A terminal dashboard with a plain-text and JSON escape hatch."""

import argparse
import json
import os
import platform
import shutil
import sys
import textwrap
import time

from . import __version__
from .checks import CHECKS, DISCLAIMER, SOURCE, System, exit_code


class Display:
    def __init__(self, color, animate, verbose):
        self.color = color
        self.animate = animate
        self.verbose = verbose
        self.width = max(30, min(88, shutil.get_terminal_size((88, 24)).columns - 2))

    def ink(self, text, code):
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def line(self, text="", indent="  ", color=None):
        # Firmware and kernel text are untrusted terminal input. Remove controls.
        clean = "".join(c if c.isprintable() else " " for c in text)
        lines = textwrap.wrap(clean, width=self.width, initial_indent=indent,
                              subsequent_indent=indent) or [""]
        for line in lines:
            print(self.ink(line, color) if color else line)

    def header(self):
        print()
        if self.width >= 65:
            for row in (
                "  ______ ____  ____  ______",
                " / ____// __ \\/ __ \\/_  __/",
                "/ /_   / / / / /_/ / / /",
                "/ __/ / /_/ / _, _/ / /",
                "/_/    \\____/_/ |_| /_/   C H E C K E R",
            ):
                self.line(row, color="1;96")
        else:
            self.line("// FORTCHECKER", color="1;96")
        self.line("LINUX READINESS SCANNER  /  " + __version__, color="35")
        self.line("=" * (self.width - 2), color="36")
        self.line("READ ONLY  |  NO SUDO  |  NO NETWORK", color="90")
        self.line(f"Linux {platform.release()} / {platform.machine()}")
        print()

    def progress(self, count):
        if self.animate:
            bar = "#" * (count * 3) + "." * ((len(CHECKS) - count) * 3)
            text = f"  [{bar}] {count}/{len(CHECKS)}"
            print("\r" + self.ink(text[:self.width], "96"), end="", flush=True)

    def finish_progress(self):
        if self.animate:
            print("\r\033[2K", end="", flush=True)

    def report(self, results, elapsed, restricted):
        failed = sum(r.status == "FAIL" for r in results)
        unknown = sum(r.status == "UNKNOWN" for r in results)
        passed = len(results) - failed - unknown
        if failed:
            title = "REQUIREMENTS NOT MET"
            color = "1;91"
            explanation = "Fix the failed checks first. UNKNOWN checks still need verification."
        elif unknown:
            title = "READINESS NOT CONFIRMED"
            color = "1;93"
            explanation = "No failures detected, but missing evidence prevents a complete verdict."
        else:
            title = "LOCAL CHECKS PASSED"
            color = "1;92"
            explanation = "These local checks do not guarantee Epic will accept this system."
        self.line(title, color=color)
        self.line(f"{passed} PASS  /  {failed} FAIL  /  {unknown} UNKNOWN  [{elapsed:.2f}s]", color="1")
        self.line(explanation)
        self.line("PASS = local evidence matches. FAIL = a problem was found. UNKNOWN = not enough proof.")
        if restricted:
            print()
            self.line("NOTE: A container was detected. Results may describe its host or restricted view, not your gaming PC.", color="93")
        print()
        for index, result in enumerate(results, 1):
            code = {"PASS": "1;92", "FAIL": "1;91", "UNKNOWN": "1;93"}[result.status]
            self.line(f"{index:02d}  [{result.status}]  {result.name}", color=code)
            self.line(result.reason, indent="      ")
            if result.action:
                self.line("Next: " + result.action, indent="      ")
            if self.verbose:
                self.line("Evidence: " + result.evidence, indent="      ", color="90")
            print()
        self.line("-" * (self.width - 2), color="36")
        self.line(DISCLAIMER)
        self.line("Do not change firmware or boot options blindly; keep a working recovery boot entry.")
        self.line("Unofficial tool. Not affiliated with Epic Games.", color="90")
        if self.verbose:
            self.line("Requirements: " + SOURCE, color="90")
        else:
            self.line("Use --verbose for evidence and the source; --json for a machine-readable report.", color="90")
        print()


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="fortchecker",
        description="Read-only Linux readiness scan for Epic's announced EAC Linux v2 requirements.",
        epilog="Exit codes: 0 = local checks passed; 1 = at least one FAIL; 2 = UNKNOWN or unsupported OS.",
    )
    parser.add_argument("--version", action="version", version=f"FortChecker {__version__}")
    parser.add_argument("--json", action="store_true", help="emit JSON only, without colors or animation")
    parser.add_argument("--verbose", "-v", action="store_true", help="show technical evidence and requirement source")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors (also respects NO_COLOR)")
    parser.add_argument("--no-animation", action="store_true", help="disable the live scan progress bar")
    args = parser.parse_args(argv)
    if platform.system() != "Linux":
        message = "FortChecker must run on the Linux machine you want to check."
        if args.json:
            print(json.dumps({"schema_version": 1, "error": message, "checks": [], "exit_code": 2}))
        else:
            print(message, file=sys.stderr)
        return 2

    system = System()
    terminal = sys.stdout.isatty() and os.environ.get("TERM") != "dumb"
    display = Display(terminal and not args.no_color and "NO_COLOR" not in os.environ,
                      terminal and not args.no_animation, args.verbose)
    container = (system.read("/run/systemd/container") is not None or
                 system.read("/.dockerenv") is not None or
                 system.read("/run/.containerenv") is not None)
    start = time.monotonic()
    results = []
    if not args.json:
        display.header()
        display.progress(0)
    for check in CHECKS:
        results.append(check(system))
        if not args.json:
            display.progress(len(results))
            if display.animate:
                # Brief visual pacing after real checks, never simulated probe output.
                time.sleep(0.045)
    elapsed = time.monotonic() - start
    code = exit_code(results)
    if args.json:
        print(json.dumps({
            "schema_version": 1,
            "version": __version__,
            "source": SOURCE,
            "notice": DISCLAIMER,
            "container_detected": container,
            "exit_code": code,
            "summary": {status: sum(r.status == status for r in results)
                        for status in ("PASS", "FAIL", "UNKNOWN")},
            "checks": [r.to_dict() for r in results],
        }, indent=2))
    else:
        display.finish_progress()
        display.report(results, elapsed, container)
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nScan cancelled. No system changes were made.", file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:
        # Avoid a second flush failure when output is piped to head.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
