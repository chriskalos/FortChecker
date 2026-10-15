# FortChecker implementation plan

Approved direction: Python 3, standard library only; Conventional Commits; basic tests.

Build a read-only Linux command-line readiness checker based on Epic's EAC Linux v2 announcement:
https://onlineservices.epicgames.com/news/introducing-easy-anti-cheat-linux-v2

1. Probe the eight published requirements through procfs, sysfs, and UEFI variables.
2. Keep unavailable evidence UNKNOWN. Never claim local inspection proves Epic attestation or key acceptance.
3. Show a colorful terminal scan with PASS, FAIL, UNKNOWN, plain-language explanations, and next steps.
4. Support JSON, verbose evidence, no-color, and no-animation modes. Disable terminal effects when redirected.
5. Add basic fixture tests and run a local smoke check.

Architecture: probes and results in fortchecker/checks.py; rendering and CLI in fortchecker/__main__.py.
Safety: no writes to system files, no elevation, no external commands, no network access at runtime.
Commands: python3 -m fortchecker; python3 -m unittest discover -s tests; python3 -m compileall -q fortchecker.
Limitations: this is a preflight, not Epic's verifier. Boot provenance, approved keys, measured-boot validity,
and handheld exemptions cannot be certified locally. Containers and virtual machines can expose incomplete host evidence.
