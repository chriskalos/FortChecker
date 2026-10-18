# FortChecker

A colorful, read-only Linux readiness scanner for Epic's announced **Easy Anti-Cheat Linux v2** requirements.
Python 3.8 or newer. No third-party dependencies. No installation required.

```sh
python3 -m fortchecker
# Or, from this directory:
./FortChecker
```

The terminal display includes a cyan ASCII banner, a live progress bar, and color-coded results.
Each check includes a plain-English explanation. Failed or uncertain checks include a suggested next step.
Colors are not required to read the results.

## Results

- **PASS**: Local evidence matches this check.
- **FAIL**: The scan found a problem.
- **UNKNOWN**: Evidence is missing, restricted, or requires verification by Epic.

**FortChecker cannot certify Fortnite compatibility.** It does not launch Fortnite or contact Epic.
The announcement describes planned support, not a guarantee that the game is available for your system.

## Options

```sh
python3 -m fortchecker --verbose       # Evidence and requirement source
python3 -m fortchecker --json          # JSON only, suitable for scripts
python3 -m fortchecker --no-animation  # Immediate results
python3 -m fortchecker --no-color      # No colors
python3 -m fortchecker --help
```

Redirected output has no colors or animation. The `NO_COLOR` environment variable also disables colors.
Exit codes: `0` means local checks passed, `1` means a failure exists, and `2` means an incomplete or unsupported scan.
A failure takes precedence over unknown results. Argument errors also return `2`.

## What it checks

| Epic requirement | Evidence and limits |
| --- | --- |
| Signed kernel and modules | Finds loaded modules with unsigned-module taint. Otherwise UNKNOWN: local inspection cannot prove Epic accepts the keys. |
| TPM 2.0 | Reads the TPM version exposed by Linux. |
| Secure Boot | Reads UEFI SecureBoot and SetupMode variables. Signing-key acceptance remains a separate check. |
| Measured boot | Looks for the TPM event log. Remains UNKNOWN because log presence does not prove valid boot measurements. |
| IOMMU | Detects identity domains and disabling or passthrough boot options. Translation alone cannot prove complete device protection. |
| Lockdown integrity mode | Requires active integrity mode and an explicit `lockdown=integrity` boot argument for PASS. |
| Kexec disabled at boot | Detects whether the kernel permits replacement. Runtime disablement alone cannot prove disablement at boot. |
| BPF LSM active | Checks for `bpf` in the active security module list. |

Signing keys, measured boot, and boot-time kexec disablement require evidence that this utility cannot fully verify.
Even a correctly configured system will retain UNKNOWN results. This is intentional, not a recommendation to keep changing settings.

Epic exempts handhelds from its IOMMU requirement. FortChecker does not guess whether a machine qualifies.
Containers and virtual machines can expose incomplete evidence. Run the checker on the actual gaming system.
Known container markers trigger a warning, but container detection is not exhaustive.

## Safety

FortChecker reads local files in `/proc`, `/sys`, and container marker locations.
It does not change firmware, boot options, drivers, or services. It does not request sudo or run external commands.
Unavailable files produce UNKNOWN unless other evidence identifies a failure.

**Keep a working recovery boot entry before you change system settings.** Incorrect boot settings can prevent startup.
Use your distribution's instructions rather than generic commands copied from another distribution.
Review verbose or JSON reports before sharing them. They can include driver names and security configuration details.

## Source

[Introducing Easy Anti-Cheat Linux v2 — Epic Online Services](https://onlineservices.epicgames.com/news/introducing-easy-anti-cheat-linux-v2)

The requirements are built into this version. FortChecker does not refresh them from the internet.
The source can change. This is an unofficial project with no affiliation to Epic Games.

## Development

```sh
python3 -m unittest discover -s tests
python3 -m compileall -q fortchecker
```

Basic tests use temporary filesystem fixtures, not the host's security settings.
No build step is required.
