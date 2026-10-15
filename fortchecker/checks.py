"""Local evidence only: never substitute heuristics for Epic attestation."""

from dataclasses import asdict, dataclass
from pathlib import Path

SOURCE = "https://onlineservices.epicgames.com/news/introducing-easy-anti-cheat-linux-v2"
DISCLAIMER = (
    "FortChecker checks local EAC Linux v2 readiness, not whether Fortnite will launch. "
    "Epic must still verify signing keys and boot attestation. Requirements can change."
)


@dataclass
class Result:
    id: str
    name: str
    status: str
    reason: str
    action: str = ""
    evidence: str = ""

    def to_dict(self):
        return asdict(self)


class System:
    """Small, read-only filesystem boundary; a fixture root supports offline tests."""

    def __init__(self, root=Path("/")):
        self.root = Path(root)

    def read(self, path, binary=False):
        try:
            with (self.root / path.lstrip("/")).open("rb") as stream:
                data = stream.read(131072)
            return data if binary else data.decode("utf-8", errors="replace").strip()
        except OSError:
            return None

    def entries(self, path):
        try:
            return sorted(p.name for p in (self.root / path.lstrip("/")).iterdir())
        except OSError:
            return None


def signed_code(system):
    modules = system.entries("/sys/module")
    unsigned = []
    if modules is not None:
        for name in modules:
            taint = system.read(f"/sys/module/{name}/taint")
            if taint is not None and "E" in taint:
                unsigned.append(name)
    if unsigned:
        return Result(
            "signatures", "Signed kernel & drivers", "FAIL",
            "A loaded driver failed the kernel's signature verification.",
            "Use drivers signed by a publisher Epic accepts. A personal signing key is not enough.",
            "Modules with unsigned-module taint (E): " + ", ".join(unsigned),
        )
    return Result(
        "signatures", "Signed kernel & drivers", "UNKNOWN",
        "Local checks cannot prove that your running kernel and drivers use keys Epic accepts.",
        "Use your distribution's signed kernel and drivers. Epic must also validate all enrolled MOK keys.",
        "No unsigned-module taint found." if modules is not None else "Cannot read /sys/module.",
    )


def tpm(system):
    devices = system.entries("/sys/class/tpm")
    versions = [] if devices is None else [
        system.read(f"/sys/class/tpm/{device}/tpm_version_major") for device in devices
    ]
    if "2" in versions:
        status, reason, action = "PASS", "Linux detects an enabled TPM 2.0 security device.", ""
    elif devices == [] or (versions and all(v == "1" for v in versions)):
        status, reason = "FAIL", "Linux does not expose a TPM 2.0 security device."
        action = "Check firmware settings for TPM 2.0, Intel PTT, or AMD fTPM. Older hardware may lack it."
    else:
        status, reason = "UNKNOWN", "The TPM version could not be read."
        action = "Check your firmware settings and distribution's TPM documentation."
    return Result("tpm", "TPM 2.0", status, reason, action, f"Reported TPM versions: {versions!r}")


def secure_boot(system):
    base = "/sys/firmware/efi/efivars/"
    guid = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
    boot = system.read(base + "SecureBoot-" + guid, binary=True)
    setup = system.read(base + "SetupMode-" + guid, binary=True)
    # efivarfs prefixes each value with four attribute bytes.
    def value(data):
        return data[4] if data is not None and len(data) == 5 and data[4] in (0, 1) else None
    enabled, setup_mode = value(boot), value(setup)
    if enabled == 0 or setup_mode == 1:
        status, reason = "FAIL", "UEFI Secure Boot is disabled or the firmware is in setup mode."
        action = "Follow your distribution's Secure Boot guide before changing firmware settings."
    elif enabled == 1 and setup_mode == 0:
        status, reason, action = "PASS", "Firmware reports Secure Boot enabled (not setup mode).", ""
    else:
        status, reason = "UNKNOWN", "Secure Boot state could not be fully read."
        action = "Check Secure Boot in firmware settings. UEFI variables may be unavailable or restricted."
    return Result("secure_boot", "Secure Boot", status, reason, action,
                  f"SecureBoot={enabled}; SetupMode={setup_mode}. Key acceptance is checked separately.")


def measured_boot(system):
    log = system.read("/sys/kernel/security/tpm0/binary_bios_measurements", binary=True)
    return Result(
        "measured_boot", "Measured boot", "UNKNOWN",
        "A boot measurement log exists, but its validity needs attestation." if log else
        "Boot measurements could not be confirmed from this session.",
        "Use a measured-boot-capable bootloader. Epic must verify that measurements match your boot session.",
        "TPM event log is nonempty; contents not validated." if log else
        "TPM event log missing, empty, or unreadable; this alone does not prove measured boot is disabled.",
    )


def iommu(system):
    groups = system.entries("/sys/kernel/iommu_groups")
    types = [] if groups is None else [
        system.read(f"/sys/kernel/iommu_groups/{group}/type") for group in groups
    ]
    cmdline = (system.read("/proc/cmdline") or "").split()
    bypass = {"iommu=pt", "iommu.passthrough=1", "iommu=off", "intel_iommu=off", "amd_iommu=off"}
    if "identity" in types or bypass.intersection(cmdline):
        status, reason = "FAIL", "IOMMU passthrough or a disabling boot option was detected."
        action = "For non-handheld PCs, enable IOMMU in firmware and disable passthrough in boot settings."
    else:
        status, reason = "UNKNOWN", "Full IOMMU protection could not be established."
        if types and all(t in ("DMA", "DMA-FQ") for t in types):
            reason = "Visible IOMMU groups use translation, but full device protection is not proven."
        action = "For non-handheld PCs, check your distribution's IOMMU guide; groups alone do not prove full protection."
    return Result("iommu", "Device memory protection (IOMMU)", status, reason, action,
                  f"Group types: {types!r}. Epic exempts handhelds from this requirement; no exemption assumed.")


def lockdown(system):
    state = system.read("/sys/kernel/security/lockdown")
    cmdline = (system.read("/proc/cmdline") or "").split()
    if state and "[none]" in state:
        status, reason = "FAIL", "Kernel lockdown is off."
        action = "Use your distribution's instructions to enable lockdown integrity mode at boot."
    elif state and "[integrity]" in state and "lockdown=integrity" in cmdline:
        status, reason, action = "PASS", "Integrity lockdown is active and explicitly requested at boot.", ""
    else:
        status, reason = "UNKNOWN", "Explicit integrity lockdown at boot could not be confirmed."
        if state and "[confidentiality]" in state:
            reason = "Stricter confidentiality lockdown is active; Epic's acceptance is not established here."
        elif state and "[integrity]" in state:
            reason = "Integrity lockdown is active, but an explicit boot setting was not found."
        action = "Check your distribution's boot settings. Epic specifies explicit integrity lockdown at boot."
    return Result("lockdown", "Kernel lockdown", status, reason, action,
                  f"Lockdown: {state!r}; lockdown boot options: {[v for v in cmdline if v.startswith('lockdown=')]}")


def kexec(system):
    value = system.read("/proc/sys/kernel/kexec_load_disabled")
    if value == "0":
        return Result("kexec", "Kernel replacement (kexec)", "FAIL",
                      "The running kernel still allows loading a replacement kernel.",
                      "Follow your distribution's guide to disable kexec at boot, then reboot and check again.",
                      "kernel.kexec_load_disabled=0")
    return Result(
        "kexec", "Kernel replacement (kexec)", "UNKNOWN",
        "Kexec is disabled now, but local inspection cannot prove it was disabled at boot." if value == "1" else
        "The kexec setting is unavailable; kexec may be absent or access may be restricted.",
        "Epic requires kexec disabled at boot. Changing the running setting alone does not prove compliance.",
        f"kernel.kexec_load_disabled={value!r}",
    )


def bpf(system):
    lsms = system.read("/sys/kernel/security/lsm")
    if lsms:
        active = "bpf" in [name.strip() for name in lsms.split(",")]
        return Result("bpf", "BPF security hooks", "PASS" if active else "FAIL",
                      "The BPF security module is loaded and active." if active else
                      "The BPF security module is not in the active module list.",
                      "" if active else "Use a kernel with BPF LSM support and enable it in your distribution's boot settings.",
                      f"Active security modules: {lsms}")
    return Result("bpf", "BPF security hooks", "UNKNOWN",
                  "The active security module list could not be read.",
                  "Check your distribution's BPF LSM support. A missing list does not prove BPF is disabled.",
                  "/sys/kernel/security/lsm is empty or unreadable.")


CHECKS = (signed_code, tpm, secure_boot, measured_boot, iommu, lockdown, kexec, bpf)


def exit_code(results):
    if any(r.status == "FAIL" for r in results):
        return 1
    if not results or any(r.status == "UNKNOWN" for r in results):
        return 2
    return 0
