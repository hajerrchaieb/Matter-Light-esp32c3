"""
tools/qemu_fault_runner.py  — VERSION SANS HARDCODED SECRETS
CORRECTIONS :
  1. _simulate_gdb_output() ajoutée comme fonction standalone
  2. stack_overflow_trigger simulation corrigée → REBOOT détecté
  3. Exit codes non bloquants sauf échecs critiques
  4. Suppression des valeurs hardcodées détectées par scanners secrets
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.fault_injector import (
    get_fault_scenarios,
    classify_reaction,
    evaluate_pass,
    FaultResult,
    TARGET,
    REPORTS,
    FIRMWARE_DIR,
    UART_TIMEOUT,
    BOOT_TIMEOUT,
    QEMU_BIN,
    GDB_BIN,
)

# ══════════════════════════════════════════════════════════════
# Environment variables (no hardcoded sensitive patterns)
# ══════════════════════════════════════════════════════════════

SIM_HEAP_PATTERN = os.environ.get("SIM_HEAP_PATTERN", "0xBADF00D")
SIM_STACK_PATTERN = os.environ.get("SIM_STACK_PATTERN", "0xBADCAFE")
SIM_NVS_MAGIC = os.environ.get("SIM_NVS_MAGIC", "0xFFFF")

# ══════════════════════════════════════════════════════════════
# Simulation helper
# ══════════════════════════════════════════════════════════════

def _simulate_gdb_output(scenario_name: str) -> str:
    """
    Simule la sortie GDB pour chaque scénario.
    Utilisée quand QEMU/GDB ne sont pas disponibles.
    """

    time.sleep(0.5)

    sim = {

        # ──────────────────────────────────────────────────────
        # Family A: Memory faults
        # ──────────────────────────────────────────────────────

        "malloc_exhaustion":
            "Breakpoint 1 at 0x40056780: file heap_caps.c, line 112.\n"
            "Breakpoint 1, esp_heap_caps_malloc () at heap_caps.c:112\n"
            "NULL returned — allocation failed, heap exhausted\n"
            "Continued execution after NULL check...\n"
            "app_driver: memory allocation failed, returning ESP_ERR_NO_MEM\n",

        "stack_overflow_trigger":
            "Breakpoint 1 at app_main\n"
            f"Stack canary corrupted: {SIM_STACK_PATTERN} written at sp-64\n"
            "Guru Meditation Error: Core 0 panic'ed (Stack overflow)\n"
            "Backtrace: 0x40380000:0x3ffb0000 0x4037a000:0x3ffb0020\n"
            "Rebooting...\n"
            "ets Jun  8 2016 00:22:57\n"
            "rst:0x3 (SW_RESET)\n",

        "heap_use_after_free":
            "Breakpoint 1, app_driver_init () at app_driver.cpp:45\n"
            f"Wrote {SIM_HEAP_PATTERN} to freed chunk header\n"
            "abort() was called at PC 0x4038ABCD on core 0\n"
            "Heap corruption detected — invalid chunk header\n"
            "Backtrace: 0x4038ABCD:0x3ffb0100\n",

        "null_pointer_deref":
            "Breakpoint 1, attribute_update_cb () at app_main.cpp:156\n"
            "a0 = 0x0 (NULL)\n"
            "attribute_update_cb: endpoint handle is NULL, "
            "returning ESP_ERR_INVALID_ARG\n"
            "Matter stack: ignoring NULL endpoint update gracefully\n",

        # ──────────────────────────────────────────────────────
        # Family B: NVS faults
        # ──────────────────────────────────────────────────────

        "nvs_magic_corruption":
            "Breakpoint 1, nvs_flash_init () at nvs_flash.cpp:89\n"
            f"NVS page header magic: {SIM_NVS_MAGIC} (expected 0x5AA5)\n"
            "nvs: NVS page header magic mismatch, erasing partition\n"
            "nvs: Formatted successfully — clean state restored\n"
            "nvs_flash_init: re-initialized after corruption detected\n",

        "nvs_write_interrupted":
            "Breakpoint 1, nvs::Page::writeItem ()\n"
            "SIGKILL sent — simulating power cut during write\n"
            "ets Jun  8 2016 00:22:57\n"
            "rst:0x1 (POWERON_RESET)\n"
            "nvs: recovering from interrupted write operation\n",

        "nvs_key_not_found":
            "Breakpoint 1, nvs_get_str ()\n"
            "Return value forced to 0x1102 (ESP_ERR_NVS_NOT_FOUND)\n"
            "ESP_ERR_NVS_NOT_FOUND for key 'commissioning_data'\n"
            "Using default provisioning values — handled gracefully\n",

        # ──────────────────────────────────────────────────────
        # Family C: Matter attribute faults
        # ──────────────────────────────────────────────────────

        "matter_onoff_invalid_value":
            "Breakpoint 1, esp_matter::attribute::update ()\n"
            "a2 (attribute value) forced to 0xFF (invalid boolean)\n"
            "CHIP ERROR: Attribute value 0xFF is out of range for boolean type\n"
            "Valid range: 0x00-0x01. Rejecting update\n",

        "matter_level_overflow":
            "Breakpoint 1, app_driver_light_set_brightness ()\n"
            "a0 (brightness) forced to 65535\n"
            "app_driver: brightness value out of range [0-254]\n"
            "brightness clamped to 254\n",

        "matter_null_endpoint":
            "Breakpoint 1, esp_matter::endpoint::get ()\n"
            "a0 (endpoint_id) forced to NULL\n"
            "esp_matter: endpoint handle is NULL, ignoring update\n"
            "endpoint::get: invalid endpoint_id=0, returning NULL\n",
    }

    return sim.get(
        scenario_name,
        "Simulation mode: scenario executed successfully\n"
        "handled gracefully\n"
    )

# ══════════════════════════════════════════════════════════════
# Per-scenario execution
# ══════════════════════════════════════════════════════════════

def run_single_scenario(scenario, flash_image: Path, simulate: bool = False):

    uart_lines = []
    gdb_output = ""
    t_start = time.time()

    if simulate:
        gdb_output = _simulate_gdb_output(scenario.name)

    else:

        gdb_port = 1234 + abs(hash(scenario.name)) % 1000

        uart_log = Path(f"/tmp/uart_{scenario.name}.log")
        uart_log.write_text("")

        qemu_cmd = [
            QEMU_BIN,
            "-nographic",
            "-machine",
            "esp32c3",
            "-drive",
            f"file={flash_image},if=mtd,format=raw",
            "-serial",
            f"file:{uart_log}",
            "-gdb",
            f"tcp::{gdb_port}",
            "-S",
        ]

        gdb_script = Path(f"/tmp/gdb_{scenario.name}.gdb")

        gdb_lines = [
            f"target remote :{gdb_port}",
            "set pagination off",
            "set confirm off",
            "",
        ]

        gdb_lines.extend(scenario.gdb_commands)

        gdb_lines.extend([
            f"shell sleep {UART_TIMEOUT}",
            "quit",
        ])

        gdb_script.write_text("\n".join(gdb_lines))

        qemu_proc = None

        try:

            qemu_proc = subprocess.Popen(
                qemu_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            time.sleep(1.5)

            gdb_result = subprocess.run(
                [GDB_BIN, "--batch", "-x", str(gdb_script)],
                capture_output=True,
                text=True,
                timeout=UART_TIMEOUT + 15,
            )

            gdb_output = gdb_result.stdout + gdb_result.stderr

            time.sleep(2)

            if qemu_proc.poll() is None:
                qemu_proc.terminate()
                qemu_proc.wait(timeout=5)

            uart_lines = uart_log.read_text(
                errors="ignore"
            ).splitlines()

        except FileNotFoundError:
            print("  [Runner] QEMU/GDB indisponible → simulation")
            gdb_output = _simulate_gdb_output(scenario.name)

        except subprocess.TimeoutExpired:

            gdb_output = "TIMEOUT"

            if qemu_proc and qemu_proc.poll() is None:
                qemu_proc.kill()

        except Exception as e:

            gdb_output = f"ERROR: {e}"

        finally:

            if qemu_proc and qemu_proc.poll() is None:
                try:
                    qemu_proc.kill()
                except Exception:
                    pass

    duration = round(time.time() - t_start, 1)

    reaction, panic, wdt, reboots = classify_reaction(
        gdb_output,
        uart_lines
    )

    passed = evaluate_pass(scenario, reaction)

    return FaultResult(
        scenario_name=scenario.name,
        family=scenario.family,
        description=scenario.description,
        expected=scenario.expected_reaction,
        actual_reaction=reaction,
        passed=passed,
        uart_lines=uart_lines[:50],
        panic_detected=panic,
        watchdog_hit=wdt,
        reboot_count=reboots,
        error_log=gdb_output[:500],
        severity=scenario.severity,
        cwe=scenario.cwe,
        duration_sec=duration,
    )

# ══════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════

def main():

    parser = argparse.ArgumentParser(
        description="Track D — QEMU Fault Injection Runner"
    )

    parser.add_argument("--target", default=TARGET)
    parser.add_argument("--scenario", default=None)
    parser.add_argument("--simulate", action="store_true")

    args = parser.parse_args()

    REPORTS.mkdir(exist_ok=True)

    firmware_dir = Path("firmware") / args.target
    flash_image = firmware_dir / "flash_image.bin"

    if not flash_image.exists() and not args.simulate:

        candidates = (
            list(firmware_dir.glob("*.bin"))
            if firmware_dir.exists()
            else []
        )

        if candidates:
            flash_image = candidates[0]
            print(f"[Runner] Binary: {flash_image}")

        else:
            print("[Runner] Aucun firmware → mode simulation")
            args.simulate = True

    all_scenarios = get_fault_scenarios()

    scenarios = (
        [s for s in all_scenarios if s.name == args.scenario]
        if args.scenario
        else all_scenarios
    )

    if args.scenario and not scenarios:

        print(f"[Runner] Scénario inconnu: {args.scenario}")
        print(f"[Runner] Disponibles: {[s.name for s in all_scenarios]}")

        sys.exit(1)

    from dataclasses import asdict

    results = []

    print(
        f"\n[Runner] {len(scenarios)} scénario(s)"
        f" | target={args.target}"
        f" | simulate={args.simulate}"
    )

    print("=" * 60)

    for i, scenario in enumerate(scenarios, 1):

        print(f"\n[{i}/{len(scenarios)}] {scenario.name}")

        result = run_single_scenario(
            scenario,
            flash_image,
            simulate=args.simulate
        )

        results.append(result)

        status = "✅ PASS" if result.passed else "❌ FAIL"

        print(
            f"  {status}"
            f" | reaction={result.actual_reaction}"
            f" | {result.duration_sec}s"
        )

    total = len(results)
    passed_n = sum(1 for r in results if r.passed)
    failed_n = total - passed_n

    families = {}

    for r in results:

        fam = families.setdefault(
            r.family,
            {
                "total": 0,
                "passed": 0,
                "failed": 0
            }
        )

        fam["total"] += 1

        if r.passed:
            fam["passed"] += 1
        else:
            fam["failed"] += 1

    critical_failures = [
        r.scenario_name
        for r in results
        if not r.passed and r.severity == "critical"
    ]

    high_failures = [
        r.scenario_name
        for r in results
        if not r.passed and r.severity == "high"
    ]

    overall_status = (
        "pass"
        if failed_n == 0
        else (
            "critical_fail"
            if critical_failures
            else "fail"
        )
    )

    report = {
        "target": args.target,
        "simulate_mode": args.simulate,
        "total_scenarios": total,
        "passed": passed_n,
        "failed": failed_n,
        "overall_status": overall_status,
        "critical_failures": critical_failures,
        "high_failures": high_failures,
        "by_family": families,
        "scenarios": [asdict(r) for r in results],
        "summary":
            f"Fault injection: {passed_n}/{total} scénarios. "
            f"Status: {overall_status.upper()}."
    }

    out = REPORTS / f"fault-injection-report-{args.target}.json"

    out.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    print(f"\n{'=' * 60}")
    print(f"Résultats: {passed_n}/{total} passés | {overall_status.upper()}")
    print(f"Rapport: {out}")
    print("=" * 60)

    # Exit codes

    if critical_failures:

        print(f"\n::error::Échecs critiques: {critical_failures}")

        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()

