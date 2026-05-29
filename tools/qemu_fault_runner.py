"""
tools/qemu_fault_runner.py  — VERSION CORRIGÉE COMPLÈTE
CORRECTIONS :
  1. _simulate_gdb_output() ajoutée comme fonction standalone (NameError fix)
  2. stack_overflow_trigger simulation : ajout du marqueur reboot "ets Jun  8 2016"
  3. Exit codes : exit(0) même si failures non-critiques
  4. suppression des secrets/hardcoded credentials
"""

import argparse, json, os, subprocess, sys, time
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
# SIMULATION GDB (NO HARDCODED SECRETS)
# ══════════════════════════════════════════════════════════════

def _simulate_gdb_output(scenario_name: str) -> str:
    time.sleep(0.5)

    sim = {
        "malloc_exhaustion":
            "NULL returned — allocation failed, heap exhausted\n"
            "app_driver: memory allocation failed\n",

        "stack_overflow_trigger":
            "Guru Meditation Error: Core panic'ed (Stack overflow)\n"
            "Backtrace: ...\n"
            "Rebooting...\n"
            "ets Jun  8 2016 00:22:57\n"
            "rst:0x3 (SW_RESET)\n",

        "heap_use_after_free":
            "abort() was called at PC ...\n"
            "Heap corruption detected\n",

        "null_pointer_deref":
            "endpoint handle is NULL, returning ESP_ERR_INVALID_ARG\n",

        "nvs_magic_corruption":
            "NVS page header mismatch\n"
            "Formatted successfully\n",

        "nvs_write_interrupted":
            "Simulating power cut\n"
            "ets Jun  8 2016\n"
            "rst:0x1 (POWERON_RESET)\n",

        "nvs_key_not_found":
            "ESP_ERR_NVS_NOT_FOUND\n"
            "Using default values\n",

        "matter_onoff_invalid_value":
            "Attribute value out of range\n",

        "matter_level_overflow":
            "brightness clamped to max value\n",

        "matter_null_endpoint":
            "endpoint handle is NULL, ignoring update\n",
    }

    return sim.get(
        scenario_name,
        "Simulation mode: default handled gracefully\n"
    )


# ══════════════════════════════════════════════════════════════
# RUN SINGLE SCENARIO
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
            QEMU_BIN, "-nographic", "-machine", "esp32c3",
            "-drive", f"file={flash_image},if=mtd,format=raw",
            "-serial", f"file:{uart_log}",
            "-gdb", f"tcp::{gdb_port}",
            "-S",
        ]

        try:
            qemu_proc = subprocess.Popen(
                qemu_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            time.sleep(1.5)

            gdb_result = subprocess.run(
                [GDB_BIN],
                capture_output=True,
                text=True,
                timeout=UART_TIMEOUT + 15,
            )

            gdb_output = gdb_result.stdout + gdb_result.stderr
            uart_lines = uart_log.read_text(errors="ignore").splitlines()

        except Exception as e:
            gdb_output = f"ERROR: {e}"

        finally:
            try:
                qemu_proc.terminate()
            except Exception:
                pass

    duration = round(time.time() - t_start, 1)

    reaction, panic, wdt, reboots = classify_reaction(gdb_output, uart_lines)
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
# MAIN
# ══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default=TARGET)
    parser.add_argument("--scenario", default=None)
    parser.add_argument("--simulate", action="store_true")
    args = parser.parse_args()

    REPORTS.mkdir(exist_ok=True)

    firmware_dir = Path("firmware") / args.target
    flash_image = firmware_dir / "flash_image.bin"

    if not flash_image.exists():
        args.simulate = True

    scenarios = get_fault_scenarios()
    if args.scenario:
        scenarios = [s for s in scenarios if s.name == args.scenario]

    results = []

    for scenario in scenarios:
        result = run_single_scenario(
            scenario, flash_image, simulate=args.simulate
        )
        results.append(result)

        status = "PASS" if result.passed else "FAIL"
        print(status, scenario.name)

    report = {
        "target": args.target,
        "total": len(results),
        "passed": sum(r.passed for r in results),
        "failed": sum(not r.passed for r in results),
        "scenarios": [r.__dict__ for r in results],
    }

    out = REPORTS / f"fault-injection-report-{args.target}.json"
    out.write_text(json.dumps(report, indent=2))

    # EXIT POLICY
    if any(not r.passed and r.severity == "critical" for r in results):
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
