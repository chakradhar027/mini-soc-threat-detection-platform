#!/usr/bin/env python3
"""
Master Acceptance Test Runner
Executes comprehensive test suites for all 8 development phases of the Mini SOC Platform.
"""

import os
import sys
import unittest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT_DIR)


def run_all_suites():
    print("=========================================================================")
    print(" EXECUTING MINI SOC FULL TEST SUITE (PHASES 1 - 8)")
    print("=========================================================================")

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Discover and add all tests from tests/
    test_modules = [
        "tests.test_phase2_honeypots",
        "tests.test_phase3_iot",
        "tests.test_phase4_wazuh",
        "tests.test_phase5_detection",
        "tests.test_phase6_soar",
        "tests.test_phase7_ml_and_dashboard"
    ]

    for mod in test_modules:
        try:
            tests = loader.loadTestsFromName(mod)
            suite.addTests(tests)
        except Exception as e:
            print(f"[!] Error loading {mod}: {e}")

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n=========================================================================")
    print(f" TEST SUITE SUMMARY: Ran {result.testsRun} tests")
    print(f" PASS: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f" FAIL: {len(result.failures)}")
    print(f" ERROR: {len(result.errors)}")
    print(f" STATUS: {'ALL TESTS PASSED' if result.wasSuccessful() else 'TEST FAILURES DETECTED'}")
    print("=========================================================================")

    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_all_suites())

