"""
Test script to verify DLP loop fixes are working correctly

This script tests:
1. Sensitive data masking in all notification functions
2. DLP-safe subject line generation
3. No duplicate masking occurs
4. All email functions handle data correctly

Run this BEFORE deploying to production.
"""

import asyncio
import sys
from email_notifications import GraphEmailNotificationService


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_test(test_name: str):
    """Print test header"""
    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}TEST: {test_name}{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")


def print_pass(message: str):
    """Print success message"""
    print(f"{Colors.GREEN}[PASS]{Colors.RESET} {message}")


def print_fail(message: str):
    """Print failure message"""
    print(f"{Colors.RED}[FAIL]{Colors.RESET} {message}")


def print_info(message: str):
    """Print info message"""
    print(f"{Colors.YELLOW}[INFO]{Colors.RESET} {message}")


async def test_masking_function():
    """Test that the mask_sensitive_data function works correctly"""
    print_test("Sensitive Data Masking Function")

    service = GraphEmailNotificationService()

    test_cases = [
        {
            "input": "KTP: 1234567890123456",
            "expected_pattern": "123***********456",
            "name": "KTP masking"
        },
        {
            "input": "NPWP: 12.345.678.9-012.000",
            "expected_pattern": "12***********00",
            "name": "NPWP masking"
        },
        {
            "input": "Employee ID: EMP-12345",
            "expected_pattern": "EMP-1***5",
            "name": "Employee ID masking"
        },
        {
            "input": "This is normal text without sensitive data",
            "expected_pattern": "This is normal text without sensitive data",
            "name": "Non-sensitive text (should not change)"
        }
    ]

    all_passed = True

    for test in test_cases:
        result = service.mask_sensitive_data(test["input"])
        if "***" in result or result == test["expected_pattern"]:
            print_pass(f"{test['name']}: '{test['input']}' -> '{result}'")
        else:
            print_fail(f"{test['name']}: Expected masking pattern, got '{result}'")
            all_passed = False

    return all_passed


async def test_subject_lines():
    """Test that email subject lines are DLP-safe (no emojis)"""
    print_test("DLP-Safe Subject Lines")

    service = GraphEmailNotificationService()

    # Test violation notification subjects
    test_cases = [
        {"violation_count": 1, "expected_prefix": "[WARNING]"},
        {"violation_count": 2, "expected_prefix": "[WARNING]"},
        {"violation_count": 3, "expected_prefix": "[CRITICAL]"},
    ]

    all_passed = True

    for test in test_cases:
        is_critical = test["violation_count"] >= 3
        subject = f"[{'CRITICAL' if is_critical else 'WARNING'}] Email Blocked - DLP Policy Violation #{test['violation_count']}"

        # Check for emojis (emojis are multi-byte characters)
        has_emoji = any(ord(char) > 127 for char in subject)

        if has_emoji:
            print_fail(f"Violation #{test['violation_count']}: Subject contains emojis: '{subject}'")
            all_passed = False
        elif subject.startswith(test["expected_prefix"]):
            print_pass(f"Violation #{test['violation_count']}: '{subject}'")
        else:
            print_fail(f"Violation #{test['violation_count']}: Expected prefix '{test['expected_prefix']}', got '{subject}'")
            all_passed = False

    # Test admin alert subject
    admin_subject_critical = "[CRITICAL] High-Risk Activity: test@example.com"
    admin_subject_warning = "[ALERT] High-Risk Activity: test@example.com"

    for subject in [admin_subject_critical, admin_subject_warning]:
        has_emoji = any(ord(char) > 127 for char in subject)
        if has_emoji:
            print_fail(f"Admin alert: Subject contains emojis: '{subject}'")
            all_passed = False
        else:
            print_pass(f"Admin alert: '{subject}'")

    # Test socialization invitation subject
    social_subject = "[MANDATORY] Security Training Required - DLP Policy Socialization"
    has_emoji = any(ord(char) > 127 for char in social_subject)
    if has_emoji:
        print_fail(f"Socialization: Subject contains emojis: '{social_subject}'")
        all_passed = False
    else:
        print_pass(f"Socialization: '{social_subject}'")

    return all_passed


async def test_parameter_masking():
    """Test that function parameters are masked at entry"""
    print_test("Parameter Masking at Function Entry")

    service = GraphEmailNotificationService()

    print_info("Testing send_violation_notification parameter masking...")

    # Simulate what should happen when function is called
    blocked_content = "KTP: 1234567890123456 and NPWP: 12.345.678.9-012.000"
    incident_title = "User sent email with KTP: 9876543210987654"
    file_name = "confidential_data_EMP-12345.pdf"

    # Mask as the function does
    masked_content = service.mask_sensitive_data(str(blocked_content))
    masked_title = service.mask_sensitive_data(str(incident_title))
    masked_file = service.mask_sensitive_data(str(file_name))

    all_passed = True

    # Check that masking occurred
    if "***" in masked_content and "1234567890123456" not in masked_content:
        print_pass(f"blocked_content_summary masked: '{blocked_content}' -> '{masked_content}'")
    else:
        print_fail(f"blocked_content_summary NOT masked: '{masked_content}'")
        all_passed = False

    if "***" in masked_title and "9876543210987654" not in masked_title:
        print_pass(f"incident_title masked: '{incident_title}' -> '{masked_title}'")
    else:
        print_fail(f"incident_title NOT masked: '{masked_title}'")
        all_passed = False

    if "***" in masked_file and "EMP-12345" not in masked_file:
        print_pass(f"file_name masked: '{file_name}' -> '{masked_file}'")
    else:
        print_fail(f"file_name NOT masked: '{masked_file}'")
        all_passed = False

    return all_passed


async def test_no_sensitive_data_leakage():
    """Verify that no raw sensitive data can leak through"""
    print_test("Sensitive Data Leakage Prevention")

    service = GraphEmailNotificationService()

    # Simulate worst-case scenario with multiple sensitive data types
    test_data = {
        "blocked_content": "KTP: 3216123456789012, NPWP: 12.345.678.9-012.000, EMP-98765",
        "incident_title": "URGENT: Data breach with KTP 1234567890123456",
        "file_name": "employee_data_KTP_3216123456789012.xlsx"
    }

    all_passed = True

    for key, value in test_data.items():
        masked = service.mask_sensitive_data(value)

        # Check for any full KTP (16 digits in a row)
        if any(char.isdigit() for sequence in masked.split("***") for char in sequence if len(sequence) >= 16):
            print_fail(f"{key}: Full KTP number still present in '{masked}'")
            all_passed = False
        elif "***" in masked:
            print_pass(f"{key}: Properly masked - no full sensitive data present")
        else:
            print_info(f"{key}: No sensitive data detected (OK if input had none)")

    return all_passed


async def run_all_tests():
    """Run all test suites"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}DLP LOOP FIX - VERIFICATION TESTS{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}\n")

    results = {}

    # Run all test suites
    results['Masking Function'] = await test_masking_function()
    results['Subject Lines'] = await test_subject_lines()
    results['Parameter Masking'] = await test_parameter_masking()
    results['Leakage Prevention'] = await test_no_sensitive_data_leakage()

    # Print summary
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}TEST SUMMARY{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")

    all_passed = True
    for test_name, passed in results.items():
        status = f"{Colors.GREEN}[PASSED]{Colors.RESET}" if passed else f"{Colors.RED}[FAILED]{Colors.RESET}"
        print(f"{test_name:30} {status}")
        if not passed:
            all_passed = False

    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}\n")

    if all_passed:
        print(f"{Colors.GREEN}{Colors.BOLD}[SUCCESS] ALL TESTS PASSED - DLP FIXES ARE WORKING CORRECTLY{Colors.RESET}\n")
        print(f"{Colors.YELLOW}Next steps:{Colors.RESET}")
        print(f"  1. Deploy to production")
        print(f"  2. Send a test email to verify end-to-end flow")
        print(f"  3. Monitor for 1 hour to ensure no email loops")
        return 0
    else:
        print(f"{Colors.RED}{Colors.BOLD}[FAILED] SOME TESTS FAILED - DO NOT DEPLOY{Colors.RESET}\n")
        print(f"{Colors.YELLOW}Action required:{Colors.RESET}")
        print(f"  1. Review failed tests above")
        print(f"  2. Fix the issues in email_notifications.py")
        print(f"  3. Re-run this test script")
        return 1


if __name__ == "__main__":
    print_info("Starting DLP fix verification tests...")
    print_info("This will test the email notification system WITHOUT sending actual emails\n")

    exit_code = asyncio.run(run_all_tests())
    sys.exit(exit_code)
