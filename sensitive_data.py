"""
Centralized Sensitive Data Detection and Masking Module

This module provides unified detection and masking for Indonesian sensitive data types:
- KTP (Kartu Tanda Penduduk) - National ID Card
- NPWP (Nomor Pokok Wajib Pajak) - Tax Identification Number
- Employee IDs - Company employee identification numbers

Usage:
    from sensitive_data import SensitiveDataDetector

    # Detect sensitive data
    result = SensitiveDataDetector.check_sensitive_content("KTP: 1234567890123456")
    print(result["has_sensitive_data"])  # True

    # Mask sensitive data
    masked = SensitiveDataDetector.mask_sensitive_data("KTP: 1234567890123456")
    print(masked)  # "KTP: 123***********456"
"""

import re
from typing import Dict, Any, List


class SensitiveDataDetector:
    """
    Centralized class for detecting and masking sensitive Indonesian data.

    This class consolidates all sensitive data detection logic in one place,
    replacing duplicate implementations in main.py and email_notifications.py.
    """

    # Regex patterns as class constants for easy modification
    KTP_PATTERN = r'\b\d{16}\b'
    # NPWP pattern supports formats: 123456789012345 or 12.345.678.9-012.345
    NPWP_PATTERN = r'npwp[:\s-]*(\d{2}[\.\s-]?\d{3}[\.\s-]?\d{3}[\.\s-]?\d{1}[\.\s-]?\d{3}[\.\s-]?\d{3}|\d{15,16})'
    # Updated to support 4-10 digit employee IDs (e.g., EMP-1234, EMP20260109)
    EMPLOYEE_ID_PATTERN = r'\b(EMP|KARY|NIP)([-\s]?)(\d{4,10})\b'

    # Masking patterns
    KTP_MASK_PATTERN = r'\b(\d{3})\d{10}(\d{3})\b'
    # Updated NPWP masking to handle both formats
    NPWP_MASK_PATTERN = r'(npwp[:\s-]*)(\d{2})([\.\s-]?)\d{3}([\.\s-]?)\d{3}([\.\s-]?)\d{1}([\.\s-]?)\d{3}([\.\s-]?)(\d{3})'
    # Updated masking pattern to support longer IDs
    EMPLOYEE_ID_MASK_PATTERN = r'\b(EMP|KARY|NIP)([-\s]?)(\d{1,2})\d+(\d{1,2})\b'

    @classmethod
    def detect_ktp(cls, text: str) -> List[str]:
        """
        Detect 16-digit KTP (Indonesian National ID) numbers in text.

        Args:
            text: Text to search for KTP numbers

        Returns:
            List of KTP numbers found (without masking)

        Example:
            >>> SensitiveDataDetector.detect_ktp("My KTP is 1234567890123456")
            ['1234567890123456']
        """
        if not text:
            return []
        return re.findall(cls.KTP_PATTERN, text)

    @classmethod
    def detect_npwp(cls, text: str) -> List[str]:
        """
        Detect NPWP (Indonesian Tax ID) numbers in text.

        Looks for the keyword "NPWP" followed by 15-16 digits.

        Args:
            text: Text to search for NPWP numbers

        Returns:
            List of NPWP numbers found (without masking)

        Example:
            >>> SensitiveDataDetector.detect_npwp("NPWP: 123456789012345")
            ['123456789012345']
        """
        if not text:
            return []
        return re.findall(cls.NPWP_PATTERN, text, re.IGNORECASE)

    @classmethod
    def detect_employee_id(cls, text: str) -> List[str]:
        """
        Detect employee ID numbers in text.

        Looks for patterns like: EMP-12345, KARY-67890, NIP-11111

        Args:
            text: Text to search for employee IDs

        Returns:
            List of employee IDs found (without masking)

        Example:
            >>> SensitiveDataDetector.detect_employee_id("Employee EMP-12345")
            ['EMP-12345']
        """
        if not text:
            return []
        # Returns tuples, so join them
        matches = re.findall(cls.EMPLOYEE_ID_PATTERN, text, re.IGNORECASE)
        return [''.join(match) for match in matches]

    @classmethod
    def mask_sensitive_data(cls, text: str) -> str:
        """
        Mask all sensitive data in text for safe display/logging.

        Masks:
        - KTP: Shows first 3 and last 3 digits (e.g., 123***********456)
        - NPWP: Shows first 2 and last 2 digits (e.g., 12***********34)
        - Employee ID: Shows first and last digit (e.g., EMP-1***5)

        Args:
            text: Text containing sensitive data to mask

        Returns:
            Text with all sensitive data masked

        Example:
            >>> text = "KTP: 1234567890123456, NPWP: 12.345.678.9-012.345"
            >>> SensitiveDataDetector.mask_sensitive_data(text)
            "KTP: 123***********456, NPWP: 12***********45"
        """
        if not text:
            return ""

        # Mask KTP (16 digits) - show first 3 and last 3
        text = re.sub(cls.KTP_MASK_PATTERN, r'\1***********\2', text)

        # Mask NPWP - show first 2 and last 3 digits
        text = re.sub(
            cls.NPWP_MASK_PATTERN,
            r'\1\2\3***\6***\8',
            text,
            flags=re.IGNORECASE
        )

        # Mask Employee ID - show first and last digit
        text = re.sub(
            cls.EMPLOYEE_ID_MASK_PATTERN,
            r'\1\2\3***\4',
            text,
            flags=re.IGNORECASE
        )

        return text

    @classmethod
    def check_sensitive_content(cls, content: str) -> Dict[str, Any]:
        """
        Comprehensively check if content contains any sensitive data.

        Performs all detection checks and returns detailed results.

        Args:
            content: Text content to analyze

        Returns:
            Dictionary containing:
            - has_sensitive_data: bool - True if any sensitive data found
            - ktp_count: int - Number of KTP numbers found
            - npwp_count: int - Number of NPWP numbers found
            - employee_id_count: int - Number of employee IDs found
            - violation_types: List[str] - Types of violations found
            - violations: List[dict] - Detailed violation breakdown

        Example:
            >>> text = "Email with KTP: 1234567890123456 and NPWP: 123456789012345"
            >>> result = SensitiveDataDetector.check_sensitive_content(text)
            >>> result["has_sensitive_data"]
            True
            >>> result["violation_types"]
            ['KTP', 'NPWP']
        """
        ktp_found = cls.detect_ktp(content)
        npwp_found = cls.detect_npwp(content)
        employee_id_found = cls.detect_employee_id(content)

        has_sensitive = bool(ktp_found or npwp_found or employee_id_found)

        violation_types = []
        if ktp_found:
            violation_types.append("KTP")
        if npwp_found:
            violation_types.append("NPWP")
        if employee_id_found:
            violation_types.append("Employee ID")

        return {
            "has_sensitive_data": has_sensitive,
            "ktp_count": len(ktp_found),
            "npwp_count": len(npwp_found),
            "employee_id_count": len(employee_id_found),
            "violation_types": violation_types,
            "violations": [
                {"type": "KTP", "count": len(ktp_found)},
                {"type": "NPWP", "count": len(npwp_found)},
                {"type": "Employee ID", "count": len(employee_id_found)}
            ]
        }

    @classmethod
    def mask_email(cls, email: str) -> str:
        """
        Mask an email address for privacy protection.

        Masks the local part of the email, keeping first 2 and last 2 characters visible.

        Args:
            email: Email address to mask

        Returns:
            Masked email address

        Example:
            >>> SensitiveDataDetector.mask_email("john.doe@example.com")
            'jo****oe@example.com'
        """
        if not email or '@' not in email:
            return email

        try:
            local, domain = email.split('@', 1)
            if len(local) <= 4:
                # For short emails, mask middle characters only
                masked_local = local[0] + '*' * (len(local) - 1)
            else:
                # Keep first 2 and last 2 characters
                masked_local = local[:2] + '*' * (len(local) - 4) + local[-2:]
            return f"{masked_local}@{domain}"
        except:
            return email


# Example usage and testing
if __name__ == "__main__":
    print("=== Sensitive Data Detector - Test Cases ===\n")

    # Test 1: KTP Detection
    test_text = "My KTP number is 1234567890123456"
    print(f"Test 1: {test_text}")
    print(f"KTPs found: {SensitiveDataDetector.detect_ktp(test_text)}")
    print(f"Masked: {SensitiveDataDetector.mask_sensitive_data(test_text)}\n")

    # Test 2: NPWP Detection
    test_text = "NPWP: 12.345.678.9-012.345"
    print(f"Test 2: {test_text}")
    print(f"NPWPs found: {SensitiveDataDetector.detect_npwp(test_text)}")
    print(f"Masked: {SensitiveDataDetector.mask_sensitive_data(test_text)}\n")

    # Test 3: Employee ID Detection
    test_text = "Employee ID: EMP-12345"
    print(f"Test 3: {test_text}")
    print(f"Employee IDs found: {SensitiveDataDetector.detect_employee_id(test_text)}")
    print(f"Masked: {SensitiveDataDetector.mask_sensitive_data(test_text)}\n")

    # Test 4: Combined Detection
    test_text = "Email: KTP 1234567890123456, NPWP: 123456789012345, EMP-54321"
    print(f"Test 4: {test_text}")
    result = SensitiveDataDetector.check_sensitive_content(test_text)
    print(f"Has sensitive data: {result['has_sensitive_data']}")
    print(f"Violation types: {result['violation_types']}")
    print(f"Masked: {SensitiveDataDetector.mask_sensitive_data(test_text)}\n")

    print("✅ All tests completed!")
