"""
Generate Test Data for DLP Engine Demo

Creates realistic sample violations to populate the dashboard.
Run this to have demo data ready for presentations.

Usage:
    python generate_test_data.py
"""

import requests
from datetime import datetime, timedelta
import random

# DLP Engine API endpoint
API_URL = "http://localhost:8000/check-email"

# Sample data
USERS = [
    "john.doe@company.com",
    "jane.smith@company.com",
    "michael.johnson@company.com",
    "sarah.williams@company.com",
    "david.brown@company.com",
    "emily.davis@company.com",
]

VIOLATION_TEMPLATES = [
    {
        "type": "KTP",
        "content": "Customer data: Name: Ahmad Rizki, KTP: 3201234567890123, Phone: 081234567890"
    },
    {
        "type": "NPWP",
        "content": "Tax information: NPWP: 12.345.678.9-012.000 for billing purposes"
    },
    {
        "type": "Employee ID",
        "content": "Employee details: ID: EMP-2024-001, Department: IT"
    },
    {
        "type": "Multiple",
        "content": "Sensitive data: KTP: 3574123456789012, NPWP: 98.765.432.1-098.000, EMP-2024-002"
    },
    {
        "type": "KTP",
        "content": "Please process KTP 3301567890123456 for new customer registration"
    },
    {
        "type": "NPWP",
        "content": "Vendor payment info: NPWP 11.222.333.4-555.000"
    },
    {
        "type": "Sensitive Data",
        "content": "CONFIDENTIAL: Customer database backup attached, contains sensitive personal information"
    },
]

def generate_test_violations(count=20):
    """Generate test violations by calling the API"""
    print(f"🧪 Generating {count} test violations...\n")

    successful = 0
    failed = 0

    for i in range(count):
        # Pick random user and template
        user = random.choice(USERS)
        recipient = random.choice([u for u in USERS if u != user])
        template = random.choice(VIOLATION_TEMPLATES)

        # Create payload
        payload = {
            "sender": user,
            "recipient": recipient,
            "subject": f"Re: {template['type']} Information",
            "content": template["content"]
        }

        try:
            # Send to API
            response = requests.post(API_URL, json=payload, timeout=5)

            if response.status_code == 200:
                result = response.json()
                if result.get("should_block"):
                    successful += 1
                    print(f"✅ [{successful:2d}] {user[:20]:20s} | {template['type']:15s} | Blocked")
                else:
                    print(f"⚠️  [{i+1:2d}] {user[:20]:20s} | {template['type']:15s} | Not blocked (no sensitive data)")
            else:
                failed += 1
                print(f"❌ [{i+1:2d}] API error: {response.status_code}")

        except requests.exceptions.ConnectionError:
            print(f"\n❌ Connection failed! Is the DLP engine running?")
            print(f"   Start it with: uvicorn app.main:app --reload")
            return
        except Exception as e:
            failed += 1
            print(f"❌ [{i+1:2d}] Error: {e}")

    print(f"\n{'='*60}")
    print(f"✅ Successfully created: {successful} violations")
    print(f"❌ Failed: {failed}")
    print(f"{'='*60}")
    print(f"\n📊 View dashboard at: http://localhost:8000")

def create_scenario_based_data():
    """
    Create specific scenarios for demo:
    1. First-time offender (1 violation) - should trigger education
    2. Repeat offender (2 violations) - should trigger warning
    3. Critical offender (3+ violations) - should trigger revoke
    """
    print("🎬 Creating scenario-based demo data...\n")

    scenarios = {
        "First-time offender (Education)": {
            "user": "newcomer@company.com",
            "count": 1,
            "description": "Accidentally shared KTP once"
        },
        "Repeat offender (Warning)": {
            "user": "repeat.user@company.com",
            "count": 2,
            "description": "Shared sensitive data twice"
        },
        "Critical risk (Revoke)": {
            "user": "high.risk@company.com",
            "count": 4,
            "description": "Multiple violations - needs account suspension"
        }
    }

    for scenario_name, config in scenarios.items():
        print(f"\n{scenario_name}:")
        print(f"  User: {config['user']}")
        print(f"  Violations: {config['count']}")

        for i in range(config['count']):
            template = random.choice(VIOLATION_TEMPLATES)
            payload = {
                "sender": config['user'],
                "recipient": "admin@company.com",
                "subject": f"Data Request {i+1}",
                "content": template["content"]
            }

            try:
                response = requests.post(API_URL, json=payload, timeout=5)
                if response.status_code == 200:
                    print(f"  ✅ Violation {i+1}/{config['count']} created")
                else:
                    print(f"  ❌ Failed to create violation {i+1}")
            except Exception as e:
                print(f"  ❌ Error: {e}")
                return

    print(f"\n{'='*60}")
    print(f"🎯 Demo scenarios created!")
    print(f"{'='*60}")
    print(f"\nTest the admin actions:")
    print(f"1. Find 'newcomer@company.com' → Send Education (1 violation)")
    print(f"2. Find 'repeat.user@company.com' → Send Warning (2 violations)")
    print(f"3. Find 'high.risk@company.com' → Revoke Access (4 violations)")
    print(f"\n📊 View at: http://localhost:8000")

if __name__ == "__main__":
    import sys

    print("="*60)
    print("  DLP ENGINE - TEST DATA GENERATOR")
    print("="*60)
    print()

    mode = input("Choose mode:\n1. Generate random data (20 violations)\n2. Create demo scenarios (Education/Warning/Revoke)\n\nEnter 1 or 2: ").strip()

    if mode == "1":
        count = input("\nHow many violations to generate? [default: 20]: ").strip()
        count = int(count) if count.isdigit() else 20
        generate_test_violations(count)
    elif mode == "2":
        create_scenario_based_data()
    else:
        print("Invalid choice. Run again and choose 1 or 2.")
