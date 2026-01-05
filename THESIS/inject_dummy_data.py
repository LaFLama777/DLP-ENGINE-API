"""
Dummy Data Injection Script for DLP Engine Testing

This script injects realistic test data into the DLP database to demonstrate
the dashboard functionality including:
- Date range filtering
- Attack type detection (KTP/NIK, NPWP, Employee ID)
- Violation trends over time
- Multiple users with varying violation counts

Usage:
    python inject_dummy_data.py [--count NUMBER] [--clear]

Options:
    --count NUMBER  Number of dummy violations to create (default: 50)
    --clear         Clear all existing violations before injecting new data
"""

import sys
import argparse
from datetime import datetime, timedelta
import random
from database import SessionLocal, Offense, create_db_and_tables

# Dummy user data
DUMMY_USERS = [
    "john.doe@company.com",
    "jane.smith@company.com",
    "bob.wilson@company.com",
    "alice.johnson@company.com",
    "charlie.brown@company.com",
    "diana.prince@company.com",
    "edward.norton@company.com",
    "fiona.apple@company.com",
]

# Violation types with realistic titles
VIOLATION_TEMPLATES = [
    {
        "type": "KTP",
        "titles": [
            "Sensitive Data Detected: KTP Number in Email",
            "DLP Alert: KTP/NIK Disclosure Attempt",
            "Policy Violation: KTP Number Shared via Email",
            "High Risk: KTP Number Detected in Outbound Email",
        ]
    },
    {
        "type": "NPWP",
        "titles": [
            "Tax ID (NPWP) Disclosure Detected",
            "DLP Alert: NPWP Number in Email Content",
            "Policy Violation: NPWP Tax ID Shared",
            "Sensitive Data: NPWP Number Detected",
        ]
    },
    {
        "type": "Employee",
        "titles": [
            "Employee ID Disclosure in Email",
            "DLP Alert: Employee Identification Number Shared",
            "Policy Violation: Employee ID in External Email",
            "Confidential Data: Employee ID Detected",
        ]
    },
]


def clear_database(db):
    """Clear all existing offenses from the database"""
    try:
        count = db.query(Offense).count()
        db.query(Offense).delete()
        db.commit()
        print(f"[OK] Cleared {count} existing violations from database")
    except Exception as e:
        db.rollback()
        print(f"[ERROR] Error clearing database: {e}")
        sys.exit(1)


def generate_random_timestamp(days_back=90):
    """Generate a random timestamp within the last N days"""
    now = datetime.utcnow()
    random_days = random.randint(0, days_back)
    random_hours = random.randint(0, 23)
    random_minutes = random.randint(0, 59)

    return now - timedelta(
        days=random_days,
        hours=random_hours,
        minutes=random_minutes
    )


def inject_dummy_data(count=50, clear_first=False):
    """
    Inject dummy violation data into the database

    Args:
        count: Number of violations to create
        clear_first: Whether to clear existing data first
    """
    # Initialize database
    create_db_and_tables()
    db = SessionLocal()

    try:
        if clear_first:
            clear_database(db)

        print(f"\n[INJECTING] Creating {count} dummy violations...")
        print("=" * 60)

        violations_created = 0

        for i in range(count):
            # Select random user (some users will have more violations)
            user = random.choices(
                DUMMY_USERS,
                weights=[10, 8, 15, 5, 12, 6, 3, 7],  # Weighted to create varying offense counts
                k=1
            )[0]

            # Select random violation type
            violation_type = random.choice(VIOLATION_TEMPLATES)
            title = random.choice(violation_type["titles"])

            # Generate random timestamp
            timestamp = generate_random_timestamp(days_back=90)

            # Create violation
            new_offense = Offense(
                user_principal_name=user,
                incident_title=title,
                timestamp=timestamp
            )

            db.add(new_offense)
            violations_created += 1

            # Progress indicator
            if (i + 1) % 10 == 0:
                print(f"  Progress: {i + 1}/{count} violations created...")

        # Commit all violations
        db.commit()

        print("=" * 60)
        print(f"[SUCCESS] Successfully injected {violations_created} dummy violations")
        print()

        # Show statistics
        print("[STATISTICS] Database Statistics:")
        print("-" * 60)

        total = db.query(Offense).count()
        unique_users = db.query(Offense.user_principal_name).distinct().count()

        print(f"  Total Violations: {total}")
        print(f"  Unique Users: {unique_users}")
        print()

        # Show violation breakdown by type
        print("  Violation Breakdown by Type:")
        ktp_count = db.query(Offense).filter(Offense.incident_title.contains('KTP')).count()
        npwp_count = db.query(Offense).filter(Offense.incident_title.contains('NPWP')).count()
        emp_count = db.query(Offense).filter(Offense.incident_title.contains('Employee')).count()

        print(f"    - KTP/NIK: {ktp_count}")
        print(f"    - NPWP: {npwp_count}")
        print(f"    - Employee ID: {emp_count}")
        print()

        # Show top violators
        print("  Top 5 Users by Violation Count:")
        from sqlalchemy import func, desc
        top_users = db.query(
            Offense.user_principal_name,
            func.count(Offense.id).label('count')
        ).group_by(Offense.user_principal_name).order_by(
            desc('count')
        ).limit(5).all()

        for idx, (user, count) in enumerate(top_users, 1):
            print(f"    {idx}. {user}: {count} violations")

        print()
        print("=" * 60)
        print("[SUCCESS] Dummy data injection completed successfully!")
        print()
        print("[INFO] You can now test the dashboard at: http://localhost:8000")
        print()
        print("[FEATURES] Test these features:")
        print("  1. Date filtering (All Time, Today, Last 7 Days, Last 30 Days, Custom)")
        print("  2. Attack type detection (KTP/NIK, NPWP, Employee ID)")
        print("  3. Violation trends chart")
        print("  4. User statistics and high-risk users")
        print()

    except Exception as e:
        db.rollback()
        print(f"[ERROR] Error injecting dummy data: {e}")
        sys.exit(1)
    finally:
        db.close()


def main():
    """Main entry point for the script"""
    parser = argparse.ArgumentParser(
        description="Inject dummy test data into DLP Engine database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python inject_dummy_data.py                    # Inject 50 violations
  python inject_dummy_data.py --count 100        # Inject 100 violations
  python inject_dummy_data.py --clear            # Clear existing data and inject 50
  python inject_dummy_data.py --count 200 --clear  # Clear and inject 200
        """
    )

    parser.add_argument(
        '--count',
        type=int,
        default=50,
        help='Number of dummy violations to create (default: 50)'
    )

    parser.add_argument(
        '--clear',
        action='store_true',
        help='Clear all existing violations before injecting new data'
    )

    args = parser.parse_args()

    # Validate count
    if args.count < 1:
        print("[ERROR] Count must be at least 1")
        sys.exit(1)

    if args.count > 1000:
        print("[WARNING] Injecting more than 1000 violations may take a while")
        confirm = input("Continue? (y/n): ")
        if confirm.lower() != 'y':
            print("Cancelled.")
            sys.exit(0)

    # Run injection
    inject_dummy_data(count=args.count, clear_first=args.clear)


if __name__ == "__main__":
    main()
