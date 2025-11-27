"""
Pre-Flight Check - Verify DLP Engine is Ready for Testing
Run this before starting your testing session.
"""
import sys
import os

def check_files():
    """Check required files exist"""
    required_files = [
        'app/main.py',
        'sensitive_data.py',
        'database.py',
        'email_notifications.py',
        'generate_test_data.py',
        '.env',
        'requirements.txt'
    ]

    print("=" * 60)
    print("FILE CHECK")
    print("=" * 60)

    all_present = True
    for file in required_files:
        exists = os.path.exists(file)
        status = "[OK]" if exists else "[MISSING]"
        print(f"{status} {file}")
        if not exists:
            all_present = False

    return all_present

def check_dependencies():
    """Check Python packages are installed"""
    print("\n" + "=" * 60)
    print("DEPENDENCY CHECK")
    print("=" * 60)

    packages = [
        'fastapi',
        'uvicorn',
        'sqlalchemy',
        'pydantic',
        'requests',
        'httpx'
    ]

    all_installed = True
    for package in packages:
        try:
            __import__(package)
            print(f"[OK] {package}")
        except ImportError:
            print(f"[MISSING] {package}")
            all_installed = False

    return all_installed

def check_env():
    """Check .env configuration"""
    print("\n" + "=" * 60)
    print("ENVIRONMENT CONFIGURATION")
    print("=" * 60)

    if not os.path.exists('.env'):
        print("[WARNING] .env file not found")
        return False

    required_vars = [
        'DATABASE_URL',
        'MICROSOFT_CLIENT_ID',
        'MICROSOFT_CLIENT_SECRET',
        'MICROSOFT_TENANT_ID'
    ]

    with open('.env', 'r') as f:
        env_content = f.read()

    all_present = True
    for var in required_vars:
        if var in env_content:
            # Check if it has a value (not empty)
            for line in env_content.split('\n'):
                if line.startswith(var):
                    value = line.split('=', 1)[1].strip() if '=' in line else ''
                    if value and value != '""' and value != "''":
                        print(f"[OK] {var} is configured")
                    else:
                        print(f"[WARNING] {var} is empty")
                        all_present = False
                    break
        else:
            print(f"[MISSING] {var}")
            all_present = False

    return all_present

def check_database():
    """Check database connection"""
    print("\n" + "=" * 60)
    print("DATABASE CONNECTION")
    print("=" * 60)

    try:
        from database import engine
        connection = engine.connect()
        connection.close()
        print("[OK] Database connection successful")
        return True
    except Exception as e:
        print(f"[ERROR] Database connection failed: {e}")
        return False

def main():
    print("\n")
    print("=" * 60)
    print("  DLP ENGINE - PRE-FLIGHT CHECK")
    print("=" * 60)
    print()

    results = []

    # Run checks
    results.append(("Files", check_files()))
    results.append(("Dependencies", check_dependencies()))
    results.append(("Environment", check_env()))
    results.append(("Database", check_database()))

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    all_passed = all([r[1] for r in results])

    for name, passed in results:
        status = "[PASS]" if passed else "[FAIL]"
        print(f"{status} {name}")

    print("\n" + "=" * 60)

    if all_passed:
        print("STATUS: READY FOR TESTING")
        print("=" * 60)
        print("\nNext steps:")
        print("1. Start server: uvicorn app.main:app --reload")
        print("2. Generate test data: python generate_test_data.py")
        print("3. Open dashboard: http://localhost:8000")
        print("\nSee TESTING_WORKFLOW.md for detailed instructions.")
    else:
        print("STATUS: NOT READY - FIX ISSUES ABOVE")
        print("=" * 60)
        print("\nCommon fixes:")
        print("- Missing dependencies: pip install -r requirements.txt")
        print("- Missing .env: Copy from .env.example or create new")
        print("- Database error: Check DATABASE_URL in .env")

    print()

if __name__ == "__main__":
    main()
