#!/usr/bin/env python3
"""
Run this script locally to verify all files are ready for deployment
"""
import os
import sys

def check_project_structure():
    """Check if all required files exist"""
    required_files = [
        'email_notifications.py',
        'app/main.py',
        'app/__init__.py',
        'database.py',
        'graph_client.py',
        'requirements.txt',
        '.env'
    ]
    
    print("=" * 60)
    print("CHECKING PROJECT STRUCTURE")
    print("=" * 60)
    
    missing_files = []
    for file in required_files:
        exists = os.path.exists(file)
        status = "✓" if exists else "✗"
        print(f"{status} {file}")
        if not exists:
            missing_files.append(file)
    
    print()
    if missing_files:
        print(f"❌ Missing {len(missing_files)} required files")
        return False
    else:
        print("✅ All required files present")
        return True

def check_imports():
    """Check if email_notifications can be imported"""
    print("\n" + "=" * 60)
    print("CHECKING IMPORTS")
    print("=" * 60)
    
    # Add current directory to path
    sys.path.insert(0, os.getcwd())
    
    try:
        import app.email_notifications as email_notifications
        print("✓ email_notifications.py can be imported")
        
        # Check for required classes/functions
        required_items = [
            'GraphEmailNotificationService',
            'send_violation_email',
            'send_socialization_email'
        ]
        
        for item in required_items:
            if hasattr(email_notifications, item):
                print(f"  ✓ {item} found")
            else:
                print(f"  ✗ {item} NOT found")
        
        return True
    except ImportError as e:
        print(f"✗ Cannot import email_notifications: {e}")
        return False

def check_environment_variables():
    """Check if required environment variables are set"""
    print("\n" + "=" * 60)
    print("CHECKING ENVIRONMENT VARIABLES")
    print("=" * 60)
    
    from dotenv import load_dotenv
    load_dotenv()
    
    required_vars = [
        'TENANT_ID',
        'BOT_CLIENT_ID',
        'BOT_CLIENT_SECRET',
        'SENDER_EMAIL',
        'DATABASE_URL'
    ]
    
    missing_vars = []
    for var in required_vars:
        value = os.getenv(var)
        if value:
            # Mask sensitive values
            if 'SECRET' in var or 'PASSWORD' in var:
                display_value = '***' + value[-4:] if len(value) > 4 else '****'
            elif 'URL' in var and '@' in value:
                display_value = value[:value.find('@')] + '@***'
            else:
                display_value = value[:20] + '...' if len(value) > 20 else value
            
            print(f"✓ {var} = {display_value}")
        else:
            print(f"✗ {var} = NOT SET")
            missing_vars.append(var)
    
    print()
    if missing_vars:
        print(f"⚠️  {len(missing_vars)} environment variables not set")
        print("   Make sure these are configured in Azure App Service settings")
        return False
    else:
        print("✅ All environment variables set")
        return True

def main():
    print("\n🔍 DLP Engine Deployment Verification\n")
    
    results = {
        'structure': check_project_structure(),
        'imports': check_imports(),
        'env_vars': check_environment_variables()
    }
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    all_passed = all(results.values())
    
    for check, passed in results.items():
        status = "✅" if passed else "❌"
        print(f"{status} {check.replace('_', ' ').title()}")
    
    print()
    if all_passed:
        print("✅ ALL CHECKS PASSED - Ready for deployment")
        print("\nNext steps:")
        print("1. Commit your changes: git add . && git commit -m 'Fix email notifications'")
        print("2. Push to main: git push origin main")
        print("3. Check Azure deployment logs")
    else:
        print("❌ SOME CHECKS FAILED - Fix issues before deploying")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())