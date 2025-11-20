
import sys
import os

# Add the current directory to sys.path
sys.path.append(os.getcwd())

print("Verifying imports...")

try:
    print("Importing app.styles...")
    from app import styles
    print("[OK] app.styles imported successfully")
except Exception as e:
    print(f"[FAIL] Failed to import app.styles: {e}")

try:
    print("Importing dashboard...")
    # We might not be able to fully import dashboard because of streamlit commands, 
    # but we can check for syntax errors by compiling it.
    with open('dashboard.py', 'r', encoding='utf-8') as f:
        compile(f.read(), 'dashboard.py', 'exec')
    print("[OK] dashboard.py syntax is valid")
except Exception as e:
    print(f"[FAIL] dashboard.py syntax error: {e}")

try:
    print("Importing app.ui_routes...")
    from app import ui_routes
    print("[OK] app.ui_routes imported successfully")
except Exception as e:
    print(f"[FAIL] Failed to import app.ui_routes: {e}")
