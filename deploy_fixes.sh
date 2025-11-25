#!/bin/bash

# Quick deployment script for Azure + DLP fixes
# Run this to deploy all fixes at once

echo "=================================================="
echo "Deploying DLP Loop Fix + Azure Deployment Fix"
echo "=================================================="

# Check if we're in the right directory
if [ ! -f "requirements.txt" ]; then
    echo "❌ Error: Not in dlp-engine directory"
    echo "Run: cd d:/dlp-engine"
    exit 1
fi

# Check git status
echo ""
echo "📊 Current git status:"
git status --short

# Stage all changes
echo ""
echo "📦 Staging changes..."
git add .github/workflows/main_dlp-engine.yml
git add .deployment
git add .azure/config
git add email_notifications.py
git add DEPLOYMENT_READY.md
git add DLP_LOOP_FIX_SUMMARY.md
git add AZURE_DEPLOYMENT_FIX.md
git add test_dlp_fixes.py
git add deploy_fixes.sh

# Show what will be committed
echo ""
echo "📝 Changes to be committed:"
git status --short

# Confirm with user
echo ""
read -p "Deploy these changes? (y/n) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Deployment cancelled"
    exit 1
fi

# Commit
echo ""
echo "💾 Creating commit..."
git commit -m "fix: DLP loop prevention + Azure deployment configuration

Changes:
- Add masking at function entry for all email notifications
- Update email subject lines (remove emojis, use DLP-safe format)
- Fix GitHub Actions workflow to install Python dependencies
- Add Azure Oryx build configuration
- Add comprehensive documentation

Fixes:
- DLP email loop (800+ notification emails)
- Azure Web App ModuleNotFoundError: uvicorn.workers
- Unmasked sensitive data in notification emails

Testing:
- Run test_dlp_fixes.py to verify masking
- Monitor Azure deployment logs for successful build
- Test with single violation email
"

# Push to trigger deployment
echo ""
echo "🚀 Pushing to GitHub (will trigger Azure deployment)..."
git push origin main

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Successfully pushed to GitHub!"
    echo ""
    echo "=================================================="
    echo "NEXT STEPS:"
    echo "=================================================="
    echo ""
    echo "1. Monitor GitHub Actions:"
    echo "   https://github.com/$(git config --get remote.origin.url | sed 's/.*github.com[:/]\(.*\)\.git/\1/')/actions"
    echo ""
    echo "2. Check Azure deployment:"
    echo "   Go to Azure Portal → App Services → dlp-engine → Deployment Center"
    echo ""
    echo "3. Watch application logs:"
    echo "   Azure Portal → App Services → dlp-engine → Monitoring → Log stream"
    echo ""
    echo "4. Test the API:"
    echo "   curl https://dlp-engine-a9g7hjfvczfjmdn.eastus-01.azurewebsites.net/health"
    echo ""
    echo "5. Verify DLP fixes:"
    echo "   Send a test violation email and confirm:"
    echo "   - Exactly 1 email sent (no loop)"
    echo "   - KTP numbers are masked"
    echo "   - Subject has [WARNING] or [CRITICAL] (no emojis)"
    echo ""
    echo "=================================================="
    echo "Expected timeline: 5-10 minutes for full deployment"
    echo "=================================================="
else
    echo ""
    echo "❌ Failed to push to GitHub"
    echo "Check your internet connection and GitHub credentials"
    exit 1
fi
