#!/bin/bash
# Script to prepare files for GitHub push

echo "Preparing files for GitHub push..."

# Create a temporary directory for GitHub files
GITHUB_DIR="/tmp/HuaweiRPKICheck_GitHub"
rm -rf $GITHUB_DIR
mkdir -p $GITHUB_DIR

# Copy files for GitHub (without sensitive data)
echo "Copying files..."
cp /opt/HuaweiRPKICheck/HuaweiRPKICheck_GitHub.py $GITHUB_DIR/HuaweiRPKICheck.py
cp /opt/HuaweiRPKICheck/README_updated.md $GITHUB_DIR/README.md
cp /opt/HuaweiRPKICheck/HuaweiRPKICheck.conf.example $GITHUB_DIR/
cp /opt/HuaweiRPKICheck/HuaweiRPKI_credgen.py $GITHUB_DIR/
cp /opt/HuaweiRPKICheck/requirements.txt $GITHUB_DIR/
cp /opt/HuaweiRPKICheck/.gitignore $GITHUB_DIR/

# Clone the repository
echo "Cloning repository..."
cd /tmp
rm -rf HuaweiRPKICheck_repo
git clone https://github.com/paolokappa/HuaweiRPKICheck.git HuaweiRPKICheck_repo

# Copy new files to repo
echo "Updating repository files..."
cp -f $GITHUB_DIR/* /tmp/HuaweiRPKICheck_repo/

# Go to repo directory
cd /tmp/HuaweiRPKICheck_repo

# Show status
echo ""
echo "Repository status:"
git status

echo ""
echo "Files are ready in: /tmp/HuaweiRPKICheck_repo"
echo ""
echo "To complete the push, run:"
echo "  cd /tmp/HuaweiRPKICheck_repo"
echo "  git add ."
echo "  git commit -m 'Release v2.0 - Add recovery notifications, auto-reset, and improved email templates'"
echo "  git push origin main"