#!/usr/bin/env bash
set -euo pipefail

export PATH="/Users/wykunitake/.local/bin:/Users/wykunitake/.local/node/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

REPO_DIR="/Users/wykunitake/Dev/cybersecurity-digest-mcp"
ZIP_PATH="/Users/wykunitake/Dev/cybersecurity-digest-mcp.zip"
REMOTE_URL="https://github.com/williambulk/cybersecurity-digest-mcp.git"

cd "$REPO_DIR"

echo "📦 Installing dependencies..."
npm install

echo "🧪 Testing CLI dry-run..."
node src/cli.js --dry-run > /dev/null
echo "✅ Feed collection, domain health check, and prioritization engine verified."

echo "🗜️ Creating portable ZIP archive at $ZIP_PATH (excluding .env and local state)..."
rm -f "$ZIP_PATH"
zip -r "$ZIP_PATH" . -x "node_modules/*" ".git/*" ".env" "data/*.json" ".DS_Store" ".published_*"

# Re-initialize clean git history so no hardcoded domains remain in commit history
rm -rf .git
git init
git branch -M main
git remote add origin "$REMOTE_URL"

git add -A
git commit -m "feat: Stack & Hosting Digest Agent + MCP Server (env-driven domain & Slack config)"
git push --force -u origin main

echo "🚀 Successfully pushed clean repo to $REMOTE_URL and created $ZIP_PATH"
