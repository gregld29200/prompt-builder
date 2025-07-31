#!/bin/bash

# Teachinspire Prompt Builder - D1 Database Setup Script
# This script sets up the D1 database for the Teachinspire Prompt Builder

set -e  # Exit on any error

echo "🚀 Setting up Teachinspire Prompt Builder D1 Database..."

# Check if wrangler is installed
if ! command -v wrangler &> /dev/null; then
    echo "❌ Wrangler CLI is not installed. Please install it first:"
    echo "   npm install -g wrangler"
    exit 1
fi

# Check if user is logged in to Cloudflare
if ! wrangler whoami &> /dev/null; then
    echo "❌ You are not logged in to Cloudflare. Please run:"
    echo "   wrangler login"
    exit 1
fi

echo "✅ Wrangler CLI is ready"

# Create the D1 database
echo "📊 Creating D1 database..."
DB_OUTPUT=$(wrangler d1 create teachinspire-prompt-builder-db)
echo "$DB_OUTPUT"

# Extract database ID from the output
DATABASE_ID=$(echo "$DB_OUTPUT" | grep -o 'database_id = "[^"]*"' | cut -d'"' -f2)

if [ -z "$DATABASE_ID" ]; then
    echo "❌ Failed to extract database ID. Please check the output above and update wrangler.toml manually."
    exit 1
fi

echo "✅ Database created with ID: $DATABASE_ID"

# Update wrangler.toml with the database ID
echo "📝 Updating wrangler.toml with database ID..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    sed -i '' "s/database_id = \"\"/database_id = \"$DATABASE_ID\"/" wrangler.toml
else
    # Linux
    sed -i "s/database_id = \"\"/database_id = \"$DATABASE_ID\"/" wrangler.toml
fi

echo "✅ wrangler.toml updated"

# Run the initial migration
echo "🔄 Running initial database migration..."
wrangler d1 execute teachinspire-prompt-builder-db --file=database/migrations/001_initial_schema.sql

echo "✅ Initial migration completed"

# Verify the setup
echo "🔍 Verifying database setup..."
wrangler d1 execute teachinspire-prompt-builder-db --command="SELECT name FROM sqlite_master WHERE type='table';"

echo ""
echo "🎉 Database setup completed successfully!"
echo ""
echo "Next steps:"
echo "1. Set your JWT secret: wrangler secret put JWT_SECRET"
echo "2. Deploy your application: wrangler pages deploy"
echo "3. Your database is ready for use in your Workers/Pages Functions"
echo ""
echo "Database binding: env.DB"
echo "Database ID: $DATABASE_ID"