#!/bin/bash
# Reset admin password - run this script to reset admin password

NEW_PASSWORD="${1:-Admin123!}"

echo "Generating password hash..."

# Generate argon2 hash
HASH=$(python3 -c "
import sys
sys.path.insert(0, '/home/me/Documents/SOCIS-AI-PT-main/backend')
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=['argon2'], deprecated='auto')
print(pwd_context.hash('$NEW_PASSWORD'))
" 2>/dev/null)

if [ -z "$HASH" ]; then
    echo "Error: Could not generate hash. Install passlib: pip install passlib argon2-cffi"
    exit 1
fi

echo "Hash: $HASH"
echo ""
echo "SQL to update password:"
echo "UPDATE users SET password_hash = '$HASH' WHERE username = 'admin';"
echo ""
echo "Run this SQL in postgres container:"
echo "  docker exec -i socis_postgres psql -U socis_admin -d socis_ai_pt -c \"UPDATE users SET password_hash = '$HASH' WHERE username = 'admin';\""