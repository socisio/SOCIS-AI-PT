#!/bin/bash
# Delete admin user so it gets recreated on next startup
# Usage: bash delete-admin.sh

echo "Deleting admin user from database..."

docker exec socis_postgres psql -U socis_admin -d socis_ai_pt -c "DELETE FROM users WHERE username = 'admin';" 2>/dev/null || \
docker exec postgres psql -U socis_admin -d socis_ai_pt -c "DELETE FROM users WHERE username = 'admin';" 2>/dev/null || \
echo "Cannot run docker command. Use this SQL manually:"
echo "  DELETE FROM users WHERE username = 'admin';"

echo "Done. Restart backend to recreate admin with password Admin123!"