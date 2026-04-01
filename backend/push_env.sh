#!/bin/bash
# push-secrets.sh — reads a .env file, converts to JSON, pushes to AWS Secrets Manager
#
# Usage:
#   ./push-secrets.sh resume-tailor/backend ../resume-tailor/backend/.env
#   ./push-secrets.sh job-tracker/api      ../job-tracker/api/.env
#   ./push-secrets.sh job-tracker/pipeline ../job-tracker/pipeline/.env

SECRET_NAME="$1"
ENV_FILE="$2"
REGION="ap-south-1"

if [ -z "$SECRET_NAME" ] || [ -z "$ENV_FILE" ]; then
  echo "Usage: $0 <secret-name> <env-file-path>"
  echo "Example: $0 resume-tailor/backend ../resume-tailor/backend/.env"
  exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
  echo "Error: $ENV_FILE not found"
  exit 1
fi

# Convert .env to JSON (skip comments and empty lines)
JSON=$(python3 -c "
import json, sys
secrets = {}
for line in open('$ENV_FILE'):
    line = line.strip()
    if not line or line.startswith('#') or '=' not in line:
        continue
    key, _, value = line.partition('=')
    key = key.strip()
    value = value.strip()
    # Remove surrounding quotes if present
    if (value.startswith('\"') and value.endswith('\"')) or \
       (value.startswith(\"'\") and value.endswith(\"'\")):
        value = value[1:-1]
    if value:  # Skip empty values
        secrets[key] = value
print(json.dumps(secrets))
")

echo "Parsed $(echo $JSON | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))') secrets from $ENV_FILE"
echo ""

# Check if secret already exists
if aws secretsmanager describe-secret --secret-id "$SECRET_NAME" --region "$REGION" > /dev/null 2>&1; then
  echo "Secret '$SECRET_NAME' already exists. Updating..."
  aws secretsmanager put-secret-value \
    --secret-id "$SECRET_NAME" \
    --secret-string "$JSON" \
    --region "$REGION"
  echo "Updated: $SECRET_NAME"
else
  echo "Creating new secret: $SECRET_NAME"
  aws secretsmanager create-secret \
    --name "$SECRET_NAME" \
    --description "Secrets for $SECRET_NAME" \
    --secret-string "$JSON" \
    --region "$REGION"
  echo "Created: $SECRET_NAME"
fi