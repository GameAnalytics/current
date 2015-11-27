#!/bin/bash
set -euo pipefail ; IFS=$'\t\n'

pkill -9 -f DynamoDBLocal || true
screen -dm -S dynamodb_local java -Djava.library.path=./dynamodb_local/DynamoDBLocal_lib -jar dynamodb_local/DynamoDBLocal.jar -inMemory
sleep 1
echo '==> local dynamo (started)'
exit 0
