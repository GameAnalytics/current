#!/bin/bash
set -euo pipefail ; IFS=$'\t\n'

kill $(cat dynamodb.pid) || true
java -Djava.library.path=./dynamodb_local/DynamoDBLocal_lib -jar dynamodb_local/DynamoDBLocal.jar -inMemory &
echo $! > dynamodb.pid
sleep 1
echo '==> local dynamo (started)'
exit 0
