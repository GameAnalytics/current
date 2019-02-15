#!/bin/bash

set -euo pipefail ; IFS=$'\t\n'

ddb_local="dynamodb_local/dynamodb_local_latest.zip"

echo '==> setup local dynamo (pre_hook)'


if ! [ -f "$ddb_local" ]; then
    mkdir -p dynamodb_local
    wget -q http://dynamodb-local.s3-website-us-west-2.amazonaws.com/dynamodb_local_latest.zip -O dynamodb_local/dynamodb_local_latest.zip
    unzip -n -q dynamodb_local/dynamodb_local_latest.zip -d dynamodb_local
fi

if [ -f dynamodb_local/dynamodb.pid ]; then
	kill $(cat dynamodb_local/dynamodb.pid) || true
fi
nohup java -Djava.library.path=./dynamodb_local/DynamoDBLocal_lib -jar dynamodb_local/DynamoDBLocal.jar -inMemory > dynamodb_local/dynamodb.out 2> dynamodb_local/dynamodb.err < /dev/null &
echo $! > dynamodb_local/dynamodb.pid

while ! nc -z localhost 8000; do
    echo "DynamoDbLocal not started yet, trying again..."
    sleep 1
done

echo '==> local dynamo (started)'
exit 0
