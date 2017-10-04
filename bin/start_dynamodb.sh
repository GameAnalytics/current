#!/bin/bash

set -euo pipefail ; IFS=$'\t\n'

ddb_local="dynamodb_local/dynamodb_local_latest.zip"

echo '==> setup local dynamo (pre_hook)'


if ! [ -f "$ddb_local" ]; then
    mkdir -p dynamodb_local
    wget -nc http://dynamodb-local.s3-website-us-west-2.amazonaws.com/dynamodb_local_latest.zip -O dynamodb_local/dynamodb_local_latest.zip
    unzip -n dynamodb_local/dynamodb_local_latest.zip -d dynamodb_local
fi

if [ -f dynamodb.pid ]; then
	kill $(cat dynamodb.pid) || true
fi
nohup java -Djava.library.path=./dynamodb_local/DynamoDBLocal_lib -jar dynamodb_local/DynamoDBLocal.jar -inMemory > dynamodb.out 2> dynamodb.err < /dev/null &
echo $! > dynamodb.pid

while ! nc -z localhost 8000; do
    echo "DynamoDbLocal not started yet, trying again..."
    sleep 1
done

echo '==> local dynamo (started)'
exit 0
