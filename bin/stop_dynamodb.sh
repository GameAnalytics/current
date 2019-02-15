#!/bin/bash
if [ -f dynamodb_local/dynamodb.pid ]; then
	kill $(cat dynamodb_local/dynamodb.pid) || true
	echo '==> local dynamo (stopped)'
fi
exit 0
