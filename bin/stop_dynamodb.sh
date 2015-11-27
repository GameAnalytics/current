#!/bin/bash
if [ -f dynamodb.pid ]; then
	kill $(cat dynamodb.pid) || true
	echo '==> local dynamo (stopped)'
fi
exit 0
