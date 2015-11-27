#!/bin/bash
kill $(cat dynamodb.pid) || true
echo '==> local dynamo (stopped)'
exit 0
