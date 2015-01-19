#!/bin/bash
echo '==> local dynamo (pre_hook)'
mkdir -p dynamodb_local
wget -nc http://dynamodb-local.s3-website-us-west-2.amazonaws.com/dynamodb_local_latest.zip -O dynamodb_local/dynamodb_local_latest.zip
unzip -n dynamodb_local/dynamodb_local_latest.zip -d dynamodb_local
echo '==> local dynamo (pre_hook) [done]'
exit 0
