# DynamoDB client for Erlang

Current is an Erlang client for Amazons DynamoDB service. It exposes
the raw JSON API described in the [DynamoDB documentation], taking
input and giving output in terms compatible with [jiffy][]. Current
can also retry requests when appropriate, for example when you're
throttled due using all your provisioned throughput or using all
available socket connections to DynamoDB.

At the moment, current uses the experimental HTTP client [party][]
which tries to do away with the single process bottleneck found in
[lhttpc][]. Although it's used in production at Game Analytics without
any problems found, it might not be ready for prime time just yet.

## Usage

```erlang

1> application:ensure_all_started(current).
{ok,[party,current]}
2> party:connect(<<"http://dynamodb.us-east-1.amazonaws.com">>, 2).
ok
3> application:set_env(current, endpoint, <<"us-east-1">>).
ok
4> application:set_env(current, access_key, <<"foo">>).
ok
5> application:set_env(current, secret_access_key, <<"bar">>).
ok
6> application:set_env(current, callback_mod, current).
ok

7> GetRequest = {[{<<"TableName">>, <<"current_test_table">>}, {<<"Key">>, {[{<<"hash_key">>, {[{<<"N">>, <<"1">>}]}}, {<<"range_key">>, {[{<<"N">>, <<"1">>}]}}]}}]}.
{[{<<"TableName">>,<<"current_test_table">>},
  {<<"Key">>,
   {[{<<"hash_key">>,{[{<<"N">>,<<"1">>}]}},
     {<<"range_key">>,{[{<<"N">>,<<"1">>}]}}]}}]}

7> current:get_item(GetRequest).
{ok,{[{<<"ConsumedCapacity">>,
       {[{<<"CapacityUnits">>,0.5},
         {<<"TableName">>,<<"current_test_table">>}]}},
      {<<"Item">>,
       {[{<<"hash_key">>,{[{<<"N">>,<<"1">>}]}},
         {<<"range_key">>,{[{<<"N">>,<<"1">>}]}}]}}]}}
```

With the new maps datastructure life will be great.

## Testing

If you provide AWS credentials in `priv/aws_credentials.term` (see
`priv/aws_credentials_term.template`), you can run the test
suite. Tables will be created under your account.


[jiffy]: https://github.com/davisp/jiffy
[party]: https://github.com/knutin/party
[lhttpc]: https://github.com/ferd/lhttpc
[DynamoDB documentation]: http://docs.aws.amazon.com/amazondynamodb/latest/APIReference/Welcome.html
