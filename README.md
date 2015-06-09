# DynamoDB client for Erlang

[![Build Status](https://travis-ci.org/GameAnalytics/current.svg?branch=master)](https://travis-ci.org/GameAnalytics/current)

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

## Dependencies
* Erlang (>= R15)
* [rebar][]
* [Java JRE][] (for testing only)
* [screen][] (for testing only)


## Usage

Fetch and compile all application dependencies:
```bash
$ rebar get compile
```

Example usage:
```erlang
1> application:ensure_all_started(current).
{ok,[party,current]}
2> current:connect(<<"http://dynamodb.us-east-1.amazonaws.com">>, 2).
ok
3> application:set_env(current, region, <<"us-east-1">>).
ok
4> application:set_env(current, access_key, <<"foo">>).
ok
5> application:set_env(current, secret_access_key, <<"bar">>).
ok

6> GetRequest = {[{<<"TableName">>, <<"current_test_table">>}, {<<"Key">>, {[{<<"hash_key">>, {[{<<"N">>, <<"1">>}]}}, {<<"range_key">>, {[{<<"N">>, <<"1">>}]}}]}}]}.
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

## Instrumentation

Current will call functions in the module specified in the
`callback_mod` environment variable. At the moment, you need to
implement two functions: `request_complete/3` and `request_error/3`,
see `src/current_callback.erl`.

```erlang
request_complete(Operation, StartTimestamp, ConsumedCapacity) ->
    statman_histogram:record_value({ddb, Operation}, StartTimestamp),
    ok.
```

All calls to DynamoDB will have the `ReturnConsumedCapacity` value set
to ```TOTAL``` by default. When DynamoDB returns the
`ConsumedCapacity`, current will forward it to your callback
module. Keep in mind that for batch requests it is a list containing
capacity for one or more tables.

## Configurable HTTP client
You can use either [`party`][] or [`lhttpc`][] HTTP client. Both clients
favor frequent calls to limited number of endpoints.

```erlang
ok = application:set_env(current, http_client, lhttpc).
```

Example of party raw sockett:
```erlang
ok = application:set_env(current, http_client, party).
{ok, Socket} = current:open_socket(<<"http://dynamodb.us-east-1.amazonaws.com">>, raw).
ok = proplists:set_value(current, party_socket, Socket).
ok = current:close_socket(Socket, raw).

```


## Testing

If you provide AWS credentials in `priv/aws_credentials.term` (see
`priv/aws_credentials_term.template`), you can run the test
suite. Tables will be created under your account.

To run all tests use `rebar eunit`


[jiffy]: https://github.com/davisp/jiffy
[party]: https://github.com/knutin/party
[lhttpc]: https://github.com/ferd/lhttpc
[DynamoDB documentation]: http://docs.aws.amazon.com/amazondynamodb/latest/APIReference/Welcome.html
[rebar]: https://github.com/rebar/rebar
[Java JRE]: http://java.com/en/
[screen]: https://www.gnu.org/software/screen/
[party]: https://github.com/GameAnalytics/party.git
[lhttpc]: https://github.com/ferd/lhttpc.git
