-module(current_test).
-include_lib("eunit/include/eunit.hrl").

-export([request_error/3]).

-define(ENDPOINT, <<"localhost:8000">>).
-define(REGION, <<"us-east-1">>).

-define(TABLE, <<"current_test">>).
-define(TABLE_OTHER, <<"current_test_other">>).
-define(i2b(I), list_to_binary(integer_to_list(I))).

-define(NUMBER(I), {[{<<"N">>, ?i2b(I)}]}).

current_test_() ->
    {setup, fun setup/0, fun teardown/1,
     [
      {timeout, 120, ?_test(table_manipulation())},
      {timeout, 30,  ?_test(batch_get_write_item())},
      {timeout, 30,  ?_test(batch_get_unprocessed_items())},
      {timeout, 30,  ?_test(scan())},
      {timeout, 30,  ?_test(q())},
      {timeout, 30,  ?_test(get_put_update_delete())},
      {timeout, 30,  ?_test(retry_with_timeout())},
      {timeout, 30,  ?_test(timeout())},
      {timeout, 30,  ?_test(throttled())},
      {timeout, 30,  ?_test(non_json_error())},
      {timeout, 30,  ?_test(http_client())},
      {timeout, 30,  ?_test(raw_socket())},
      {timeout, 30,  ?_test(exp_error_tuple_backpressure())}
     ]}.


%%
%% DYNAMODB
%%


table_manipulation() ->
    current:delete_table({[{<<"TableName">>, ?TABLE}]}),
    ?assertEqual(ok, current:wait_for_delete(?TABLE, 5000)),

    ?assertMatch({error, {<<"ResourceNotFoundException">>, _}},
                 current:describe_table({[{<<"TableName">>, ?TABLE}]})),

    ok = create_table(?TABLE),

    ?assertEqual(ok, current:wait_for_active(?TABLE, 5000)),
    ?assertMatch({ok, _}, current:describe_table({[{<<"TableName">>, ?TABLE}]})),
    %% TODO: list tables and check membership
    ok.


batch_get_write_item() ->
    ok = create_table(?TABLE),
    ok = clear_table(?TABLE),
    ok = create_table(?TABLE_OTHER),
    ok = clear_table(?TABLE_OTHER),

    Keys = [{[{<<"range_key">>, ?NUMBER(rand:uniform(1000))},
              {<<"hash_key">>, ?NUMBER(rand:uniform(100000))}]}
            || _ <- lists:seq(1, 50)],

    WriteRequestItems = [{[{<<"PutRequest">>, {[{<<"Item">>, Key}]}}]}
                         || Key <- Keys],
    WriteRequest = {[{<<"RequestItems">>,
                      {[{?TABLE, WriteRequestItems},
                        {?TABLE_OTHER, WriteRequestItems}]}
                     }]},

    ?assertEqual(ok, current:batch_write_item(WriteRequest, [])),

    GetRequest = {[{<<"RequestItems">>,
                    {[{?TABLE, {[{<<"Keys">>, Keys}]}},
                      {?TABLE_OTHER, {[{<<"Keys">>, Keys}]}}
                     ]}
                   }]},

    {ok, [{?TABLE_OTHER, Table1}, {?TABLE, Table2}]} =
        current:batch_get_item(GetRequest),

    ?assertEqual(key_sort(Keys), key_sort(Table1)),
    ?assertEqual(key_sort(Keys), key_sort(Table2)).

batch_get_unprocessed_items() ->
    ok = create_table(?TABLE),
    ok = create_table(?TABLE_OTHER),

    Keys = [{[{<<"range_key">>, ?NUMBER(rand:uniform(1000))},
              {<<"hash_key">>, ?NUMBER(rand:uniform(100000))}]}
            || _ <- lists:seq(1, 150)],

    WriteRequestItems = [{[{<<"PutRequest">>, {[{<<"Item">>, Key}]}}]}
                         || Key <- Keys],
    WriteRequest = {[{<<"RequestItems">>,
                      {[{?TABLE, WriteRequestItems},
                        {?TABLE_OTHER, WriteRequestItems}]}
                     }]},

    ?assertEqual(ok, current:batch_write_item(WriteRequest, [])),


    {Keys1, Keys2} = lists:split(110, Keys),
    UnprocessedKeys = {[{?TABLE, {[{<<"Keys">>, Keys2}]}},
                        {?TABLE_OTHER, {[{<<"Keys">>, Keys2}]}}
                       ]},
    meck:new(current_http_client, [passthrough]),
    meck:expect(current_http_client, post, 4,
                meck:seq([fun (URL, Headers, Body, Opts) ->
                                  {ok, {{200, _}, ResponseHeaders, ResponseBody}} =
                                      meck:passthrough([URL, Headers, Body, Opts]),
                                  {Result} = jiffy:decode(ResponseBody),
                                  ?assertEqual(
                                     {[]}, proplists:get_value(<<"UnprocessedKeys">>, Result)),
                                  MockResult = lists:keystore(
                                                 <<"UnprocessedKeys">>, 1,
                                                 Result, {<<"UnprocessedKeys">>,
                                                          UnprocessedKeys}),
                                  {ok, {{200, <<"OK">>}, ResponseHeaders,
                                        jiffy:encode({MockResult})}}
                          end,
                          meck:passthrough()])),

    GetRequest = {[{<<"RequestItems">>,
                    {[{?TABLE, {[{<<"Keys">>, Keys1}]}},
                      {?TABLE_OTHER, {[{<<"Keys">>, Keys1}]}}
                     ]}
                   }]},

    {ok, [{?TABLE_OTHER, Table1}, {?TABLE, Table2}]} =
        current:batch_get_item(GetRequest, []),

    ?assertEqual(key_sort(Keys), key_sort(Table1)),
    ?assertEqual(key_sort(Keys), key_sort(Table2)),

    meck:unload(current_http_client).


scan() ->
    ok = create_table(?TABLE),
    ok = clear_table(?TABLE),

    RequestItems = [begin
                        {[{<<"PutRequest">>,
                           {[{<<"Item">>,
                              {[{<<"hash_key">>, {[{<<"N">>, <<"1">>}]}},
                                {<<"range_key">>, {[{<<"N">>, ?i2b(I)}]}},
                                {<<"attribute">>, {[{<<"S">>, <<"foo">>}]}}
                               ]}}]}
                          }]}
                    end || I <- lists:seq(1, 100)],
    Request = {[{<<"RequestItems">>,
                 {[{?TABLE, RequestItems}]}
                }]},

    ok = current:batch_write_item(Request, []),

    Q = {[{<<"TableName">>, ?TABLE}]},

    ?assertMatch({ok, L} when is_list(L), current:scan(Q, [])),

    %% Errors
    ErrorQ = {[{<<"TableName">>, <<"non-existing-table">>}]},
    ?assertMatch({error, {<<"ResourceNotFoundException">>, _}},
                 current:scan(ErrorQ, [])),

    %% Limit and pagging
    Q1 = {[{<<"TableName">>, ?TABLE},
          {<<"Limit">>, 80}]},
    {ok, LimitedItems1, LastEvaluatedKey1} = current:scan(Q1),
    ?assertEqual(80, length(LimitedItems1)),

    %% Pagging last page
    Q2 = {[{<<"TableName">>, ?TABLE},
           {<<"ExclusiveStartKey">>, LastEvaluatedKey1},
           {<<"Limit">>, 30}]},
    {ok, LimitedItems2} = current:scan(Q2),

    %% check for overlaps
    ?assertEqual(0, sets:size(sets:intersection(sets:from_list(LimitedItems1),
                                                sets:from_list(LimitedItems2)))),

    ?assertEqual(20, length(LimitedItems2)).


take_write_batch_test() ->
    ?assertEqual({[{<<"table1">>, [1, 2, 3]},
                   {<<"table2">>, [1, 2, 3]}],
                  []},
                 current:take_write_batch(
                   {[{<<"table1">>, [1, 2, 3]},
                     {<<"table2">>, [1, 2, 3]}]}, 25)),


    {Batch1, Rest1} = current:take_write_batch(
                      {[{<<"table1">>, lists:seq(1, 30)},
                        {<<"table2">>, lists:seq(1, 30)}]}, 25),
    ?assertEqual([{<<"table1">>, lists:seq(1, 25)}], Batch1),
    ?assertEqual([{<<"table1">>, lists:seq(26, 30)},
                  {<<"table2">>, lists:seq(1, 30)}], Rest1),


    {Batch2, Rest2} = current:take_write_batch({Rest1}, 25),
    ?assertEqual([{<<"table1">>, lists:seq(26, 30)},
                  {<<"table2">>, lists:seq(1, 20)}], Batch2),
    ?assertEqual([{<<"table2">>, lists:seq(21, 30)}], Rest2),

    {Batch3, Rest3} = current:take_write_batch({Rest2}, 25),
    ?assertEqual([{<<"table2">>, lists:seq(21, 30)}], Batch3),
    ?assertEqual([], Rest3).

take_get_batch_test() ->
    Spec = {[{<<"Keys">>, [1,2,3]},
             {<<"AttributesToGet">>, [<<"foo">>, <<"bar">>]},
             {<<"ConsistentRead">>, false}]},

    {Batch1, Rest1} = current:take_get_batch({[{<<"table1">>, Spec},
                                               {<<"table2">>, Spec}]}, 2),


    ?assertEqual([{<<"table1">>, {[{<<"Keys">>, [1, 2]},
                                   {<<"AttributesToGet">>, [<<"foo">>, <<"bar">>]},
                                   {<<"ConsistentRead">>, false}]}}],
                 Batch1),

    {Batch2, _Rest2} = current:take_get_batch({Rest1}, 2),
    ?assertEqual([{<<"table1">>, {[{<<"Keys">>, [3]},
                                   {<<"AttributesToGet">>, [<<"foo">>, <<"bar">>]},
                                   {<<"ConsistentRead">>, false}]}},
                  {<<"table2">>, {[{<<"Keys">>, [1]},
                                   {<<"AttributesToGet">>, [<<"foo">>, <<"bar">>]},
                                   {<<"ConsistentRead">>, false}]}}],
                 Batch2).




q() ->
    ok = create_table(?TABLE),
    ok = clear_table(?TABLE),

    Items = [{[{<<"range_key">>, {[{<<"N">>, ?i2b(I)}]}},
               {<<"hash_key">>, {[{<<"N">>, <<"1">>}]}}]}
             || I <- lists:seq(1, 100)],

    RequestItems = [begin
                        {[{<<"PutRequest">>, {[{<<"Item">>, Item}]}}]}
                    end || Item <- Items],
    Request = {[{<<"RequestItems">>, {[{?TABLE, RequestItems}]}}]},

    ok = current:batch_write_item(Request, []),

    Q = {[{<<"TableName">>, ?TABLE},
          {<<"KeyConditions">>,
           {[{<<"hash_key">>,
              {[{<<"AttributeValueList">>, [{[{<<"N">>, <<"1">>}]}]},
                {<<"ComparisonOperator">>, <<"EQ">>}]}}]}}]},

    {ok, ResultItems} = current:q(Q, []),

    ?assertEqual(key_sort(Items), key_sort(ResultItems)),

    %% Count
    CountQ = {[{<<"TableName">>, ?TABLE},
               {<<"KeyConditions">>,
                {[{<<"hash_key">>,
                   {[{<<"AttributeValueList">>, [{[{<<"N">>, <<"1">>}]}]},
                     {<<"ComparisonOperator">>, <<"EQ">>}]}}]}},
               {<<"Select">>, <<"COUNT">>}]},
    {ok, ResultCount} = current:q(CountQ, []),
    ?assertEqual(100, ResultCount),

    %% Errors
    ErrorQ = {[{<<"TableName">>, <<"non-existing-table">>},
               {<<"KeyConditions">>,
                {[{<<"hash_key">>,
                   {[{<<"AttributeValueList">>, [{[{<<"N">>, <<"1">>}]}]},
                     {<<"ComparisonOperator">>, <<"EQ">>}]}}]}}]},
    ?assertMatch({error, {<<"ResourceNotFoundException">>, _}},
                 current:q(ErrorQ, [])),

    %% Limit and pagging
    Q1 = {[{<<"TableName">>, ?TABLE},
           {<<"KeyConditions">>,
            {[{<<"hash_key">>,
               {[{<<"AttributeValueList">>, [{[{<<"N">>, <<"1">>}]}]},
                 {<<"ComparisonOperator">>, <<"EQ">>}]}}]}},
          {<<"Limit">>, 80}]},
    {ok, LimitedItems1, LastEvaluatedKey1} = current:q(Q1),
    ?assertEqual(80, length(LimitedItems1)),

    %% Pagging last page
    Q2 = {[{<<"TableName">>, ?TABLE},
          {<<"KeyConditions">>,
           {[{<<"hash_key">>,
              {[{<<"AttributeValueList">>, [{[{<<"N">>, <<"1">>}]}]},
                {<<"ComparisonOperator">>, <<"EQ">>}]}}]}},
           {<<"ExclusiveStartKey">>, LastEvaluatedKey1},
           {<<"Limit">>, 30}]},
    {ok, LimitedItems2} = current:q(Q2),

    %% check for overlaps
    ?assertEqual(0, sets:size(
                      sets:intersection(sets:from_list(LimitedItems1),
                                        sets:from_list(LimitedItems2)))),

    ?assertEqual(20, length(LimitedItems2)).


get_put_update_delete() ->
    ok = create_table(?TABLE),
    ok = clear_table(?TABLE),

    Key = {[{<<"hash_key">>, {[{<<"N">>, <<"1">>}]}},
            {<<"range_key">>, {[{<<"N">>, <<"1">>}]}}]},

    Item = {[{<<"attribute">>, {[{<<"SS">>, [<<"foo">>]}]}},
             {<<"range_key">>, {[{<<"N">>, <<"1">>}]}},
             {<<"hash_key">>, {[{<<"N">>, <<"1">>}]}}]},

    {ok, {NoItem}} = current:get_item({[{<<"TableName">>, ?TABLE},
                                        {<<"Key">>, Key}]}),
    ?assertNot(proplists:is_defined(<<"Item">>, NoItem)),


    ?assertMatch({ok, _}, current:put_item({[{<<"TableName">>, ?TABLE},
                                             {<<"Item">>, Item}]})),

    {ok, {WithItem}} = current:get_item({[{<<"TableName">>, ?TABLE},
                                        {<<"Key">>, Key}]}),
    {ActualItem} = proplists:get_value(<<"Item">>, WithItem),
    ?assertEqual(lists:sort(element(1, Item)), lists:sort(ActualItem)),

    {ok, _} = current:update_item(
                {[{<<"TableName">>, ?TABLE},
                  {<<"AttributeUpdates">>,
                   {[{<<"attribute">>, {[{<<"Action">>, <<"ADD">>},
                                         {<<"Value">>, {[{<<"SS">>, [<<"bar">>]}]}}
                                        ]}}]}},
                  {<<"Key">>, Key}]}),

    {ok, {WithUpdate}} = current:get_item({[{<<"TableName">>, ?TABLE},
                                             {<<"Key">>, Key}]}),
    {UpdatedItem} = proplists:get_value(<<"Item">>, WithUpdate),
    Attribute = proplists:get_value(<<"attribute">>, UpdatedItem),
    ?assertMatch({[{<<"SS">>, _Values}]}, Attribute),
    {[{<<"SS">>, Values}]} = Attribute,
    ?assertEqual([<<"bar">>, <<"foo">>], lists:sort(Values)),


    ?assertMatch({ok, _}, current:delete_item({[{<<"TableName">>, ?TABLE},
                                                {<<"Key">>, Key}]})),

    {ok, {NoItemAgain}} = current:get_item({[{<<"TableName">>, ?TABLE},
                                             {<<"Key">>, Key}]}),
    ?assertNot(proplists:is_defined(<<"Item">>, NoItemAgain)).


retry_with_timeout() ->
    meck:new(current_http_client, [passthrough]),
    meck:expect(current_http_client, post, fun (_, _, _, _) ->
                                                   {error, claim_timeout}
                                           end),
    ?assertEqual({error, {max_retries, claim_timeout}},
                 current:describe_table({[{<<"TableName">>, ?TABLE}]},
                                        [{retries, 3}])),

    meck:unload(current_http_client).

timeout() ->
    ?assertEqual({error, {max_retries, timeout}},
                 current:describe_table({[{<<"TableName">>, ?TABLE}]},
                                        [{call_timeout, 1}])).


throttled() ->
    ok = create_table(?TABLE),
    ok = clear_table(?TABLE),

    E = <<"com.amazonaws.dynamodb.v20120810#"
          "ProvisionedThroughputExceededException">>,

    ThrottledResponse = {ok, {{400, foo}, [],
                              jiffy:encode(
                                {[{'__type',  E},
                                  {message, <<"foobar">>}]})}},

    meck:new(current_http_client, [passthrough]),
    meck:expect(current_http_client, post, 4,
                meck_ret_spec:seq(
                  [ThrottledResponse,
                   ThrottledResponse,
                   meck_ret_spec:passthrough()])),


    Key = {[{<<"hash_key">>, ?NUMBER(1)},
            {<<"range_key">>, ?NUMBER(1)}]},

    WriteRequestItems = [{[{<<"PutRequest">>, {[{<<"Item">>, Key}]}}]}],

    WriteRequest = {[{<<"RequestItems">>,
                      {[{?TABLE, WriteRequestItems}]}}
                    ]},

    ?assertEqual(ok, current:batch_write_item(WriteRequest, [{retries, 3}])),

    meck:unload(current_http_client).

non_json_error() ->
    meck:new(current_http_client, [passthrough]),
    CurrentResponse = {ok, {{413, ""}, [], <<"not a json response!">>}},
    meck:expect(current_http_client, post, 4, CurrentResponse),

    Key = {[{<<"hash_key">>, ?NUMBER(1)},
            {<<"range_key">>, ?NUMBER(1)}]},
    Response = current:get_item({[{<<"TableName">>, ?TABLE},
                                  {<<"Key">>, Key}]}),

    ?assertEqual({error, {413, <<"not a json response!">>}},
                 Response),

    meck:unload(current_http_client).



%%
%% SIGNING
%%

key_derivation_test() ->
    application:set_env(current, secret_access_key,
                        <<"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY">>),
    application:set_env(current, region, <<"us-east-1">>),
    application:set_env(current, aws_host, <<"iam">>),
    Now = edatetime:datetime2ts({{2012, 2, 15}, {0, 0, 0}}),

    ?assertEqual(<<"f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d">>,
                 base16:encode(current:derived_key(Now))).

post_vanilla_test() ->
    application:set_env(current, region, <<"us-east-1">>),
    application:set_env(current, aws_host, <<"host">>),
    application:set_env(current, access_key, <<"AKIDEXAMPLE">>),
    application:set_env(current, secret_access_key,
                        <<"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY">>),

    Now = edatetime:datetime2ts({{2011, 9, 9}, {23, 36, 0}}),

    %% from post-vanilla.req
    Headers = [{<<"date">>, <<"Mon, 09 Sep 2011 23:36:00 GMT">>},
               {<<"host">>, <<"host.foo.com">>}],

    CanonicalRequest = current:canonical(Headers, ""),
    ?assertEqual(creq("post-vanilla"), iolist_to_binary(CanonicalRequest)),

    HashedCanonicalRequest = base16:encode(crypto:hash(sha256, CanonicalRequest)),

    ?assertEqual(sts("post-vanilla"),
                 iolist_to_binary(
                   current:string_to_sign(HashedCanonicalRequest, Now))),

    ?assertEqual(authz("post-vanilla"),
                 iolist_to_binary(
                   current:authorization(Headers, "", Now))).

http_client() ->
    ?assertEqual(ok, application:set_env(current, http_client, party)),
    ok = maybe_connect_party(),
    current:delete_table({[{<<"TableName">>, ?TABLE}]}),
    ?assertNotEqual({ok, lhttpc}, application:get_env(current, http_client)),
    ?assertEqual(ok, current:wait_for_delete(?TABLE, 5000)),

    ?assertEqual(ok, application:set_env(current, http_client, lhttpc)),
    current:delete_table({[{<<"TableName">>, ?TABLE}]}),
    ?assertNotEqual({ok, party}, application:get_env(current, http_client)),
    ?assertEqual(ok, current:wait_for_delete(?TABLE, 5000)),

    ok.

raw_socket() ->
    ?assertEqual(ok, application:set_env(current, http_client, lhttpc)),
    ?assertEqual({error,raw_socket_not_supported},
                 current:open_socket(?ENDPOINT, party_socket)),

    ?assertEqual(ok, application:set_env(current, http_client, party)),
    {Reply, Socket} = current:open_socket(?ENDPOINT, party_socket),
    ?assertEqual(ok, Reply),

    current:delete_table({[{<<"TableName">>, ?TABLE}]}),
    ?assertEqual(ok, current:wait_for_delete(?TABLE, 5000)),

    ?assertEqual(ok, current:close_socket(Socket, party_socket)),

    ok.

exp_error_tuple_backpressure() ->
    Reason = timeout,
    Retries = 3,
    Opts = [{retries, Retries}],

    ?assertEqual({error, {max_retries, Reason}},
                 current:apply_backpressure(some_op,
                                            some_body,
                                            Retries,
                                            start,
                                            Opts,
                                            Reason)),
    ok.

%%
%% HELPERS
%%

maybe_connect_party() ->
    current:connect(iolist_to_binary(["http://", ?ENDPOINT]), 2).

creq(Name) ->
    {ok, B} = file:read_file(
                filename:join(["test", "aws4_testsuite", Name ++ ".creq"])),
    binary:replace(B, <<"\r\n">>, <<"\n">>, [global]).

sts(Name) ->
    {ok, B} = file:read_file(
                filename:join(["test", "aws4_testsuite", Name ++ ".sts"])),
    binary:replace(B, <<"\r\n">>, <<"\n">>, [global]).


authz(Name) ->
    {ok, B} = file:read_file(
                filename:join(["test", "aws4_testsuite", Name ++ ".authz"])),
    binary:replace(B, <<"\r\n">>, <<"\n">>, [global]).

key_sort(L) ->
    lists:sort(normalize_key_order(L, [])).

normalize_key_order([], Acc) ->
    lists:reverse(Acc);
normalize_key_order([{H} | T], Acc) ->
    K1 = proplists:get_value(<<"hash_key">>, H),
    K2 = proplists:get_value(<<"range_key">>, H),
    normalize_key_order(T, [{[{<<"hash_key">>, K1}, {<<"range_key">>, K2}]} | Acc]).

setup() ->
    {ok, _} = application:ensure_all_started(current),

    %% Make travis-ci use different env/config we do not need valid
    %% credentials for CI since we are using local DynamDB
    Environment = case os:getenv("TRAVIS") of
                      "true" -> "aws_credentials.term.template";
                      false  -> "aws_credentials.term"
                  end,

    File = filename:join([code:priv_dir(current), Environment]),
    {ok, Cred} = file:consult(File),
    AccessKey = proplists:get_value(access_key, Cred),
    SecretAccessKey = proplists:get_value(secret_access_key, Cred),

    application:set_env(current, callback_mod, ?MODULE),
    application:set_env(current, endpoint, ?ENDPOINT),
    application:set_env(current, region, ?REGION),
    application:set_env(current, access_key, AccessKey),
    application:set_env(current, secret_access_key, SecretAccessKey),

    {ok, _} = application:ensure_all_started(current),

    maybe_connect_party(),

    ok.

teardown(_) ->
    application:stop(current).


create_table(Name) ->
    AttrDefs = [{[{<<"AttributeName">>, <<"hash_key">>},
                  {<<"AttributeType">>, <<"N">>}]},
                {[{<<"AttributeName">>, <<"range_key">>},
                  {<<"AttributeType">>, <<"N">>}]}],
    KeySchema = [{[{<<"AttributeName">>, <<"hash_key">>},
                   {<<"KeyType">>, <<"HASH">>}]},
                 {[{<<"AttributeName">>, <<"range_key">>},
                   {<<"KeyType">>, <<"RANGE">>}]}],

    R = {[{<<"AttributeDefinitions">>, AttrDefs},
          {<<"KeySchema">>, KeySchema},
          {<<"ProvisionedThroughput">>,
           {[{<<"ReadCapacityUnits">>, 10},
             {<<"WriteCapacityUnits">>, 5}]}},
          {<<"TableName">>, Name}]},

    case current:describe_table({[{<<"TableName">>, Name}]}) of
        {error, {<<"ResourceNotFoundException">>, _}} ->
            ?assertMatch({ok, _},
                         current:create_table(R, [{timeout, 5000}, {retries, 3}])),
            ok = current:wait_for_active(?TABLE, 5000);
        {error, {_Type, Reason}} ->
            error_logger:info_msg("~p~n", [Reason]);
        {ok, _} ->
            ok
    end.

clear_table(Name) ->
    case current:scan({[{<<"TableName">>, Name},
                        {<<"AttributesToGet">>, [<<"hash_key">>, <<"range_key">>]}]},
                      []) of
        {ok, []} ->
            ok;
        {ok, Items} ->
            RequestItems = [{[{<<"DeleteRequest">>,
                               {[{<<"Key">>, Item}]}}]} || Item <- Items],
            Request = {[{<<"RequestItems">>, {[{Name, RequestItems}]}}]},
            ok = current:batch_write_item(Request, []),
            clear_table(Name)
    end.

request_error(Operation, _Start, Reason) ->
    io:format("ERROR in ~p: ~p~n", [Operation, Reason]).
