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
      {timeout, 30, ?_test(batch_get_write_item())},
      {timeout, 30, ?_test(batch_get_unprocessed_items())},
      {timeout, 30, ?_test(scan())},
      {timeout, 30, ?_test(q())},
      {timeout, 30, ?_test(get_put_update_delete())},
      {timeout, 30, ?_test(retry_with_timeout())},
      {timeout, 30, ?_test(timeout())},
      {timeout, 30, ?_test(throttled())},
      {timeout, 30, ?_test(non_json_error())}
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

    Keys = [{[{<<"range_key">>, ?NUMBER(random:uniform(1000))},
              {<<"hash_key">>, ?NUMBER(random:uniform(100000))}]}
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

    ?assertEqual(lists:sort(Keys), lists:sort(Table1)),
    ?assertEqual(lists:sort(Keys), lists:sort(Table2)).


batch_get_unprocessed_items() ->
    ok = create_table(?TABLE),
    ok = create_table(?TABLE_OTHER),

    Keys = [{[{<<"range_key">>, ?NUMBER(random:uniform(1000))},
              {<<"hash_key">>, ?NUMBER(random:uniform(100000))}]}
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
    meck:new(party, [passthrough]),
    meck:expect(party, post, 4,
                meck:seq([fun (URL, Headers, Body, Opts) ->
                                  {ok, {{200, <<"OK">>}, ResponseHeaders, ResponseBody}} =
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

    ?assertEqual(lists:sort(Keys), lists:sort(Table1)),
    ?assertEqual(lists:sort(Keys), lists:sort(Table2)),

    ?assert(meck:validate(party)),
    ok = meck:unload(party).


scan() ->
    ok = create_table(?TABLE),
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

    Q = {[{<<"TableName">>, ?TABLE},
          {<<"Limit">>, 10}]},

    ?assertMatch({ok, L} when is_list(L), current:scan(Q, [])),

    %% Errors
    ErrorQ = {[{<<"TableName">>, <<"non-existing-table">>}]},
    ?assertMatch({error, {<<"ResourceNotFoundException">>, _}},
                 current:scan(ErrorQ, [])),

    %% Limit and pagging
    {ok, LimitedItems1, LastEvaluatedKey1} = current:scan(Q, [{max_items, 80}]),
    ?assertEqual(80, length(LimitedItems1)),

    %% Pagging last page
    Q1 = {[{<<"TableName">>, ?TABLE},
           {<<"ExclusiveStartKey">>, LastEvaluatedKey1},
           {<<"Limit">>, 10}]},
    {ok, LimitedItems2, LastEvaluatedKey2} = current:scan(Q1, [{max_items, 30}]),

    ?debugFmt("scan.part1=~p", [LimitedItems1]),
    ?debugFmt("scan.part2=~p", [LimitedItems2]),

    ?debugFmt("scan.resutls(30)=~p", [length(LimitedItems2)]),
    ?assertEqual(20, length(LimitedItems2)),
    ?assertEqual(undefined, LastEvaluatedKey2),

    %% check for overlaps
    ?assertEqual(0, sets:size(
                      sets:intersection(sets:from_list(LimitedItems1),
                                        sets:from_list(LimitedItems2)))).


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
                {<<"ComparisonOperator">>, <<"EQ">>}]}}]}},
          {<<"Limit">>, 10}]},

    {ok, ResultItems} = current:q(Q, []),

    ?assertEqual(lists:sort(Items), lists:sort(ResultItems)),

    %% Count
    CountQ = {[{<<"TableName">>, ?TABLE},
               {<<"KeyConditions">>,
                {[{<<"hash_key">>,
                   {[{<<"AttributeValueList">>, [{[{<<"N">>, <<"1">>}]}]},
                     {<<"ComparisonOperator">>, <<"EQ">>}]}}]}},
               {<<"Limit">>, 10},
               {<<"Select">>, <<"COUNT">>}]},
    {ok, ResultCount} = current:q(CountQ, []),
    ?assertEqual(100, ResultCount),

    %% Errors
    ErrorQ = {[{<<"TableName">>, <<"non-existing-table">>},
               {<<"KeyConditions">>,
                {[{<<"hash_key">>,
                   {[{<<"AttributeValueList">>, [{[{<<"N">>, <<"1">>}]}]},
                     {<<"ComparisonOperator">>, <<"EQ">>}]}}]}},
               {<<"Limit">>, 10}]},
    ?assertMatch({error, {<<"ResourceNotFoundException">>, _}},
                 current:q(ErrorQ, [])),

    %% Limit and pagging
    {ok, LimitedItems1, LastEvaluatedKey1} = current:q(Q, [{max_items, 80}]),
    ?assertEqual(80, length(LimitedItems1)),

    %% Pagging last page
    Q1 = {[{<<"TableName">>, ?TABLE},
          {<<"KeyConditions">>,
           {[{<<"hash_key">>,
              {[{<<"AttributeValueList">>, [{[{<<"N">>, <<"1">>}]}]},
                {<<"ComparisonOperator">>, <<"EQ">>}]}}]}},
           {<<"ExclusiveStartKey">>, LastEvaluatedKey1},
           {<<"Limit">>, 10}]},
    {ok, LimitedItems2, LastEvaluatedKey2} = current:q(Q1, [{max_items, 30}]),
    ?assertEqual(20, length(LimitedItems2)),
    ?assertEqual(undefined, LastEvaluatedKey2),

    %% check for overlaps
    ?assertEqual(0, sets:size(
                      sets:intersection(sets:from_list(LimitedItems1),
                                        sets:from_list(LimitedItems2)))).


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
    meck:new(party, [passthrough]),
    meck:expect(party, post, fun (_, _, _, _) ->
                                         {error, claim_timeout}
                                 end),

    ?assertEqual({error, max_retries},
                 current:describe_table({[{<<"TableName">>, ?TABLE}]},
                                        [{retries, 3}])),

    meck:unload(party).

timeout() ->
    ?assertEqual({error, max_retries},
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

    meck:new(party, [passthrough]),
    meck:expect(party, post, 4,
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

    meck:unload(party).

non_json_error() ->
    meck:new(party, [passthrough]),
    PartyResponse = {ok, {{413, ""}, [], <<"not a json response!">>}},
    meck:expect(party, post, 4, PartyResponse),

    Key = {[{<<"hash_key">>, ?NUMBER(1)},
            {<<"range_key">>, ?NUMBER(1)}]},
    Response = current:get_item({[{<<"TableName">>, ?TABLE},
                                  {<<"Key">>, Key}]}),

    ?assertEqual({error, {413, <<"not a json response!">>}},
                 Response),

    meck:unload(party).



%%
%% SIGNING
%%

key_derivation_test() ->
    application:set_env(current, secret_access_key,
                        <<"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY">>),
    application:set_env(current, region, <<"us-east-1">>),
    application:set_env(current, aws_host, <<"iam">>),
    Now = edatetime:datetime2ts({{2012, 2, 15}, {0, 0, 0}}),

    ?assertEqual("f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d",
                 string:to_lower(hmac:hexlify(current:derived_key(Now)))).

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

    HashedCanonicalRequest = string:to_lower(
                               hmac:hexlify(
                                 erlsha2:sha256(CanonicalRequest))),

    ?assertEqual(sts("post-vanilla"),
                 iolist_to_binary(
                   current:string_to_sign(HashedCanonicalRequest, Now))),

    ?assertEqual(authz("post-vanilla"),
                 iolist_to_binary(
                   current:authorization(Headers, "", Now))).



%%
%% HELPERS
%%

creq(Name) ->
    {ok, B} = file:read_file(
                filename:join(["../test", "aws4_testsuite", Name ++ ".creq"])),
    binary:replace(B, <<"\r\n">>, <<"\n">>, [global]).

sts(Name) ->
    {ok, B} = file:read_file(
                filename:join(["../test", "aws4_testsuite", Name ++ ".sts"])),
    binary:replace(B, <<"\r\n">>, <<"\n">>, [global]).


authz(Name) ->
    {ok, B} = file:read_file(
                filename:join(["../test", "aws4_testsuite", Name ++ ".authz"])),
    binary:replace(B, <<"\r\n">>, <<"\n">>, [global]).




setup() ->
    application:start(carpool),
    application:start(party),

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

    ok = party:connect(iolist_to_binary(["http://", ?ENDPOINT]), 2),

    application:start(current).

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
