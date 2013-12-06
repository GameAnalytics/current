-module(current_test).
-include_lib("eunit/include/eunit.hrl").

-define(TABLE, <<"current_test_table">>).
-define(i2b(I), list_to_binary(integer_to_list(I))).

-define(NUMBER(I), {[{<<"N">>, ?i2b(I)}]}).

current_test_() ->
    {setup, fun setup/0, fun teardown/1,
     [
      {timeout, 120, ?_test(table_manipulation())},
      {timeout, 10, ?_test(batch_get_write_item())},
      {timeout, 10, ?_test(scan())},
      {timeout, 20, ?_test(q())},
      {timeout, 20, ?_test(get_put_update_delete())},
      {timeout, 10, ?_test(retry_with_timeout())},
      {timeout, 10, ?_test(timeout())},
      {timeout, 10, ?_test(throttled())}
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
    ok = create_table(<<"current_test_other_table">>),

    Keys = [{[{<<"hash_key">>, ?NUMBER(random:uniform(100000))},
              {<<"range_key">>, ?NUMBER(random:uniform(1000))}]}
            || _ <- lists:seq(1, 130)],

    WriteRequestItems = [{[{<<"PutRequest">>, {[{<<"Item">>, Key}]}}]}
                         || Key <- Keys],
    WriteRequest = {[{<<"RequestItems">>,
                      {[{?TABLE, WriteRequestItems},
                        {<<"current_test_other_table">>, WriteRequestItems}]}
                     }]},

    ?assertEqual(ok, current:batch_write_item(WriteRequest, [])),

    GetRequest = {[{<<"RequestItems">>,
                    {[{?TABLE, {[{<<"Keys">>, Keys}]}},
                      {<<"current_test_other_table">>, {[{<<"Keys">>, Keys}]}}
                     ]}
                   }]},

    {ok, [{?TABLE, Table1}, {<<"current_test_other_table">>, Table2}]} =
        current:batch_get_item(GetRequest, []),

    ?assertEqual(lists:sort(Keys), lists:sort(Table1)),
    ?assertEqual(lists:sort(Keys), lists:sort(Table2)).




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

    Q = {[{<<"TableName">>, ?TABLE}]},

    ?assertMatch({ok, L} when is_list(L), current:scan(Q, [])).



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

    Items = [{[{<<"hash_key">>, {[{<<"N">>, <<"1">>}]}},
               {<<"range_key">>, {[{<<"N">>, ?i2b(I)}]}}]}
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
    ?assertEqual(lists:sort(Items), lists:sort(ResultItems)).



get_put_update_delete() ->
    ok = create_table(?TABLE),
    ok = clear_table(?TABLE),

    Key = {[{<<"hash_key">>, {[{<<"N">>, <<"1">>}]}},
            {<<"range_key">>, {[{<<"N">>, <<"1">>}]}}]},

    Item = {[{<<"range_key">>, {[{<<"N">>, <<"1">>}]}},
             {<<"hash_key">>, {[{<<"N">>, <<"1">>}]}},
             {<<"attribute">>, {[{<<"SS">>, [<<"foo">>]}]}}]},

    {ok, {NoItem}} = current:get_item({[{<<"TableName">>, ?TABLE},
                                        {<<"Key">>, Key}]}),
    ?assertNot(proplists:is_defined(<<"Item">>, NoItem)),


    ?assertMatch({ok, _}, current:put_item({[{<<"TableName">>, ?TABLE},
                                             {<<"Item">>, Item}]})),

    {ok, {WithItem}} = current:get_item({[{<<"TableName">>, ?TABLE},
                                        {<<"Key">>, Key}]}),
    ?assertEqual(Item, proplists:get_value(<<"Item">>, WithItem)),

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
    ?assertEqual({[{<<"SS">>, [<<"bar">>, <<"foo">>]}]},
                 proplists:get_value(<<"attribute">>, UpdatedItem)),


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
    application:set_env(current, endpoint, <<"us-east-1">>),
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
    application:start(asn1),
    application:start(crypto),
    application:start(public_key),
    application:start(ssl),
    application:start(carpool),
    application:start(party),

    File = filename:join([code:priv_dir(current), "aws_credentials.term"]),
    {ok, Cred} = file:consult(File),
    AccessKey = proplists:get_value(access_key, Cred),
    SecretAccessKey = proplists:get_value(secret_access_key, Cred),

    application:set_env(current, endpoint, <<"us-east-1">>),
    application:set_env(current, access_key, AccessKey),
    application:set_env(current, secret_access_key, SecretAccessKey),
    application:set_env(current, callback_mod, current),

    ok = party:connect(<<"http://dynamodb.us-east-1.amazonaws.com">>, 2),

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
        {error, {Type, Reason}} ->
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
            Request = {[{<<"RequestItems">>,
                         {[{Name, RequestItems}]}},
                        {<<"AttributesToGet">>, [<<"hash_key">>, <<"range_key">>]}
                       ]},
            ok = current:batch_write_item(Request, [])
    end.
