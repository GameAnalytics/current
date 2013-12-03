-module(current_test).
-include_lib("eunit/include/eunit.hrl").

-define(TABLE, <<"current_test_table">>).
-define(i2b(I), list_to_binary(integer_to_list(I))).

-define(NUMBER(I), {[{<<"N">>, ?i2b(I)}]}).

current_test_() ->
    {setup, fun setup/0, fun teardown/1,
     [
      %% {timeout, 120, ?_test(table_manipulation())},
      ?_test(batch_get_write_item())
      %% ?_test(scan()),
      %% ?_test(q()),
      %% ?_test(get_put_update_delete()),
      %% ?_test(retry_with_timeout())
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
    %%ok = create_table(?TABLE),
    %%ok = create_table(<<"current_test_other_table">>),

    Keys = [{[{<<"hash_key">>, ?NUMBER(random:uniform(100000))},
              {<<"range_key">>, ?NUMBER(random:uniform(1000))}]}
            || _ <- lists:seq(1, 120)],

    WriteRequestItems = [{[{<<"PutRequest">>, {[{<<"Item">>, Key}]}}]}
                         || Key <- Keys],
    WriteRequest = {[{<<"RequestItems">>,
                      {[{?TABLE, WriteRequestItems},
                        {<<"current_test_other_table">>, WriteRequestItems}]}
                     }]},

    ?assertEqual(ok, current:batch_write_item(WriteRequest, [])),

    %% ReadRequestItems = [{[{<<"Keys">>, Keys}]}],

    %% GetRequest = {[{<<"RequestItems">>,
    %%                 {[{?TABLE, ReadRequestItems},
    %%                   {<<"current_test_other_table">>, ReadRequestItems}]}}]},

    %% error_logger:info_msg("~p~n", [current:batch_get_item(GetRequest, [])]).
    ok.



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



take_batch_test() ->
    ?assertEqual({[{<<"table1">>, lists:seq(1, 25)}],
                  [{<<"table1">>, lists:seq(26, 30)},
                   {<<"table2">>, lists:seq(1, 30)}]},
                 current:take_batch(
                   {[{<<"table1">>, lists:seq(1, 30)},
                     {<<"table2">>, lists:seq(1, 30)}]}, 25)),

    ?assertEqual({[{<<"table1">>, [1, 2, 3]},
                   {<<"table2">>, [1, 2, 3]}],
                  []},
                 current:take_batch(
                   {[{<<"table1">>, [1, 2, 3]},
                     {<<"table2">>, [1, 2, 3]}]}, 25)).



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
    ok = create_table(?TABLE),
    ok = clear_table(?TABLE),

    meck:new(lhttpc, [passthrough]),
    meck:expect(lhttpc, request, fun (_, _, _, _, _) ->
                                         timer:sleep(100),
                                         {error, timeout}
                                 end),

    Start = os:timestamp(),
    ?assertEqual({error, max_retries},
                 current:describe_table({[{<<"TableName">>, ?TABLE}]},
                                        [{timeout, 300}, {retries, 10}])),
    ?assert(timer:now_diff(os:timestamp(), Start) / 1000 > 300),
    ?assert(timer:now_diff(os:timestamp(), Start) / 1000 < 600),

    meck:unload(lhttpc).



%%
%% SIGNING
%%

key_derivation_test() ->
    application:set_env(current, secret_access_key,
                        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
    application:set_env(current, region, "us-east-1"),
    application:set_env(current, aws_host, "iam"),
    Now = edatetime:datetime2ts({{2012, 2, 15}, {0, 0, 0}}),

    ?assertEqual("f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d",
                 string:to_lower(hmac:hexlify(current:derived_key(Now)))).

post_vanilla_test() ->
    application:set_env(current, endpoint, "us-east-1"),
    application:set_env(current, aws_host, "host"),
    application:set_env(current, access_key, "AKIDEXAMPLE"),
    application:set_env(current, secret_access_key,
                        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),

    Now = edatetime:datetime2ts({{2011, 9, 9}, {23, 36, 0}}),

    %% from post-vanilla.req
    Headers = [{"date", "Mon, 09 Sep 2011 23:36:00 GMT"},
               {"host", "host.foo.com"}],

    CanonicalRequest = current:canonical(Headers, ""),
    ?assertEqual(creq("post-vanilla"), lists:flatten(CanonicalRequest)),

    HashedCanonicalRequest = string:to_lower(
                               hmac:hexlify(
                                 erlsha2:sha256(CanonicalRequest))),

    ?assertEqual(sts("post-vanilla"),
                 lists:flatten(
                   current:string_to_sign(HashedCanonicalRequest, Now))),

    ?assertEqual(authz("post-vanilla"),
                 lists:flatten(
                   current:authorization(Headers, "", Now))).



%%
%% HELPERS
%%

creq(Name) ->
    {ok, B} = file:read_file(
                filename:join(["../test", "aws4_testsuite", Name ++ ".creq"])),
    binary_to_list(binary:replace(B, <<"\r\n">>, <<"\n">>, [global])).

sts(Name) ->
    {ok, B} = file:read_file(
                filename:join(["../test", "aws4_testsuite", Name ++ ".sts"])),
    binary_to_list(binary:replace(B, <<"\r\n">>, <<"\n">>, [global])).


authz(Name) ->
    {ok, B} = file:read_file(
                filename:join(["../test", "aws4_testsuite", Name ++ ".authz"])),
    binary_to_list(binary:replace(B, <<"\r\n">>, <<"\n">>, [global])).




setup() ->
    application:start(asn1),
    application:start(crypto),
    application:start(public_key),
    application:start(ssl),
    application:start(lhttpc),

    File = filename:join([code:priv_dir(current), "aws_credentials.term"]),
    {ok, Cred} = file:consult(File),
    AccessKey = proplists:get_value(access_key, Cred),
    SecretAccessKey = proplists:get_value(secret_access_key, Cred),

    application:set_env(current, endpoint, "us-east-1"),
    application:set_env(current, access_key, AccessKey),
    application:set_env(current, secret_access_key, SecretAccessKey),
    application:set_env(current, callback_mod, current),
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
