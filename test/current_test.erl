-module(current_test).
-include_lib("eunit/include/eunit.hrl").

-define(TABLE, <<"table">>).
-define(i2b(I), list_to_binary(integer_to_list(I))).

current_test_() ->
    {setup, fun setup/0, fun teardown/1,
     [
      %% {timeout, 60, ?_test(table_manipulation())},
      ?_test(batch_write_item())
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


batch_write_item() ->
    ok = create_table(?TABLE),
    ok = create_table(<<"other_table">>),


    RequestItems = [begin
                        {[{<<"PutRequest">>,
                           {[{<<"Item">>,
                              {[{<<"hash_key">>, {[{<<"N">>,
                                                    ?i2b(random:uniform(100000))}]}},
                                {<<"range_key">>, {[{<<"N">>,
                                                     ?i2b(random:uniform(1000))}]}}
                               ]}}]}
                          }]}
                    end || _ <- lists:seq(1, 30)],
    Request = {[{<<"RequestItems">>,
                 {[{?TABLE, RequestItems},
                  {<<"other_table">>, RequestItems}]}
                }]},

    ?assertEqual(ok, current:batch_write_item(Request, [])).




%% take_write_batch_test() ->
%%     ?assertEqual({[{<<"table1">>, lists:seq(1, 25)}],
%%                   [{<<"table1">>, lists:seq(26, 30)},
%%                    {<<"table2">>, lists:seq(1, 30)}]},
%%                  current:take_write_batch(
%%                    {[{<<"RequestItems">>,
%%                       {[{<<"table1">>, lists:seq(1, 30)},
%%                         {<<"table2">>, lists:seq(1, 30)}]}}]})),

%%     ?assertEqual({[{<<"table1">>, [1, 2, 3]},
%%                    {<<"table2">>, [1, 2, 3]}],
%%                   []},
%%                  current:take_write_batch(
%%                    {[{<<"RequestItems">>,
%%                       {[{<<"table1">>, [1, 2, 3]},
%%                         {<<"table2">>, [1, 2, 3]}]}}]})).




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
             {<<"WriteCapacityUnits">>, 1}]}},
          {<<"TableName">>, Name}]},

    case current:describe_table({[{<<"TableName">>, Name}]}) of
        {error, {<<"ResourceNotFoundException">>, _}} ->
            ?assertMatch({ok, _},
                         current:create_table(R, [{timeout, 5000}, {retries, 3}])),
            ok = current:wait_for_active(?TABLE, 5000);
        {ok, _} ->
            ok
    end.

