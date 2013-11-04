-module(current_test).
-include_lib("eunit/include/eunit.hrl").

current_test_() ->
    {setup, fun setup/0, fun teardown/1,
     [
      ?_test(list_tables())
     ]}.


list_tables() ->
    Response = current:do(list_tables, {[{<<"Limit">>, 10}]}, 5000),

    error_logger:info_msg("~p~n", [Response]).



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



%% request(Name) ->
%%     {ok, B} = file:read_file(filename:join(["../test", "aws4_testsuite", Name])),
%%     [RequestLine | Rest] = string:tokens(binary_to_list(B), "\r\n"),

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





