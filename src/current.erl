%% @doc: DynamoDB client
-module(current).
-compile(export_all).

do(Operation, Request, Timeout) ->
    Now = edatetime:now2ts(),
    Body = jiffy:encode(Request),

    URL = "http://dynamodb." ++ endpoint() ++ ".amazonaws.com/",
    Headers = [
               {"host", "dynamodb." ++ endpoint() ++ ".amazonaws.com"},
               {"content-type", "application/x-amz-json-1.0"},
               {"x-amz-date", binary_to_list(edatetime:iso8601(Now))},
               {"x-amz-target", target(Operation)}
              ],

    Signed = [{"Authorization", authorization(Headers, Body, Now)} | Headers],

    lhttpc:request(URL, "POST", Signed, Body, Timeout).


canonical(Headers, Body) ->
    string:join(
      ["POST",
       "/",
       "",
       [string:to_lower(K) ++ ":" ++ V ++ "\n" || {K, V} <- lists:sort(Headers)],
       string:join([string:to_lower(K) || {K, _} <- lists:sort(Headers)],
                   ";"),
       hexdigest(Body)],
      "\n").

string_to_sign(HashedCanonicalRequest, Now) ->
    ["AWS4-HMAC-SHA256", "\n",
     binary_to_list(edatetime:iso8601_basic(Now)), "\n",
     [ymd(Now), "/", endpoint(), "/", aws_host(), "/aws4_request"], "\n",
     HashedCanonicalRequest].


derived_key(Now) ->
    Secret = ["AWS4", secret_key()],
    Date = hmac:hmac256(Secret, ymd(Now)),
    Region = hmac:hmac256(Date, endpoint()),
    Service = hmac:hmac256(Region, aws_host()),
    hmac:hmac256(Service, "aws4_request").


signature(StringToSign, Now) ->
    string:to_lower(
      hmac:hexlify(
        hmac:hmac256(derived_key(Now),
                     StringToSign))).


authorization(Headers, Body, Now) ->
    CanonicalRequest = canonical(Headers, Body),

    HashedCanonicalRequest = string:to_lower(
                               hmac:hexlify(
                                 erlsha2:sha256(CanonicalRequest))),

    StringToSign = string_to_sign(HashedCanonicalRequest, Now),

    lists:flatten(
      ["AWS4-HMAC-SHA256 ",
       "Credential=", credential(Now), ", ",
       "SignedHeaders=", string:join([string:to_lower(K)
                                      || {K, _} <- lists:sort(Headers)],
                                     ";"), ", ",
       "Signature=", signature(StringToSign, Now)]).


credential(Now) ->
    [access_key(), "/", ymd(Now), "/", endpoint(), "/", aws_host(), "/aws4_request"].

hexdigest(Body) ->
    string:to_lower(hmac:hexlify(erlsha2:sha256(Body))).

target(list_tables) -> "DynamoDB_20120810.ListTables".


endpoint() ->
    {ok, Endpoint} = application:get_env(current, endpoint),
    Endpoint.

aws_host() ->
    application:get_env(current, aws_host, "dynamodb").

access_key() ->
    {ok, Access} = application:get_env(current, access_key),
    Access.

secret_key() ->
    {ok, Secret} = application:get_env(current, secret_access_key),
    Secret.

ymd(Now) ->
    {Y, M, D} = edatetime:ts2date(Now),
    io_lib:format("~4.10.0B~2.10.0B~2.10.0B", [Y, M, D]).

