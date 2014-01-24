%% @doc: DynamoDB client
-module(current).

%% DynamoDB API
-export([
         batch_get_item/1,
         batch_get_item/2,
         batch_write_item/1,
         batch_write_item/2,
         create_table/1,
         create_table/2,
         delete_item/1,
         delete_item/2,
         delete_table/1,
         delete_table/2,
         describe_table/1,
         describe_table/2,
         get_item/1,
         get_item/2,
         list_tables/1,
         list_tables/2,
         put_item/1,
         put_item/2,
         q/1,
         q/2,
         scan/1,
         scan/2,
         update_item/1,
         update_item/2,
         update_table/1,
         update_table/2
        ]).


-export([wait_for_delete/2, wait_for_active/2]).


%% Exported for testing
-export([take_get_batch/2, take_write_batch/2]).
-export([request_complete/3, request_error/3]).
-export([derived_key/1, canonical/2, string_to_sign/2, authorization/3]).

%%
%% LOW-LEVEL API
%%


batch_get_item(Request)         -> do_batch_get_item(Request, []).
batch_get_item(Request, Opts)   -> do_batch_get_item(Request, Opts).
batch_write_item(Request)       -> do_batch_write_item(Request, []).
batch_write_item(Request, Opts) -> do_batch_write_item(Request, Opts).
create_table(Request)           -> retry(create_table, Request, []).
create_table(Request, Opts)     -> retry(create_table, Request, Opts).
delete_item(Request)            -> retry(delete_item, Request, []).
delete_item(Request, Opts)      -> retry(delete_item, Request, Opts).
delete_table(Request)           -> retry(delete_table, Request, []).
delete_table(Request, Opts)     -> retry(delete_table, Request, Opts).
describe_table(Request)         -> retry(describe_table, Request, []).
describe_table(Request, Opts)   -> retry(describe_table, Request, Opts).
get_item(Request)               -> retry(get_item, Request, []).
get_item(Request, Opts)         -> retry(get_item, Request, Opts).
list_tables(Request)            -> retry(list_tables, Request, []).
list_tables(Request, Opts)      -> retry(list_tables, Request, Opts).
put_item(Request)               -> retry(put_item, Request, []).
put_item(Request, Opts)         -> retry(put_item, Request, Opts).
q(Request)                      -> do_query(Request, []).
q(Request, Opts)                -> do_query(Request, Opts).
scan(Request)                   -> do_scan(Request, []).
scan(Request, Opts)             -> do_scan(Request, Opts).
update_item(Request)            -> retry(update_item, Request, []).
update_item(Request, Opts)      -> retry(update_item, Request, Opts).
update_table(Request)           -> retry(update_table, Request, []).
update_table(Request, Opts)     -> retry(update_table, Request, Opts).



%%
%% HIGH-LEVEL HELPERS
%%

wait_for_active(Table, Timeout) ->
    case describe_table({[{<<"TableName">>, Table}]}, [{timeout, Timeout}]) of
        {ok, {[{<<"Table">>, {Description}}]}} ->
            case proplists:get_value(<<"TableStatus">>, Description) of
                <<"ACTIVE">> ->
                    ok;
                <<"DELETING">> ->
                    {error, deleting};
                _Other ->
                    wait_for_active(Table, Timeout)
            end;
        {error, {<<"ResourceNotFoundException">>, _}} ->
            {error, not_found}
    end.


wait_for_delete(Table, Timeout) ->
    case describe_table({[{<<"TableName">>, Table}]}, [{timeout, Timeout}]) of
        {ok, {[{<<"Table">>, {Description}}]}} ->
            case proplists:get_value(<<"TableStatus">>, Description) of
                <<"DELETING">> ->
                    wait_for_delete(Table, Timeout);
                Other ->
                    {error, {unexpected_state, Other}}
            end;
        {error, {<<"ResourceNotFoundException">>, _}} ->
            ok
    end.


%% ============================================================================
%% IMPLEMENTATION
%% ============================================================================




%%
%% BATCH GET AND WRITE
%%


do_batch_get_item(Request, Opts) ->
    case do_batch_get_item(Request, [], Opts) of
        {error, Reason} ->
            {error, Reason};
        Result ->
            {ok, lists:reverse(Result)}
    end.


do_batch_get_item({Request}, Acc, Opts) ->
    {value, {<<"RequestItems">>, RequestItems}, CleanRequest} =
        lists:keytake(<<"RequestItems">>, 1, Request),

    case take_get_batch(RequestItems, 100) of
        {[], []} ->
            Acc;
        {Batch, Rest} ->
            BatchRequest = {[{<<"RequestItems">>, {Batch}} | CleanRequest]},

            case retry(batch_get_item, BatchRequest, Opts) of
                {ok, {Result}} ->
                    {Responses} = proplists:get_value(<<"Responses">>, Result),
                    NewAcc = orddict:merge(fun (_, Left, Right) -> Left ++ Right end,
                                           orddict:from_list(Responses),
                                           orddict:from_list(Acc)),

                    {Unprocessed} = proplists:get_value(<<"UnprocessedKeys">>, Result),
                    Remaining = orddict:merge(
                                  fun (_, {Left}, {Right}) ->
                                          LeftKeys = proplists:get_value(
                                                       <<"Keys">>, Left),
                                          RightKeys = proplists:get_value(
                                                        <<"Keys">>, Right),
                                          {lists:keystore(
                                             <<"Keys">>, 1, Right,
                                             {<<"Keys">>, LeftKeys ++ RightKeys})}
                                  end,
                                  orddict:from_list(Unprocessed),
                                  orddict:from_list(Rest)),
                    do_batch_get_item({[{<<"RequestItems">>, {Remaining}}]},
                                      NewAcc, Opts);
                {error, _} = Error ->
                    Error
            end
    end.


do_batch_write_item({Request}, Opts) ->
    {value, {<<"RequestItems">>, RequestItems}, CleanRequest} =
        lists:keytake(<<"RequestItems">>, 1, Request),

    case take_write_batch(RequestItems, 25) of
        {[], []} ->
            ok;
        {Batch, Rest} ->
            BatchRequest = {[{<<"RequestItems">>, {Batch}} | CleanRequest]},

            case retry(batch_write_item, BatchRequest, Opts) of
                {ok, {Result}} ->
                    {Unprocessed} = proplists:get_value(<<"UnprocessedItems">>, Result),
                    case Unprocessed =:= [] andalso Rest =:= [] of
                        true ->
                            ok;
                        false ->
                            Remaining = orddict:merge(fun (_, Left, Right) ->
                                                              Left ++ Right
                                                      end,
                                                      orddict:from_list(Unprocessed),
                                                      orddict:from_list(Rest)),

                            do_batch_write_item({[{<<"RequestItems">>, {Remaining}}]}, Opts)
                    end;
                {error, _} = Error ->
                    Error
            end
    end.


take_get_batch({RequestItems}, MaxItems) ->
    do_take_get_batch(RequestItems, 0, MaxItems, []).

do_take_get_batch(Remaining, MaxItems, MaxItems, Acc) ->
    {lists:reverse(Acc), Remaining};

do_take_get_batch([], _, _, Acc) ->
    {lists:reverse(Acc), []};

do_take_get_batch([{Table, {Spec}} | RemainingTables], N, MaxItems, Acc) ->
    case lists:keyfind(<<"Keys">>, 1, Spec) of
        {<<"Keys">>, []} ->
            do_take_get_batch(RemainingTables, N, MaxItems, Acc);
        {<<"Keys">>, Keys} ->
            {Batch, Rest} = split_batch(MaxItems - N, Keys, []),
            BatchSpec = lists:keystore(<<"Keys">>, 1, Spec, {<<"Keys">>, Batch}),
            RestSpec = lists:keystore(<<"Keys">>, 1, Spec, {<<"Keys">>, Rest}),
            do_take_get_batch([{Table, {RestSpec}} | RemainingTables],
                              N + length(Batch),
                              MaxItems,
                              [{Table, {BatchSpec}} | Acc])
    end.



take_write_batch({RequestItems}, MaxItems) ->
    %% TODO: Validate item size
    %% TODO: Chunk on 1MB request size
    do_take_write_batch(RequestItems, 0, MaxItems, []).

do_take_write_batch([{_, []} | RemainingTables], N, MaxItems, Acc) ->
    do_take_write_batch(RemainingTables, N, MaxItems, Acc);

do_take_write_batch(Remaining, MaxItems, MaxItems, Acc) ->
    {lists:reverse(Acc), Remaining};

do_take_write_batch([], _, _, Acc) ->
    {lists:reverse(Acc), []};

do_take_write_batch([{Table, Requests} | RemainingTables], N, MaxItems, Acc) ->
    {Batch, Rest} = split_batch(MaxItems - N, Requests, []),

    do_take_write_batch([{Table, Rest} | RemainingTables],
                        N + length(Batch),
                        MaxItems,
                        [{Table, Batch} | Acc]).


split_batch(0, T, Acc)       -> {lists:reverse(Acc), T};
split_batch(_, [], Acc)      -> {[], Acc};
split_batch(_, [H], Acc)     -> {lists:reverse([H | Acc]), []};
split_batch(N, [H | T], Acc) -> split_batch(N-1, T, [H | Acc]).





%%
%% QUERY
%%

do_query(Request, Opts) ->
    do_query(Request, [], Opts).

do_query({UserRequest}, Acc, Opts) ->
    ExclusiveStartKey = case proplists:get_value(<<"ExclusiveStartKey">>, UserRequest) of
                            undefined ->
                                [];
                            StartKey ->
                                [{<<"ExclusiveStartKey">>, StartKey}]
                        end,

    Request = {ExclusiveStartKey ++ UserRequest},

    case retry('query', Request, Opts) of
        {ok, {Response}} ->
            Items = proplists:get_value(<<"Items">>, Response),
            case proplists:get_value(<<"LastEvaluatedKey">>, Response) of
                undefined ->
                    {ok, Items ++ Acc};
                LastEvaluatedKey ->
                    NextRequest = {lists:keystore(
                                     <<"ExclusiveStartKey">>, 1,
                                     UserRequest,
                                     {<<"ExclusiveStartKey">>, LastEvaluatedKey})},
                    do_query(NextRequest, Items ++ Acc, Opts)
            end
    end.







%%
%% SCAN
%%


do_scan(Request, Opts) ->
    do_scan(Request, [], Opts).

do_scan({UserRequest}, Acc, Opts) ->
    ExclusiveStartKey = case proplists:get_value(<<"ExclusiveStartKey">>, UserRequest) of
                            undefined ->
                                [];
                            StartKey ->
                                [{<<"ExclusiveStartKey">>, StartKey}]
                        end,

    Request = {ExclusiveStartKey ++ UserRequest},

    case retry(scan, Request, Opts) of
        {ok, {Response}} ->
            Items = proplists:get_value(<<"Items">>, Response, []),
            case proplists:get_value(<<"LastEvaluatedKey">>, Response) of
                undefined ->
                    {ok, Items ++ Acc};
                LastEvaluatedKey ->
                    NextRequest = {lists:keystore(
                                     <<"ExclusiveStartKey">>, 1,
                                     UserRequest,
                                     {<<"ExclusiveStartKey">>, LastEvaluatedKey})},
                    do_scan(NextRequest, Items ++ Acc, Opts)
            end
    end.







%%
%% INTERNALS
%%

retry(Op, Request, Opts) ->
    case proplists:is_defined(no_retry, Opts) of
        true ->
            do(Op, Request, timeout(Opts));
        false ->
            retry(Op, Request, 0, os:timestamp(), Opts)
    end.

retry(Op, Request, Retries, Start, Opts) ->
    RequestStart = os:timestamp(),
    case do(Op, Request, Opts) of
        {ok, Response} ->

            case proplists:get_value(<<"ConsumedCapacity">>,
                                     element(1, Response)) of
                undefined -> ok;
                Capacity  -> catch (callback_mod()):request_complete(
                                     Op, RequestStart, Capacity)
            end,

            {ok, Response};

        {error, Reason} = Error ->
            catch (callback_mod()):request_error(Op, RequestStart, Reason),

            case should_retry(Reason) of
                true ->
                    case Retries =:= retries(Opts) of
                        true ->
                            {error, max_retries};
                        false ->
                            timer:sleep(trunc(math:pow(2, Retries) * 50)),
                            retry(Op, Request, Retries+1, Start, Opts)
                    end;
                false ->
                    Error
            end
    end.


do(Operation, {UserRequest}, Opts) ->
    Now = edatetime:now2ts(),

    Request = {lists:keystore(<<"ReturnConsumedCapacity">>, 1, UserRequest,
                              {<<"ReturnConsumedCapacity">>, <<"TOTAL">>})},

    Body = jiffy:encode(Request),

    URL = <<"http://dynamodb.", (endpoint())/binary, ".amazonaws.com/">>,
    Headers = [
               {<<"Host">>, <<"dynamodb.", (endpoint())/binary,
                              ".amazonaws.com">>},
               {<<"Content-Type">>, <<"application/x-amz-json-1.0">>},
               {<<"x-amz-date">>, edatetime:iso8601(Now)},
               {<<"x-amz-target">>, target(Operation)}
              ],
    Signed = [{<<"Authorization">>, authorization(Headers, Body, Now)}
              | Headers],

    ServerTimeout = proplists:get_value(server_timeout, Opts, 5000),
    CallTimeout = proplists:get_value(call_timeout, Opts, 10000),
    ClaimTimeout = proplists:get_value(claim_timeout, Opts, 1000), %% us

    case party:post(URL, Signed, Body, [{server_timeout, ServerTimeout},
                                        {call_timeout, CallTimeout},
                                        {claim_timeout, ClaimTimeout}]) of
        {ok, {{200, <<"OK">>}, _, ResponseBody}} ->
            {ok, jiffy:decode(ResponseBody)};

        {ok, {{Code, _}, _, ResponseBody}}
          when 400 =< Code andalso Code =< 599 ->
            {Response} = jiffy:decode(ResponseBody),
            Type = case proplists:get_value(<<"__type">>, Response) of
                       <<"com.amazonaws.dynamodb.v20120810#", T/binary>> ->
                           T;
                       <<"com.amazon.coral.validate#", T/binary>> ->
                           T;
                       <<"com.amazon.coral.service#", T/binary>> ->
                           T
                   end,
            Message = case proplists:get_value(<<"message">>, Response) of
                          undefined ->
                              %% com.amazon.coral.service#SerializationException
                              proplists:get_value(<<"Message">>, Response);
                          M ->
                              M
                      end,
            {error, {Type, Message}};

        {error, Reason} ->
            {error, Reason}
    end.


timeout(Opts) -> proplists:get_value(timeout, Opts, 5000).
retries(Opts) -> proplists:get_value(retries, Opts, 3).


%%
%% AWS4 request signing
%% http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
%%


authorization(Headers, Body, Now) ->
    CanonicalRequest = canonical(Headers, Body),

    HashedCanonicalRequest = to_lower(
                               hmac:hexlify(
                                 erlsha2:sha256(CanonicalRequest))),

    StringToSign = string_to_sign(HashedCanonicalRequest, Now),

    lists:flatten(
      ["AWS4-HMAC-SHA256 ",
       "Credential=", credential(Now), ", ",
       "SignedHeaders=", string:join([to_lower(K)
                                      || {K, _} <- lists:sort(Headers)],
                                     ";"), ", ",
       "Signature=", signature(StringToSign, Now)]).


canonical(Headers, Body) ->
    string:join(
      ["POST",
       "/",
       "",
       [[to_lower(K), ":", V, "\n"] || {K, V} <- lists:sort(Headers)],
       string:join([to_lower(K) || {K, _} <- lists:sort(Headers)],
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
    to_lower(
      hmac:hexlify(
        hmac:hmac256(derived_key(Now),
                     StringToSign))).



credential(Now) ->
    [access_key(), "/", ymd(Now), "/", endpoint(), "/", aws_host(), "/aws4_request"].

hexdigest(Body) ->
    to_lower(hmac:hexlify(erlsha2:sha256(Body))).



target(batch_get_item)   -> <<"DynamoDB_20120810.BatchGetItem">>;
target(batch_write_item) -> <<"DynamoDB_20120810.BatchWriteItem">>;
target(create_table)     -> <<"DynamoDB_20120810.CreateTable">>;
target(delete_table)     -> <<"DynamoDB_20120810.DeleteTable">>;
target(delete_item)      -> <<"DynamoDB_20120810.DeleteItem">>;
target(describe_table)   -> <<"DynamoDB_20120810.DescribeTable">>;
target(get_item)         -> <<"DynamoDB_20120810.GetItem">>;
target(list_tables)      -> <<"DynamoDB_20120810.ListTables">>;
target(put_item)         -> <<"DynamoDB_20120810.PutItem">>;
target('query')          -> <<"DynamoDB_20120810.Query">>;
target(scan)             -> <<"DynamoDB_20120810.Scan">>;
target(update_item)      -> <<"DynamoDB_20120810.UpdateItem">>;
target(update_table)     -> <<"DynamoDB_20120810.UpdateTable">>;
target(Target)           -> throw({unknown_target, Target}).


should_retry({<<"ProvisionedThroughputExceededException">>, _}) -> true;
should_retry({<<"ResourceNotFoundException">>, _})              -> false;
should_retry({<<"ResourceInUseException">>, _})                 -> true;
should_retry({<<"ValidationException">>, _})                    -> false;
should_retry({<<"InvalidSignatureException">>, _})              -> false;
should_retry({<<"SerializationException">>, _})                 -> false;
should_retry({<<"InternalServerError">>, _})                    -> true;
should_retry({<<"ConditionalCheckFailedException">>, _})        -> false;
should_retry(timeout)                                           -> true;
should_retry(claim_timeout)                                     -> true;
should_retry(busy)                                              -> true;
should_retry(max_concurrency)                                   -> true.



%%
%% Callbacks
%%

request_complete(_Operation, _Start, _Capacity) ->
    ok.

request_error(_Operation, _Start, _Reason) ->
    ok.

%%
%% INTERNAL HELPERS
%%

to_lower(Binary) when is_binary(Binary) ->
    string:to_lower(binary_to_list(Binary));
to_lower(List) ->
    string:to_lower(List).



endpoint() ->
    {ok, Endpoint} = application:get_env(current, endpoint),
    Endpoint.

aws_host() ->
    application:get_env(current, aws_host, <<"dynamodb">>).

access_key() ->
    {ok, Access} = application:get_env(current, access_key),
    Access.

secret_key() ->
    {ok, Secret} = application:get_env(current, secret_access_key),
    Secret.

ymd(Now) ->
    {Y, M, D} = edatetime:ts2date(Now),
    io_lib:format("~4.10.0B~2.10.0B~2.10.0B", [Y, M, D]).

callback_mod() ->
    case application:get_env(current, callback_mod) of
        {ok, Mod} ->
            Mod;
        undefined ->
            throw(current_missing_callback_mod)
    end.

