%% @doc HTTP client wrapper
-module(current_http_client).

%% API
-export([post/4]).

%%
%% TYPES
%%
-type header()         :: {binary() | string(), any()}.
-type headers()        :: [header()].
-type body()           :: iolist() | binary().
-type options()        :: list({atom(), any()}).
-type response_ok()    :: {ok, integer(), body()}.
-type response_error() :: {error, any()}.


%%
%% API
%%
-spec post(binary(), headers(), body(), options()) ->
                  response_ok() | response_error().
post(URL, Headers, Body, Opts) ->
    CallTimeout   = proplists:get_value(call_timeout,    Opts, 10000),
    Request = {to_list(URL), normalize_headers(Headers), "", Body},
    Options = [{body_format, binary}],
    case httpc:request(post, Request, [{timeout, CallTimeout}], Options) of
        {ok,{{_,Code,_},_Headers, RetBody}} ->
            {ok, Code, RetBody};
        {error, Error} ->
            {error, Error}
    end.

%%
%% INTERNALS
%%
normalize_headers(Headers) ->
    [{to_list(K), to_list(V)} || {K,V} <- Headers].

to_list(B) when is_binary(B) ->
    binary_to_list(B);
to_list(L) ->
    L.
