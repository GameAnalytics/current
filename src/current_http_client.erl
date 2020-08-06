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
    CallTimeout   = proplists:get_value(call_timeout, Opts, 10000),
    Options = [{pool, default}, {recv_timeout, CallTimeout}],
    case hackney:request(post, URL, Headers, Body, Options) of
        {ok, Code, _Headers, Ref} ->
            case hackney:body(Ref) of
                {ok, RetBody} ->
                    {ok, Code, RetBody};
                {error, Error} ->
                    {error, Error}
            end;
        {error, Error} ->
            {error, Error}
    end.
