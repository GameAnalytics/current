%% @doc HTTP client wrapper
-module(current_http_client).

%% API
-export([post/4]).
-export([is_party_active/0]).

%%
%% TYPES
%%
-type header()         :: {binary() | string(), any()}.
-type headers()        :: [header()].
-type body()           :: iolist() | binary().
-type options()        :: list({atom(), any()}).
-type response_ok()    :: {ok, {{integer(), string()}, headers(), body()}}.
-type response_error() :: {error, any()}.


%%
%% API
%%
%%TODO: how to handle that party:connect abstraction leak?
-spec post(binary(), headers(), body(), options()) ->
                  response_ok() | response_error().
post(URL, Headers, Body, Opts) ->
    ServerTimeout = proplists:get_value(server_timeout,  Opts, 5000),
    CallTimeout   = proplists:get_value(call_timeout,    Opts, 10000),
    ClaimTimeout  = proplists:get_value(claim_timeout,   Opts, 1000), %% us
    PartySocket   = proplists:get_value(party_socket,    Opts, undefined),
    MaxConns      = proplists:get_value(max_connections, Opts, 10),

    case is_party_active() of
        true  ->
            Options = [{server_timeout, ServerTimeout},
                       {call_timeout,   CallTimeout},
                       {claim_timeout,  ClaimTimeout},
                       {party_socket,   PartySocket}],
            party:post(URL, Headers, Body, Options);
        false ->
            Options = [{connect_timeout, CallTimeout},
                       {max_connections, MaxConns}],
            lhttpc:request(to_list(URL), post,
                           normalize_headers(Headers), Body,
                           CallTimeout, Options)
    end.

is_party_active() ->
    application:get_env(current, http_client, party) =:= party.


%%
%% INTERNALS
%%
normalize_headers(Headers) ->
    [{to_list(K), to_list(V)} || {K,V} <- Headers].

to_list(B) when is_binary(B) ->
    binary_to_list(B);
to_list(L) ->
    L.
