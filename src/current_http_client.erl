-module(current_http_client).
-include_lib("eunit/include/eunit.hrl").

-export([post/4]).

-type headers()        :: list({binary(), any()}).
-type options()        :: list({atom(), any()}).
-type response_ok()    :: {ok, {{integer(), string()}, headers(), binary()}}.
-type response_error() :: {error, any()}.

%%TODO: map options
%%TODO: how to handle that party:connect abstraction leak?
-spec post(binary(), headers(), binary(), options()) ->
                  response_ok() | response_error().
post(URL, Headers, Body, Opts) ->
    ServerTimeout = proplists:get_value(server_timeout, Opts, 5000),
    CallTimeout   = proplists:get_value(call_timeout, Opts, 10000),
    ClaimTimeout  = proplists:get_value(claim_timeout, Opts, 1000), %% us
    PartySocket   = proplists:get_value(party_socket, Opts, undefined),

    case config_http_client() =:= party of
        true  ->
            Options = [{server_timeout, ServerTimeout},
                       {call_timeout,   CallTimeout},
                       {claim_timeout,  ClaimTimeout},
                       {party_socket,   PartySocket}],
            party:post(URL, Headers, Body, Options);
        false ->
            Options = [{connect_timeout, CallTimeout}],
            lhttpc:request(URL, post, Headers, Body, Options)
    end.

config_http_client() ->
    application:get_env(current, http_client, party).
