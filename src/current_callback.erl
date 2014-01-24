-module(current_callback).
-export([request_complete/3, request_error/3]).

-callback request_complete(current:target(), erlang:timestamp(), term()) -> ok.
-callback request_error(current:target(), erlang:timestamp(), term()) -> ok.

request_complete(_Op, _Start, _Capacity) ->
    ok.

request_error(_Operation, _Start, _Reason) ->
    ok.
