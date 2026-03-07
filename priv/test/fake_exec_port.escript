#!/usr/bin/env escript
%%! -noshell
-mode(compile).

main(_) ->
    Mode = getenv("ERLEXEC_FAKE_PORT_MODE", "invalid"),
    EmitDelayMs = list_to_integer(getenv("ERLEXEC_FAKE_PORT_EMIT_DELAY_MS", "0")),
    SleepMs = list_to_integer(getenv("ERLEXEC_FAKE_PORT_SLEEP_MS", "1000")),
    timer:sleep(EmitDelayMs),
    ok = emit_packet(payload(Mode)),
    timer:sleep(SleepMs).

payload("invalid") ->
    <<0>>;
payload("unsafe_atom") ->
    Name = iolist_to_binary(
        io_lib:format("__erlexec_fake_atom_~B", [erlang:unique_integer([positive])])
    ),
    Atom = binary_to_atom(Name, utf8),
    term_to_binary({0, Atom});
payload(Other) ->
    erlang:error({unknown_mode, Other}).

emit_packet(Payload) when is_binary(Payload), byte_size(Payload) =< 16#FFFF ->
    ok = file:write_file("/dev/stdout", <<(byte_size(Payload)):16/big, Payload/binary>>),
    ok.

getenv(Name, Default) ->
    case os:getenv(Name) of
        false -> Default;
        Value -> Value
    end.
