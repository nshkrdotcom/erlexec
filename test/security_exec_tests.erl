%%% vim:ts=4:sw=4:et
-module(security_exec_tests).

-include_lib("eunit/include/eunit.hrl").

security_exec_test_() ->
    [
        ?_test(manage_is_denied_by_default()),
        ?_test(manage_can_be_enabled()),
        ?_test(shell_commands_can_be_denied()),
        ?_test(custom_kill_command_can_be_denied()),
        ?_test(port_startup_args_are_not_shell_evaluated()),
        ?_test(no_broad_group_kill_in_finalize()),
        ?_test(port_protocol_decode_is_safe()),
        ?_test(no_dynamic_atom_creation_in_exec())
    ].

manage_is_denied_by_default() ->
    with_exec([], fun() ->
        ?assertMatch({error, manage_external_pids_disabled}, exec:manage(999999, []))
    end).

manage_can_be_enabled() ->
    with_exec([{allow_manage_external_pids, true}], fun() ->
        ?assertMatch({error, not_found}, exec:manage(999999, []))
    end).

shell_commands_can_be_denied() ->
    with_exec([{allow_shell_commands, false}], fun() ->
        ?assertMatch({error, shell_commands_not_allowed},
                     exec:run("echo blocked", [sync, stdout])),
        ?assertMatch({ok, [{stdout, [<<"allowed\n">>]}]},
                     exec:run(["/bin/echo", "allowed"], [sync, stdout]))
    end).

custom_kill_command_can_be_denied() ->
    with_exec([{allow_custom_kill_commands, false}], fun() ->
        ?assertMatch({error, custom_kill_commands_not_allowed},
                     exec:run(["/bin/sleep", "1"], [{kill, "kill -9 ${CHILD_PID}"}]))
    end).

port_startup_args_are_not_shell_evaluated() ->
    TouchFile = temp_file("startup_touch"),
    _ = file:delete(TouchFile),
    Res = exec:start([{args, "; touch " ++ TouchFile ++ " ;"}]),
    case Res of
        {ok, Pid} -> exit(Pid, kill);
        _ -> ok
    end,
    ?assertMatch({error, enoent}, file:read_file_info(TouchFile)).

no_broad_group_kill_in_finalize() ->
    {ok, Bin} = file:read_file("c_src/exec.cpp"),
    ?assertEqual(nomatch, binary:match(Bin, <<"kill(0, SIGTERM)">>)).

port_protocol_decode_is_safe() ->
    {ok, Bin} = file:read_file("src/exec.erl"),
    ?assertNotEqual(nomatch, binary:match(Bin, <<"binary_to_term(Bin, [safe])">>)).

no_dynamic_atom_creation_in_exec() ->
    {ok, Bin} = file:read_file("src/exec.erl"),
    ?assertEqual(nomatch, re:run(Bin, <<"\\blist_to_atom\\s*\\(">>)),
    ?assertEqual(nomatch, re:run(Bin, <<"\\bbinary_to_atom\\s*\\(">>)).

with_exec(Opts, Fun) ->
    {ok, Pid} = exec:start(Opts),
    try
        Fun()
    after
        exit(Pid, kill)
    end.

temp_file(Prefix) ->
    Dir = case os:getenv("TEMP") of
        false -> "/tmp";
        Path  -> Path
    end,
    {I1, I2, I3} = erlang:timestamp(),
    filename:join(Dir, io_lib:format("erlexec_~s_~w_~w_~w", [Prefix, I1, I2, I3])).
