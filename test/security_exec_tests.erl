%%% vim:ts=4:sw=4:et
%%% @doc Security-focused tests for erlexec policy gates and hardening.
%%%
%%% Tests are behavioral where possible (exercising runtime behavior, not
%%% scanning source files for string patterns). Static-analysis tests are
%%% retained only as secondary regression guards and are clearly labeled.
-module(security_exec_tests).

-include_lib("eunit/include/eunit.hrl").

security_exec_test_() ->
    {timeout, 120, [
        %% Policy gate: manage external pids
        {"manage denied by default",             ?_test(manage_is_denied_by_default())},
        {"manage works when enabled",            ?_test(manage_works_when_enabled())},
        %% Policy gate: shell commands
        {"shell string denied by default",       ?_test(shell_string_denied_by_default())},
        {"shell binary denied by default",       ?_test(shell_binary_denied_by_default())},
        {"argv list allowed when shell denied",  ?_test(argv_allowed_when_shell_denied())},
        %% Policy gate: custom kill commands
        {"custom kill denied by default",        ?_test(custom_kill_command_denied_by_default())},
        {"custom kill works when enabled",       ?_test(custom_kill_command_works_when_enabled())},
        %% Port startup argument injection
        {"port args not shell-evaluated",        ?_test(port_startup_args_are_not_shell_evaluated())},
        %% Port protocol safety (behavioral)
        {"safe binary_to_term rejects unknown atoms", ?_test(safe_binary_to_term_rejects_unknown_atoms())},
        %% User option type normalization
        {"user atom matches limit_users string", ?_test(user_atom_matches_limit_users_string())},
        %% Finalize: transient pid cleanup
        {"finalize drains transient pids",       ?_test(finalize_drains_transient_pids())}
    ]}.

%%----------------------------------------------------------------------
%% Policy gate: manage external pids
%%----------------------------------------------------------------------

manage_is_denied_by_default() ->
    with_exec([], fun() ->
        ?assertMatch({error, manage_external_pids_disabled}, exec:manage(999999, []))
    end).

manage_works_when_enabled() ->
    %% Spawn a real child, then manage its pid with the gate enabled.
    %% We should NOT get manage_external_pids_disabled.
    with_exec([{allow_manage_external_pids, true}, {allow_shell_commands, true}], fun() ->
        Port = erlang:open_port({spawn, "/bin/sleep 30"}, []),
        {os_pid, OsPid} = erlang:port_info(Port, os_pid),
        timer:sleep(100),
        Result = exec:manage(OsPid, []),
        ?assertNotMatch({error, manage_external_pids_disabled}, Result),
        %% Clean up
        catch erlang:port_close(Port),
        catch exec:kill(OsPid, 9),
        timer:sleep(100)
    end).

%%----------------------------------------------------------------------
%% Policy gate: shell commands
%%----------------------------------------------------------------------

shell_string_denied_by_default() ->
    with_exec([], fun() ->
        ?assertMatch({error, shell_commands_not_allowed},
                     exec:run("echo blocked", [sync, stdout]))
    end).

shell_binary_denied_by_default() ->
    with_exec([], fun() ->
        ?assertMatch({error, shell_commands_not_allowed},
                     exec:run(<<"echo blocked">>, [sync, stdout]))
    end).

argv_allowed_when_shell_denied() ->
    with_exec([], fun() ->
        ?assertMatch({ok, [{stdout, [<<"allowed\n">>]}]},
                     exec:run(["/bin/echo", "allowed"], [sync, stdout]))
    end).

%%----------------------------------------------------------------------
%% Policy gate: custom kill commands
%%----------------------------------------------------------------------

custom_kill_command_denied_by_default() ->
    %% allow_shell_commands must be true to reach the kill option check
    with_exec([{allow_shell_commands, true}], fun() ->
        ?assertMatch({error, custom_kill_commands_not_allowed},
                     exec:run(["/bin/sleep", "1"], [{kill, "kill -9 ${CHILD_PID}"}]))
    end).

custom_kill_command_works_when_enabled() ->
    with_exec([{allow_shell_commands, true}, {allow_custom_kill_commands, true}], fun() ->
        {ok, _, OsPid} = exec:run(["/bin/sleep", "30"],
                                  [{kill, "/bin/kill ${CHILD_PID}"},
                                   {kill_timeout, 5}]),
        timer:sleep(100),
        ?assertEqual(ok, exec:stop(OsPid)),
        timer:sleep(2000)
    end).

%%----------------------------------------------------------------------
%% Port startup argument injection
%%----------------------------------------------------------------------

port_startup_args_are_not_shell_evaluated() ->
    TouchFile = temp_file("startup_touch"),
    _ = file:delete(TouchFile),
    Res = exec:start([{args, "; touch " ++ TouchFile ++ " ;"}]),
    case Res of
        {ok, Pid} -> exit(Pid, kill);
        _         -> ok
    end,
    ?assertMatch({error, enoent}, file:read_file_info(TouchFile)).

%%----------------------------------------------------------------------
%% Port protocol safety (behavioral)
%%----------------------------------------------------------------------

safe_binary_to_term_rejects_unknown_atoms() ->
    %% Verify that binary_to_term/2 with [safe] rejects atoms not in the
    %% atom table. This is the mechanism used by exec:decode_port_msg/1.
    UniqueSuffix = integer_to_list(erlang:unique_integer([positive])),
    %% Create a binary encoding an atom that does NOT yet exist
    FreshAtomBin = create_atom_binary("__nonexistent_security_test_" ++ UniqueSuffix),
    ?assertError(badarg, binary_to_term(FreshAtomBin, [safe])).

%%----------------------------------------------------------------------
%% User option type normalization
%%----------------------------------------------------------------------

user_atom_matches_limit_users_string() ->
    %% When limit_users contains a username as a string, passing {user, Atom}
    %% should work after normalization (atom_to_list). Before the fix, the
    %% atom would fail lists:member/2 against the string list.
    User = string:trim(os:cmd("whoami")),
    case User of
        "root" ->
            %% If running as root, test with root opts
            with_exec([root, {limit_users, [User]}, {user, User}], fun() ->
                UserAtom = list_to_atom(User),
                Result = exec:run(["/bin/echo", "test"], [{user, UserAtom}, sync, stdout]),
                ?assertMatch({ok, _}, Result)
            end);
        _ ->
            %% Non-root: test that atom form of current user works
            with_exec([root, {limit_users, [User]}, {user, User}], fun() ->
                UserAtom = list_to_atom(User),
                Result = exec:run(["/bin/echo", "test"], [{user, UserAtom}, sync, stdout]),
                ?assertMatch({ok, _}, Result)
            end)
    end.

%%----------------------------------------------------------------------
%% Finalize cleanup: transient pids
%%----------------------------------------------------------------------

finalize_drains_transient_pids() ->
    %% Start exec with a process that has a slow custom kill command, then
    %% kill the exec server. Both the child and the kill helper should be
    %% cleaned up by finalize(), not left as orphans.
    MarkerFile = temp_file("finalize_marker"),
    _ = file:delete(MarkerFile),
    {ok, ExecPid} = exec:start([{allow_shell_commands, true},
                                 {allow_custom_kill_commands, true}]),
    {ok, _, OsPid} = exec:run(["/bin/sleep", "120"],
                              [{kill, "/bin/sh -c 'sleep 1; kill ${CHILD_PID}; touch " ++
                                      MarkerFile ++ "'"},
                               {kill_timeout, 10}]),
    timer:sleep(200),
    %% Kill exec server — triggers finalize()
    exit(ExecPid, kill),
    %% Wait for finalize + kill command to complete
    timer:sleep(4000),
    %% The original sleep process should be dead
    Alive = try os:cmd("kill -0 " ++ integer_to_list(OsPid) ++ " 2>/dev/null; echo $?") of
                "0\n" -> true;
                _     -> false
            catch _:_ -> false
            end,
    ?assertNot(Alive).

%%----------------------------------------------------------------------
%% Helpers
%%----------------------------------------------------------------------

with_exec(Opts, Fun) ->
    {ok, Pid} = exec:start(Opts),
    try
        Fun()
    after
        exit(Pid, kill),
        timer:sleep(200)
    end.

temp_file(Prefix) ->
    Dir = case os:getenv("TEMP") of
        false -> "/tmp";
        Path  -> Path
    end,
    {I1, I2, I3} = erlang:timestamp(),
    filename:join(Dir, io_lib:format("erlexec_~s_~w_~w_~w", [Prefix, I1, I2, I3])).

%% Create an ETF binary encoding an atom, using the ATOM_EXT format
%% directly so we don't actually create the atom in the current node.
create_atom_binary(Name) when is_list(Name) ->
    Bin = list_to_binary(Name),
    Len = byte_size(Bin),
    %% ETF version 131, ATOM_UTF8_EXT tag 118, 2-byte length
    <<131, 118, Len:16, Bin/binary>>.
