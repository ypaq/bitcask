%% -------------------------------------------------------------------
%%
%% Testing testing testing
%%
%% Copyright (c) 2014 Basho Technologies, Inc. All Rights Reserved.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% -------------------------------------------------------------------
-module(generic_qc_fsm).
%% Borrowed heavily from bitcask_qc_fsm.erl

-ifdef(EQC).

-include_lib("eqc/include/eqc.hrl").
-include_lib("eqc/include/eqc_fsm.hrl").
-include_lib("kernel/include/file.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(export_all).

-record(state,{ handle :: term(),
                dir :: term(),
                data = [] :: term(),
                keys :: term() }). %% Keys to use in the test

%% Used for output within EUnit...
-define(QC_FMT(Fmt, Args),
        io:format(user, Fmt, Args)).

-define(QC_OUT(P),
        eqc:on_output(fun(Str, Args) -> io:format(user, Str, Args) end, P)).

-define(TEST_DIR, "/tmp/generic.qc").

initial_state() ->
    init.

initial_state_data() ->
    #state{}.

init(_S) ->
    [{closed, {call, ?MODULE, set_keys, [non_empty(list(key_gen(0))),
                                         {var,parameter_test_dir}]}}].

closed(#state{dir=TestDir}) ->
    [{opened, {call, ?MODULE, open, [TestDir,[read_write,
                                              {open_timeout, 60},
                                              {expiry_secs, 0},
                                              {max_file_size, 1024*1024}
                                             ]]}}
    ].

opened(S) ->
    [{closed, {call, ?MODULE, close, [S#state.handle]}},
     {opened, {call, ?MODULE, get, [S#state.handle, key(S)]}},
     {opened, {call, ?MODULE, put, [S#state.handle, key(S), value()]}},
     {opened, {call, ?MODULE, put_filler, [S#state.handle, gen_filler_keys(), gen_filler_value()]}},
     {opened, {call, ?MODULE, delete, [S#state.handle, key(S)]}},
     {opened, {call, ?MODULE, fold_all, [S#state.handle]}},
     {opened, {call, ?MODULE, merge, [S#state.dir]}}
     ].

next_state_data(init, closed, S, _, {call, _, set_keys, [Keys, TestDir]}) ->
    S#state{ keys = Keys, dir = TestDir };
next_state_data(closed, opened, S, Handle, {call, _, open, _}) ->
    S#state { handle = Handle };
next_state_data(opened, closed, S, _, {call, _, close, _}) ->
    S#state { handle = undefined };
next_state_data(opened, opened, S, _, {call, _, put, [_, Key, Value]}) ->
    S#state { data = orddict:store(Key, Value, S#state.data) };
next_state_data(opened, opened, S, _, {call, _, delete, [_, Key]}) ->
    S#state { data = orddict:erase(Key, S#state.data) };
next_state_data(_From, _To, S, _Res, _Call) ->
    S.

precondition(_From,_To,S,{call,_,put,[K, _V]}) ->
    %% This kind of test case should never be generated in the first place.
    %% {[{set,{var,1},
    %%    {call,generic_qc_fsm,set_keys,
    %%     [[<<0,0,0,0,0>>],{var,parameter_test_dir}]}},
    %%   {set,{var,2},
    %%    {call,generic_qc_fsm,open,
    %%     [{var,parameter_test_dir},
    %%      [read_write,{open_timeout,60},{expiry_secs,0}]]}},
    %%   {set,{var,6},{call,generic_qc_fsm,put,[{var,2},<<124,193,0,0,0,0>>,<<>>]}},
    %%   {set,{var,7},{call,generic_qc_fsm,fold_all,[{var,2}]}}],
    %%  1}
    %% WTF, why do I have to do this precondition??
    lists:member(K, S#state.keys);
precondition(_From,_To,_S,_Call) ->
    true.

postcondition(_OldSt, _NewSt, _S, {call, _, _Func, _Args}, _Res) ->
    true.

qc_test_() ->
    TestTime = 45,
    {timeout, TestTime*2,
     {setup, fun prepare/0, fun cleanup/1,
      %% Run for one second without FI to allow code loader to load everything
      %% without interference from artificial faults.
      [{timeout, TestTime*2, ?_assertEqual(true,
                eqc:quickcheck(eqc:testing_time(1, ?QC_OUT(prop(false)))))},
       %% TODO: check an OS env var or check result of an experimental peek
       %%       to see if we can run with FI, then change the arg below!
       {timeout, TestTime*2, ?_assertEqual(true,
                eqc:quickcheck(eqc:testing_time(TestTime, ?QC_OUT(prop()))))}
      ]}}.

prepare() ->
    ok.

cleanup(_) ->
    ok.

prop() ->
    prop(false).

prop(FI_enabledP) ->
    prop(FI_enabledP, false).

prop(FI_enabledP, VerboseP) ->
    _ = faulterl_nif:poke("bc_fi_enabled", 0, <<0:8/native>>, false),
    {ok, RE1} = re:compile("open,.*put,.*close,.*open,.*get,"),
    ?FORALL({Cmds, Seed}, {commands(?MODULE), choose(1,99999)},
            begin
                faulterl_nif:poke("bc_fi_enabled", 0, <<0:8/native>>, false),
                [catch erlang:garbage_collect(Pid) || Pid <- erlang:processes()],

                {Ta, Tb, Tc} = now(),
                TestDir = ?TEST_DIR ++ lists:flatten(io_lib:format(".~w.~w.~w", [Ta, Tb, Tc])),
                ok = file:make_dir(TestDir),
                Env = [{parameter_test_dir, TestDir}],

                event_logger:start_link(),
                if FI_enabledP ->
                        ok = faulterl_nif:poke("bc_fi_enabled", 0,
                                               <<1:8/native>>, false),
                        VerboseI = if VerboseP -> 1;
                                      true     -> 0 end,
                        ok = faulterl_nif:poke("bc_fi_verbose", 0,
                                               <<VerboseI:8/native>>, false),

                        ok = faulterl_nif:poke("bc_fi_random_seed", 0,
                                               <<Seed:32/native>>, false),
                        %% io:format("Seed=~p,", [Seed]),
                        ok = faulterl_nif:poke("bc_fi_random_reseed", 0,
                                               <<1:8/native>>, false);
                   true ->
                        ok
                end,
                event_logger:start_logging(),
                {H,{_State, StateData}, Res} = run_commands(?MODULE,Cmds,Env),
                _ = faulterl_nif:poke("bc_fi_enabled", 0, <<0:8/native>>, false),
                case (StateData#state.handle) of
                    Handle when is_binary(Handle) orelse
                                is_reference(Handle) ->
                        catch (close(Handle));
                    _ ->
                        true
                end,
                %% application:unload(bitcask),
                Trace0 = event_logger:get_events(),
                Trace = remove_timestamps(Trace0),
                Sane0 = verify_trace(Trace),
                Sane = case Sane0 of
                           {get,_How,_K,expected,[_EXP],got,_GOT}
                             when %(is_binary(EXP) andalso GOT == not_found)
                                  %orelse
                                  %(EXP == not_found andalso is_binary(GOT)) ->
                                  true ->
                               Str = lists:flatten(io_lib:format("~w", [Trace])),
                               case re:run(Str, RE1) of
                                   {match, _} ->
                                       ?QC_FMT("SKIP1", []),
                                       true;
                                   _ ->
                                       Sane0
                               end;
                           Else ->
                               Else
                       end,

                ok = really_delete_dir(TestDir),

                ?WHENFAIL(
                ?QC_FMT("Trace: ~P\nverify_trace: ~p\n", [Trace, 150, Sane]),
                aggregate(zip(state_names(H),command_names(Cmds)), 
                          conjunction([{postconditions, equals(Res, ok)},
                                       {verify_trace, Sane}])))
            end).

remove_timestamps(Trace) ->
    [Event || {_TS, Event} <- Trace].

verify_trace([]) ->
    true;
verify_trace([{set_keys, Keys}|TraceTail]) ->
    Dict0 = dict:from_list([{K, [not_found]} || K <- Keys]),
    {Bool, _D} =
        lists:foldl(
          fun({get, How, K, V}, {true, D}) ->
                  PrefixLen = byte_size(K) - 4,
                  <<_:PrefixLen/binary, Suffix:32>> = K,
                  if Suffix == 0 ->
                          Vs = dict:fetch(K, D),
                          case lists:member(V, Vs) of
                              true ->
                                  {true, D};
                              false ->
                                  {{get,How,K,expected,Vs,got,V}, D}
                          end;
                     true ->
                          %% Filler, skip
                          {true, D}
                  end;
             ({put, yes, K, V}, {true, D}) ->
                  {true, dict:store(K, [V], D)};
             ({put, maybe, K, V, _Err}, {true, D}) ->
                  io:format(user, "pm,", []),
                  Vs = dict:fetch(K, D),
                  {true, dict:store(K, [V|Vs], D)};
             ({delete, yes, K}, {true, D}) ->
                  {true, dict:store(K, [not_found], D)};
             ({delete, maybe, K, _Err}, {true, D}) ->
                  io:format(user, "dm,", []),
                  Vs = dict:fetch(K, D),
                  {true, dict:store(K, [not_found|Vs], D)};
             (open, Acc) ->
                  Acc;
             ({open, _}, Acc) ->
                  Acc;
             (close, Acc) ->
                  Acc;
             (_Else, Acc) ->
                  %%io:format(user, "verify_trace: ~p\n", [_Else]),
                  Acc
          end, {true, Dict0}, TraceTail),
    Bool.

%% Weight for transition (this callback is optional).
%% Specify how often each transition should be chosen
weight(_From, _To,{call,_,close,_}) ->
    10;
weight(_From, _To,{call,_,merge,_}) ->
    5;
weight(_From, _To,{call,_,fold_all,_}) ->
    5;
weight(_From,_To,{call,_,_,_}) ->
    100.

set_keys(Keys, _TestDir) -> %% next_state sets the keys for use by key()
    event_logger:event({set_keys, Keys}),
    ok.

key_gen(SuffixI) ->
    ?LET(Prefix,
         ?SUCHTHAT(X, binary(), X /= <<>>),
         <<Prefix/binary, SuffixI:32>>).

key(#state{keys = Keys}) ->
    elements(Keys).

value() ->
    binary().

sync_strategy() ->
    {sync_strategy, oneof([none])}.

gen_filler_keys() ->
    {choose(1, 50), non_empty(binary())}.
    %% ?LET({N, Prefix}, {choose(1, 4*1000), non_empty(binary())},
    %%      [<<Prefix/binary, I:32>> || I <- lists:seq(1, N)]).

gen_filler_value() ->
    choose(1, 128*1024).
    %% ?LET(Size, choose(1, 128*1024), <<42:(Size*8)>>).

really_delete_dir(Dir) ->
    [file:delete(X) || X <- filelib:wildcard(Dir ++ "/*")],
    [file:delete(X) || X <- filelib:wildcard(Dir ++ "/*/*")],
    [file:del_dir(X) || X <- filelib:wildcard(Dir ++ "/*")],
    case file:del_dir(Dir) of
        ok             -> ok;
        {error,enoent} -> ok;
        Else           -> Else
    end.

open(Dir, Opts) ->
    %% io:format(user, "open,", []),
    bitcask:open(Dir, Opts).

close(H) ->
    %% io:format(user, "close,", []),
    bitcask:close(H).

get(H, K) ->
    %% io:format(user, "get ~p,", [K]),
    bitcask:get(H, K).

put(H, K, V) ->
    %% io:format(user, "put ~p,", [K]),
    bitcask:put(H, K, V).

put_filler(not_open, _Ks, _V) ->
    put_result_ignored;
put_filler(H, {NumKs, Prefix}, ValSize) ->
    io:format(user, "<f", []),
    Val = <<42:(ValSize*8)>>,
    [bitcask:put(H, <<Prefix/binary, N:32>>, Val) || N <- lists:seq(1, NumKs)],
    io:format(user, ">", []),
    ok.

delete(H, K) ->
    %% io:format(user, "delete ~p,", [K]),
    bitcask:delete(H, K).

fold_all(not_open) ->
    fold_result_ignored;
fold_all(H) ->
    F = fun(K, V, Acc) ->
                event_logger:event({get, fold, K, V}),
                [{K,V}|Acc]
        end,
    _Res = bitcask:fold(H, F, []),
    %%io:format(user, "~p,", [_Res]),
    ok.

merge(H) ->
    bitcask:merge(H).

-endif.


