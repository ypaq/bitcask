%% -------------------------------------------------------------------
%%
%% bitcask: Eric Brewer-inspired key/value store
%%
%% Copyright (c) 2010 Basho Technologies, Inc. All Rights Reserved.
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
-module(bitcask_nifs).

-export([init/0,
         keydir_new/0, keydir_new/1,
         maybe_keydir_new/1,
         keydir_mark_ready/1,
         keydir_put/6,
         keydir_put/8,
         keydir_get/2,
         keydir_get/3,
         keydir_get_epoch/1,
         keydir_remove/2, keydir_remove/4,
         keydir_fold/3,
         keydir_itr/1,
         keydir_itr/2,
         keydir_itr_next/1,
         keydir_itr_release/1,
         keydir_frozen/2,
         keydir_info/1,
         keydir_release/1,
         increment_file_id/1,
         increment_file_id/2,
         keydir_trim_fstats/2,
         update_fstats/8,
         set_pending_delete/2,
         lock_acquire/2,
         lock_release/1,
         lock_readdata/1,
         lock_writedata/2,
         file_open/2,
         file_close/1,
         file_sync/1,
         file_pread/3,
         file_pwrite/3,
         file_read/2,
         file_write/2,
         file_position/2,
         file_seekbof/1,
         file_truncate/1]).

-on_load(init/0).

-include("bitcask.hrl").

-ifdef(PULSE).
-compile({parse_transform, pulse_instrument}).
-export([set_pulse_pid/1]).
-compile({pulse_skip, [{init,0}]}).
-endif.

-ifdef(TEST).
-ifdef(EQC).
-include_lib("eqc/include/eqc.hrl").
-endif.
-compile(export_all).
-include_lib("eunit/include/eunit.hrl").
-endif.

-type errno_atom() :: atom().                   % POSIX errno as atom


-spec init() ->
        ok | {error, any()}.
init() ->
    SoName =
        case code:priv_dir(bitcask) of
            {error, bad_name} ->
                case code:which(?MODULE) of
                    Filename when is_list(Filename) ->
                        filename:join([filename:dirname(Filename),"../priv",
                                       "bitcask"]);
                    _ ->
                        filename:join("../priv", "bitcask")
                end;
            Dir ->
                filename:join(Dir, "bitcask")
        end,
    erlang:load_nif(SoName, 0).

-ifdef(PULSE).
set_pulse_pid(_Pid) ->
    erlang:nif_error({error, not_loaded}).
-endif.

%% ===================================================================
%% Internal functions
%% ===================================================================
%%
%% Most of the functions below are actually defined in c_src/bitcask_nifs.c
%% See that file for the real functionality of the bitcask_nifs module.
%% The definitions here are only to satisfy trivial static analysis.
%%


-spec keydir_new() -> {ok, reference()}.
keydir_new() ->
    erlang:nif_error({error, not_loaded}).

-spec keydir_new(string()) ->
        {ok, reference()} |
        {ready, reference()} | {not_ready, reference()} |
        {error, not_ready}.
keydir_new(Name) when is_list(Name) ->
    erlang:nif_error({error, not_loaded}).

-spec maybe_keydir_new(string()) ->
        {ready, reference()} |
        {error, not_ready}.
maybe_keydir_new(Name) when is_list(Name) ->
    erlang:nif_error({error, not_loaded}).

-spec keydir_mark_ready(reference()) ->
        ok.
keydir_mark_ready(_Ref) ->
    erlang:nif_error({error, not_loaded}).

-spec keydir_put(reference(), binary(), integer(), integer(),
                 integer(), integer()) ->
        ok | already_exists.
keydir_put(Ref, Key, FileId, TotalSz, Offset, Tstamp) ->
    keydir_put(Ref, Key, FileId, TotalSz, Offset, Tstamp, 0, 0).

-spec keydir_put(Ref::reference(), Key::binary(), FileId::integer(),
                 TotalSz::integer(), Offset::integer(), Tstamp::integer(),
                 OldFileId::integer(), OldOffset::integer()) ->
        ok | already_exists.
keydir_put(Ref, Key, FileId, TotalSz, Offset, Tstamp, OldFileId, OldOffset) ->
    keydir_put_int(Ref, Key, FileId, TotalSz, <<Offset:64/unsigned-native>>,
                   Tstamp, OldFileId, <<OldOffset:64/unsigned-native>>).

-spec keydir_put_int(Ref::reference(), Key::binary(), FileId::integer(),
                     TotalSz::integer(), Offset::binary(), Tstamp::integer(),
                     OldFileId::integer(), OldOffset::binary()) ->
        ok | already_exists.
keydir_put_int(_Ref, _Key, _FileId, _TotalSz, _Offset, _Tstamp,
               _OldFileId, _OldOffset) ->
    erlang:nif_error({error, not_loaded}).

-spec keydir_get(reference(), binary()) ->
        not_found | #bitcask_entry{}.
keydir_get(Ref, Key) ->
    keydir_get(Ref, Key, 16#ffffffffffffffff).

-spec keydir_get(reference(), binary(), integer()) ->
        not_found | #bitcask_entry{}.
keydir_get(Ref, Key, Epoch) ->
    case keydir_get_int(Ref, Key, Epoch) of
        E when is_record(E, bitcask_entry) ->
            <<Offset:64/unsigned-native>> = E#bitcask_entry.offset,
            E#bitcask_entry{offset = Offset};
        _ ->
            not_found
    end.

-spec keydir_get_int(reference(), binary(), integer()) ->
        not_found | #bitcask_entry{}.
keydir_get_int(_Ref, _Key, _Epoch) ->
    erlang:nif_error({error, not_loaded}).

keydir_get_epoch(_Ref) ->
    erlang:nif_error({error, not_loaded}).

-spec keydir_remove(reference(), binary()) ->
        ok | already_exists.
keydir_remove(_Ref, _Key) ->
    erlang:nif_error({error, not_loaded}).

-spec keydir_remove(reference(), binary(), integer(), integer()) ->
        ok | already_exists.
keydir_remove(Ref, Key, FileId, Offset) ->
    keydir_remove_int(Ref, Key, FileId, <<Offset:64/unsigned-native>>).

keydir_remove_int(_Ref, _Key, _FileId, _Offset) ->
    erlang:nif_error({error, not_loaded}).

-spec keydir_itr(reference(), 0 | 1) ->
    {ok, reference()} | {error, allocation_error}.
keydir_itr(_Ref, _UseSnapshot) ->
    erlang:nif_error({error, not_loaded}).

-spec keydir_itr(reference()) ->
    {ok, reference()} | {error, allocation_error}.
keydir_itr(Ref) ->
    keydir_itr(Ref, 1).

-spec keydir_itr_next(reference()) ->
        #bitcask_entry{} | allocation_error | not_found.
keydir_itr_next(_Ref) ->
    erlang:nif_error({error, not_loaded}).

-spec keydir_itr_release(reference()) ->
        ok.
keydir_itr_release(_Ref) ->
    erlang:nif_error({error, not_loaded}).

-spec increment_file_id(reference()) ->
        {ok, non_neg_integer()}.
increment_file_id(_Ref) ->
    erlang:nif_error({error, not_loaded}).

-spec increment_file_id(reference(), non_neg_integer()) ->
        {ok, non_neg_integer()}.
increment_file_id(_Ref, _ConditionalFileId) ->
    erlang:nif_error({error, not_loaded}).

-spec keydir_fold(reference(), fun((any(), any()) -> any()), any()) ->
        any() | {error, any()}.
keydir_fold(Ref, Fun, Acc0) ->
    FrozenFun = fun(Itr) ->
                        keydir_fold_cont(keydir_itr_next(Itr), Itr, Fun, Acc0)
                end,
    keydir_frozen(Ref, FrozenFun).

%% Execute the function once the keydir is frozen
keydir_frozen(Ref, FrozenFun) ->
    case keydir_itr(Ref) of
        {ok, Itr} ->
            try
                FrozenFun(Itr)
            after
                keydir_itr_release(Itr)
            end;
        {error, Reason} ->
            {error, Reason}
    end.

-spec keydir_info(reference()) ->
        {integer(), integer(),
         [{integer(), integer(), integer(), integer(), integer(),
           integer(), integer(), integer()}],
         {integer(), integer(), boolean(), 'undefined'|integer()},
        non_neg_integer()}.
keydir_info(_Ref) ->
    erlang:nif_error({error, not_loaded}).

-spec keydir_release(reference()) ->
        ok.
keydir_release(_Ref) ->
    erlang:nif_error({error, not_loaded}).

-spec keydir_trim_fstats(reference(), [integer()]) ->
        {ok, integer()} | {error, atom()}.
keydir_trim_fstats(_Ref, _IDList) ->
    erlang:nif_error({error, not_loaded}).

-spec update_fstats(reference(), non_neg_integer(), non_neg_integer(),
                    integer(), integer(), integer(), integer(), integer() ) ->
    ok.
update_fstats(_Ref, _FileId, _Tstamp,
              _LiveKeyIncr, _TotalKeyIncr,
              _LiveIncr, _TotalIncr, _ShouldCreate) ->
    erlang:nif_error({error, not_loaded}).

-spec set_pending_delete(reference(), non_neg_integer()) ->
    ok.
set_pending_delete(_Ref, _FileId) ->
    erlang:nif_error({error, not_loaded}).

-spec lock_acquire(string(), integer()) ->
        {ok, reference()} | {error, atom()}.
lock_acquire(Filename, IsWriteLock) ->
    bitcask_bump:big(),
    lock_acquire_int(Filename, IsWriteLock).

lock_acquire_int(_Filename, _IsWriteLock) ->
    erlang:nif_error({error, not_loaded}).

-spec lock_release(reference()) ->
        ok.
lock_release(Ref) ->
    bitcask_bump:big(),
    lock_release_int(Ref).

lock_release_int(_Ref) ->
    erlang:nif_error({error, not_loaded}).

-spec lock_readdata(reference()) ->
        {ok, binary()} |
        {fstat_error, integer()} | {error, allocation_error} |
        {pread_error, integer()}.
lock_readdata(Ref) ->
    bitcask_bump:big(),
    lock_readdata_int(Ref).

lock_readdata_int(_Ref) ->
    erlang:nif_error({error, not_loaded}).

-spec lock_writedata(reference(), binary()) ->
        ok |
        {ftruncate_error, errno_atom()} | {pwrite_error, errno_atom()} |
        {error, lock_not_writable}.
lock_writedata(Ref, Data) ->
    bitcask_bump:big(),
    lock_writedata_int(Ref, Data).

lock_writedata_int(_Ref, _Data) ->
    erlang:nif_error({error, not_loaded}).

file_open(Filename, Opts) ->
    bitcask_bump:big(),
    file_open_int(Filename, Opts).

file_open_int(_Filename, _Opts) ->
    erlang:nif_error({error, not_loaded}).

file_close(Ref) ->
    bitcask_bump:big(),
    file_close_int(Ref).

file_close_int(_Ref) ->
    erlang:nif_error({error, not_loaded}).

file_sync(Ref) ->
    bitcask_bump:big(),
    file_sync_int(Ref).

file_sync_int(_Ref) ->
    erlang:nif_error({error, not_loaded}).

file_pread(Ref, Offset, Size) ->
    bitcask_bump:big(),
    file_pread_int(Ref, Offset, Size).

file_pread_int(_Ref, _Offset, _Size) ->
    erlang:nif_error({error, not_loaded}).

file_pwrite(Ref, Offset, Bytes) ->
    bitcask_bump:big(),
    file_pwrite_int(Ref, Offset, Bytes).

file_pwrite_int(_Ref, _Offset, _Bytes) ->
    erlang:nif_error({error, not_loaded}).

file_read(Ref, Size) ->
    bitcask_bump:big(),
    file_read_int(Ref, Size).

file_read_int(_Ref, _Size) ->
    erlang:nif_error({error, not_loaded}).

file_write(Ref, Bytes) ->
    bitcask_bump:big(),
    file_write_int(Ref, Bytes).

file_write_int(_Ref, _Bytes) ->
    erlang:nif_error({error, not_loaded}).

file_position(Ref, Position) ->
    bitcask_bump:big(),
    file_position_int(Ref, Position).

file_position_int(_Ref, _Position) ->
    erlang:nif_error({error, not_loaded}).

file_seekbof(Ref) ->
    bitcask_bump:big(),
    file_seekbof_int(Ref).

file_seekbof_int(_Ref) ->
    erlang:nif_error({error, not_loaded}).

file_truncate(Ref) ->
    bitcask_bump:big(),
    file_truncate_int(Ref).

file_truncate_int(_Ref) ->
    erlang:nif_error({error, not_loaded}).


%% ===================================================================
%% Internal functions
%% ===================================================================

keydir_fold_cont(not_found, _Ref, _Fun, Acc0) ->
    Acc0;
keydir_fold_cont(Curr, Ref, Fun, Acc0) ->
    Acc = Fun(Curr, Acc0),
    keydir_fold_cont(keydir_itr_next(Ref), Ref, Fun, Acc).

%% ===================================================================
%% EUnit tests
%% ===================================================================
-ifdef(TEST).

keydir_basic_test_() ->
    {timeout, 60, fun keydir_basic_test2/0}.

keydir_basic_test2() ->
    {ok, Ref} = keydir_new(),
    ok = keydir_put(Ref, <<"abc">>, 0, 1234, 0, 1),

    {1, 3, [{0, 1, 1, 1234, 1234, 1, 1, _}],
     {0, 0, false, _},_} = keydir_info(Ref),

    E = keydir_get(Ref, <<"abc">>),
    0 = E#bitcask_entry.file_id,
    1234 = E#bitcask_entry.total_sz,
    0 = E#bitcask_entry.offset,
    1 = E#bitcask_entry.tstamp,

    already_exists = keydir_put(Ref, <<"abc">>, 0, 1234, 0, 0),

    ok = keydir_remove(Ref, <<"abc">>),
    not_found = keydir_get(Ref, <<"abc">>).

keydir_itr_anon_test_() ->
    {timeout, 60, fun keydir_itr_anon_test2/0}.

keydir_itr_anon_test2() ->
    {ok, Ref} = keydir_new(),
    keydir_itr_test_base(Ref).

keydir_itr_named_test_() ->
    {timeout, 60, fun keydir_itr_named_test2/0}.

keydir_itr_named_test2() ->
    {not_ready, Ref} = keydir_new("keydir_itr_named_test"),
    keydir_mark_ready(Ref),
    keydir_itr_test_base(Ref).


keydir_itr_test_base(Ref) ->
    ok = keydir_put(Ref, <<"abc">>, 0, 1234, 0, 1),
    ok = keydir_put(Ref, <<"def">>, 0, 4567, 1234, 2),
    ok = keydir_put(Ref, <<"hij">>, 1, 7890, 0, 3),

    {3, 9, _, _, _} = keydir_info(Ref),

    List = keydir_fold(Ref, fun(E, Acc) -> [ E | Acc] end, []),
    3 = length(List),
    true = lists:keymember(<<"abc">>, #bitcask_entry.key, List),
    true = lists:keymember(<<"def">>, #bitcask_entry.key, List),
    true = lists:keymember(<<"hij">>, #bitcask_entry.key, List).

keydir_named_test_() ->
    {timeout, 60, fun keydir_named_test2/0}.

keydir_named_test2() ->
    {not_ready, Ref} = keydir_new("k1"),
    ok = keydir_put(Ref, <<"abc">>, 0, 1234, 0, 1),
    keydir_mark_ready(Ref),

    {ready, Ref2} = keydir_new("k1"),
    #bitcask_entry { key = <<"abc">> } = keydir_get(Ref2, <<"abc">>).

keydir_named_not_ready_test_() ->
    {timeout, 60, fun keydir_named_not_ready_test2/0}.

keydir_named_not_ready_test2() ->
    {not_ready, Ref} = keydir_new("k2"),
    ok = keydir_put(Ref, <<"abc">>, 0, 1234, 0, 1),

    {error, not_ready} = keydir_new("k2").

keydir_itr_while_itr_error_test_() ->
    {timeout, 60, fun keydir_itr_while_itr_error_test2/0}.

keydir_itr_while_itr_error_test2() ->
    {ok, Ref1} = keydir_new(),
    {ok, Itr} = keydir_itr(Ref1),
    try
        ?assertEqual({error, iteration_in_process},
                     keydir_itr(Itr))
    after
        keydir_itr_release(Itr)
    end.

keydir_double_itr_test_() -> % check iterating flag is cleared
    {timeout, 60, fun keydir_double_itr_test2/0}.

keydir_double_itr_test2() ->
    {ok, Ref1} = keydir_new(),
    Folder = fun(_,Acc) -> Acc end,
    ?assertEqual(acc, keydir_fold(Ref1, Folder, acc)),
    ?assertEqual(acc, keydir_fold(Ref1, Folder, acc)).

keydir_next_notstarted_error_test_() ->
    {timeout, 60, fun keydir_next_notstarted_error_test2/0}.

keydir_next_notstarted_error_test2() ->
    {ok, Ref1} = keydir_new(),
    ?assertEqual({error, iteration_not_started}, keydir_itr_next(Ref1)).

keydir_del_while_pending_test_() ->
    {timeout, 60, fun keydir_del_while_pending_test2/0}.

keydir_del_while_pending_test2() ->
    Name = "k_del_while_pending_test",
    {not_ready, Ref1} = keydir_new(Name),
    Key = <<"abc">>,
    T = bitcask_time:tstamp() - 10,
    ok = keydir_put(Ref1, Key, 0, 1234, 0, T),
    keydir_mark_ready(Ref1),
    ?assertEqual(#bitcask_entry{key = Key, file_id = 0, total_sz = 1234,
                                offset = <<0:64/unsigned-native>>, tstamp = T},
                 keydir_get_int(Ref1, Key, 16#ffffffffffffffff)),
    {ready, Ref2} = keydir_new(Name),
    try
        %% Start keyfold iterator on Ref2
        {ok, Itr} = keydir_itr(Ref2),
        %% Delete Key
        ?assertEqual(ok, keydir_remove(Ref1, Key)),
        ?assertEqual(not_found, keydir_get(Ref1, Key)),

        %% Keep iterating on Ref2 and check result is [Key]
        Fun = fun(IterKey, Acc) -> [IterKey | Acc] end,
        ?assertEqual([#bitcask_entry{key = Key, file_id = 0, total_sz = 1234,
                                     offset = 0, tstamp = T}],
                     keydir_fold_cont(keydir_itr_next(Itr), Itr, Fun, []))
    after
        %% End iteration
        ok = keydir_itr_release(Itr)
    end,
    %% Check key is deleted
    ?assertEqual(not_found, keydir_get(Ref1, Key)).

keydir_create_del_while_pending_test_() ->
    {timeout, 60, fun keydir_create_del_while_pending_test2/0}.

keydir_create_del_while_pending_test2() ->
    Name = "k_create_del_while_pending_test",
    {not_ready, Ref1} = keydir_new(Name),
    Key = <<"abc">>,
    keydir_mark_ready(Ref1),
    {ready, Ref2} = keydir_new(Name),
    %% Start keyfold iterator on Ref2
    {ok, Itr} = keydir_itr(Ref2),
    try
        %% Delete Key
        ok = keydir_put(Ref1, Key, 0, 1234, 0, 1),
        ?assertEqual(#bitcask_entry{key = Key, file_id = 0, total_sz = 1234,
                                    offset = <<0:64/unsigned-native>>,
                                    tstamp = 1},
                     keydir_get_int(Ref1, Key, 16#ffffffffffffffff)),
        ?assertEqual(ok, keydir_remove(Ref1, Key)),
        ?assertEqual(not_found, keydir_get(Ref1, Key)),

        %% Keep iterating on Ref2 and check result is [] it was started after iter
        Fun = fun(IterKey, Acc) -> [IterKey | Acc] end,
        ?assertEqual([], keydir_fold_cont(keydir_itr_next(Itr), Itr, Fun, []))
    after
        %% End iteration
        ok = keydir_itr_release(Itr)
    end,
    %% Check key is deleted
    ?assertEqual(not_found, keydir_get(Ref1, Key)),
    keydir_release(Ref1),
    keydir_release(Ref2),
    ok.

keydir_del_put_while_pending_test_() ->
    {timeout, 60, fun keydir_del_put_while_pending_test2/0}.

keydir_del_put_while_pending_test2() ->
    Name = "k_del_put_while_pending_test",
    {not_ready, Ref1} = keydir_new(Name),
    Key = <<"abc">>,
    keydir_mark_ready(Ref1),
    {ready, Ref2} = keydir_new(Name),
    T = bitcask_time:tstamp(),
    %% Start keyfold iterator on Ref2
    {ok, Itr} = keydir_itr(Ref2),
    try
        %% Delete Key
        ?assertEqual(ok, keydir_remove(Ref1, Key)),
        ok = keydir_put(Ref1, Key, 0, 1234, 0, T+2),
        ?assertEqual(#bitcask_entry{key = Key, file_id = 0, total_sz = 1234,
                                     offset = <<0:64/unsigned-native>>, tstamp = T+2},
                     keydir_get_int(Ref1, Key, T+2)),

        %% Keep iterating on Ref2 and check result is [] it was started after iter
        Fun = fun(IterKey, Acc) -> [IterKey | Acc] end,
        ?assertEqual([], keydir_fold_cont(keydir_itr_next(Itr), Itr, Fun, []))
    after
        %% End iteration
        ok = keydir_itr_release(Itr)
    end,
    %% Check key is still present
    ?assertEqual(#bitcask_entry{key = Key, file_id = 0, total_sz = 1234,
                                offset = <<0:64/unsigned-native>>, tstamp = T+2},
                 keydir_get_int(Ref1, Key, 16#ffffffffffffffff)).

keydir_multi_put_during_itr_test_() ->
    {timeout, 60, fun keydir_multi_put_during_itr_test2/0}.

keydir_multi_put_during_itr_test2() ->
    {not_ready, Ref} = bitcask_nifs:keydir_new("t"),
    bitcask_nifs:keydir_mark_ready(Ref),
    bitcask_nifs:keydir_put(Ref, <<"k">>, 123, 1, 0, 1),
    {ok, Itr} = bitcask_nifs:keydir_itr(Ref),
    bitcask_nifs:keydir_put(Ref, <<"k">>, 123, 2, 10, 2),
    bitcask_nifs:keydir_put(Ref, <<"k">>, 123, 3, 20, 3),
    bitcask_nifs:keydir_put(Ref, <<"k">>, 123, 4, 30, 4),
    bitcask_nifs:keydir_itr_release(Itr).

keydir_itr_out_of_date_test_() ->
    {timeout, 60, fun keydir_itr_out_of_date_test2/0}.

keydir_itr_out_of_date_test2() ->
    Name = "keydir_itr_out_of_date_test",
    {not_ready, Ref1} = bitcask_nifs:keydir_new(Name),
    bitcask_nifs:keydir_mark_ready(Ref1),
    ok = bitcask_nifs:keydir_itr_int(Ref1, 1000000, 0, 0),
    put_till_frozen(Ref1, Name),
    {ready, Ref2} = bitcask_nifs:keydir_new(Name),
    %% now() will have ensured a new usecs for keydir_itr/3 - check out of date immediately
    ?assertEqual(out_of_date, bitcask_nifs:keydir_itr_int(Ref2, 1000001,
                                                          0, 0)),
    keydir_itr_release(Ref1),
    ?assertEqual(ok, receive
                         ready ->
                             ok
                     after
                         1000 ->
                             timeout
                     end).

put_till_frozen(R, Name) ->
    bitcask_nifs:keydir_put(R, crypto:rand_bytes(32), 0, 1234, 0, 1),
    {ready, Ref2} = bitcask_nifs:keydir_new(Name),
    %%?debugFmt("Putting", []),
    case bitcask_nifs:keydir_itr_int(Ref2, 2000001,
                                     0, 0) of
        ok ->
            %%?debugFmt("keydir still OK", []),
            bitcask_nifs:keydir_itr_release(Ref2),
            put_till_frozen(R, Name);
        out_of_date ->
            %%?debugFmt("keydir now frozen", []),
            bitcask_nifs:keydir_itr_release(Ref2),
            ok
    end.

keydir_itr_many_pending_test_() ->
    {timeout, 60, fun keydir_itr_many_pending_test2/0}.

keydir_itr_many_pending_test2() ->
    Name = "keydir_itr_many_out_of_date_test",
    {not_ready, Ref1} = bitcask_nifs:keydir_new(Name),
    bitcask_nifs:keydir_mark_ready(Ref1),

    ok = bitcask_nifs:keydir_itr_int(Ref1, 1000000, 0, 0),
    put_till_frozen(Ref1, Name),
    Me = self(),
    F = fun() ->
                {ready, Ref2} = bitcask_nifs:keydir_new(Name),
                out_of_date = bitcask_nifs:keydir_itr_int(Ref2, 1000001,
                                                          0, 0),
                Me ! {ready, self()},
                receive
                    ready ->
                        Me ! {done, self()}
                end
        end,
    %% Check the pending_awaken array grows nicely
    Pids = [proc_lib:spawn_link(F) || _X <- lists:seq(1, 100)],
    ?assertEqual(lists:usort([receive {ready, Pid} -> ready
                              after 500 -> {timeout, Pid}
                              end || Pid <- Pids]), [ready]),
    %% Wake them up and check them.
    keydir_itr_release(Ref1),
    ?assertEqual(lists:usort([receive {done, Pid} -> ok
                              after 500 -> {timeout, Pid}
                              end || Pid <- Pids]), [ok]).

clear_recv_buffer(Ct) ->
    receive
        _ ->
            clear_recv_buffer(Ct+1)
    after 0 ->
            ok %%?debugFmt("cleared ~p msgs", [Ct])
    end.


-ifdef(EQC).

-define(POW_2(N), trunc(math:pow(2, N))).

-define(QC_OUT(P),
        eqc:on_output(fun(Str, Args) -> io:format(user, Str, Args) end, P)).

g_uint32() ->
    choose(0, ?POW_2(31)).

g_uint64() ->
    choose(0, ?POW_2(62)).

g_entry() ->
    #bitcask_entry{ key = non_empty(binary()),
                    file_id = g_uint32(),
                    total_sz = g_uint32(),
                    offset = g_uint64(),
                    tstamp = g_uint32() }.

keydir_get_put_prop() ->
    ?FORALL(E, g_entry(),
            begin
                {ok, Ref} = keydir_new(),

                ok = keydir_put(Ref, E#bitcask_entry.key, E#bitcask_entry.file_id,
                                E#bitcask_entry.total_sz, E#bitcask_entry.offset,
                                E#bitcask_entry.tstamp),

                E2 = keydir_get(Ref, E#bitcask_entry.key),
                keydir_release(Ref),
                ?assertEqual(E, E2),
                true
            end).

keydir_get_put_test_() ->
    {timeout, 60, fun() -> eqc:quickcheck(?QC_OUT(keydir_get_put_prop())) end}.

-endif.

-ifdef(TIMING_TEST_NOT_EUNIT_TEST).

-define(YOO_ITERS, 10).
yoo_start_test_() ->
    {timeout, 60, fun() ->
                          io:format(user, "My OS pid is ~s\n", [os:getpid()]),
                          timer:sleep(15*1000)
                  end}.

yoo_test_1M_c1k_d0_() ->
    {timeout, 6666, fun() -> [yoo(1000000, 1000, 0) || _ <- lists:seq(1,?YOO_ITERS)] end}.

yoo_test_1M_c250k_d0_() ->
    {timeout, 6666, fun() -> [yoo(1000000, 250000, 0) || _ <- lists:seq(1,?YOO_ITERS)] end}.

yoo_test_1M_c900k_d0_() ->
    {timeout, 6666, fun() -> [yoo(1000000, 900000, 0) || _ <- lists:seq(1,?YOO_ITERS)] end}.

yoo_test_1M_c0_d1k_() ->
    {timeout, 6666, fun() -> [yoo(1000000, 1000, 0) || _ <- lists:seq(1,?YOO_ITERS)] end}.

yoo_test_1M_c0_d250k_() ->
    {timeout, 6666, fun() -> [yoo(1000000, 250000, 0) || _ <- lists:seq(1,?YOO_ITERS)] end}.

yoo_test_1M_c0_d900k_() ->
    {timeout, 6666, fun() -> [yoo(1000000, 900000, 0) || _ <- lists:seq(1,?YOO_ITERS)] end}.

yoo(NumKeys, NumChange, NumDelete) ->
    _ = (catch folsom:start()),
    timer:sleep(200),
    catch folsom_metrics:delete_metric(foo),
    folsom_metrics:new_histogram(foo, uniform, 9981239823),
    {ok, Ref} = keydir_new(),
    try
        T0 = os:timestamp(),
        [ok = keydir_put(Ref, <<X:32>>, 0, 0, X, 0) ||
            X <- lists:seq(1, NumKeys)],
        T1 = os:timestamp(),
        {ok, Itr} = keydir_itr(Ref),
        T2 = os:timestamp(),
        [ok = keydir_put(Ref, <<X:32>>, 1, 0, X, 0) ||
            X <- lists:seq(1, NumChange)],
        [ok = keydir_remove(Ref, <<X:32>>) ||
            X <- lists:seq(NumKeys - NumDelete, NumKeys)],
        T3 = os:timestamp(),
        ok = keydir_itr_release(Itr),

        %% This method's use of list comprehension + lists:seq(1,LargeNum)
        %% generates enough garbage to cause tail latency outliers
        %% that are really annoying.
        %%
        %% OpList = lists:seq(1, NumKeys),
        %% Get = fun(Seq) ->
        %%               erlang:garbage_collect(),
        %%               dyntrace:pn(0, 1),
        %%               [begin
        %%                    dyntrace:pn(1, 1),
        %%                    %% T4 = os:timestamp(),
        %%                    _ = keydir_get(Ref, <<X:32>>, 1),
        %%                    %% T5 = os:timestamp(),
        %%                    dyntrace:pn(1, 0),
        %%                    %% Elapsed = timer:now_diff(T5, T4),
        %%                    %% dyntrace:pn(900, Elapsed),
        %%                    %% if Elapsed > 16384 -> io:format(user, "16+x", []); Elapsed > 8192 -> io:format(user, "8x", []); Elapsed > 4096 -> io:format(user, "4x", []); Elapsed > 2048 -> io:format(user, "2x", []); Elapsed > 1024 -> io:format(user, "x", []); true -> ok end,
        %%                    %% folsom_metrics_histogram:update(foo, Elapsed)
        %%                    ok
        %%                end || X <- OpList],
        %%               dyntrace:pn(0, 0),
        %%               QQ = folsom_metrics:get_histogram_statistics(foo),
        %%               catch folsom_metrics:delete_metric(foo),
        %%               folsom_metrics:new_histogram(foo, uniform, 9981239823),
        %%               {Seq, [X || X = {Tag, _} <- QQ, Tag == max orelse Tag == percentile]}
        %%       end,

        GetAndTime = fun(X) ->
                             dyntrace:pn(1, 1),
                             %% T4 = os:timestamp(),
                             _ = keydir_get(Ref, <<X:32>>, 1),
                             %% T5 = os:timestamp(),
                             dyntrace:pn(1, 0)
                     end,
        Get = fun(Seq) ->
                      erlang:garbage_collect(),
                      dyntrace:pn(0, 1, Seq),
                      iter(GetAndTime, NumKeys),
                      dyntrace:pn(0, 0, Seq),
                      ok
              end,

        [io:format(user, "~p\n", [Get(Seq)]) || Seq <- lists:seq(1,4)],
        ok
    after
        catch folsom_metrics:delete_metric(foo),
        ok = keydir_release(Ref)
    end.

iter(Fun, 0) ->
    ok;
iter(Fun, N) ->
    Fun(N),
    iter(Fun, N-1).

-endif. % TIMING_TEST_NOT_EUNIT_TEST

-endif. % EQC
