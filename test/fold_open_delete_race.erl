%% -------------------------------------------------------------------
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
-module(fold_open_delete_race).

-ifdef(TEST).
-compile(export_all).
-include_lib("eunit/include/eunit.hrl").
-include_lib("kernel/include/file.hrl").

demonstration_test_() ->
    {timeout, 60, fun test_body/0}.

test_body() ->
    ?debugMsg("Fold open/delete race demonstration"),
    Dir = "/tmp/bc.fold.open.del.race",
    % Write some values
    ?debugMsg("Writing values"),
    Keys = lists:sort([integer_to_binary(N) || N <- lists:seq(1,10)]),
    DataSet = [{K, <<>>} || K <- Keys],
    B0 = bitcask:init_dataset(Dir, [{max_file_size, 1}], DataSet),
    ok = bitcask:close(B0),
    Parent = self(),
    application:set_env(bitcask, test_master_pid, Parent),
    ?debugMsg("Starting fold in another process\n"),
    % Start a fold in a different process
    spawn_link(fun() ->
                       B1 = bitcask:open(Dir, []),
                       KAcc = fun(K, _V, Acc) -> [K | Acc] end,
                       ActualKeys = bitcask:fold(B1, KAcc, []),
                       ?debugFmt("Got keys ~p", [ActualKeys]),
                       Parent ! {keys, ActualKeys},
                       ok = bitcask:close(B1)
               end),
    FolderPid = receive
                    {ready_to_open_fold_files, SentPid} ->
                        SentPid
                after
                    10000 ->
                        ?assert(timeout_on_fold_open)
                end,
    [F1|_] = bitcask:list_data_files(Dir, undefined, undefined),
    ?debugMsg("Merge that shit\n"),
    % Merge all existing files
    ok = bitcask:merge(Dir),
    ?debugFmt("Waiting for ~s to be deleted\n", [F1]),
    % Wait for some deletes to happen
    FileIsGone = fun() -> not filelib:is_regular(F1) end,
    ?assertEqual(ok, wait_until(FileIsGone, 10000, 100)),
    ?debugMsg("Release that fold!\n"),
    % Release fold
    FolderPid ! open_fold_files,
    ?debugMsg("Verify fold results\n"),
    % Verify fold results
    receive
        {keys, ActualKeys} ->
            ?assertEqual(Keys, lists:sort(ActualKeys))
    after
        30000 ->
            ?assert(timeout_waiting_for_fold_keys)
    end.

wait_until(_, TimeOut, _) when TimeOut =< 0 ->
   timeout;
wait_until(F, Timeout, Step) ->
    case F() of
        true ->
            ok;
        false ->
            timer:sleep(Step),
            wait_until(F, Timeout - Step, Step)
    end.

-endif.

