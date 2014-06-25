%% -*- erlang -*-

-mode(compile).

%%% stuff cribbed from develop at
%%% 5ff44fc6ea54605f24021989bc77195066744374 should be updated when
%%% stuff changes

-include_lib("kernel/include/file.hrl").

-define(TOMBSTONE, <<"bitcask_tombstone">>).

-define(OFFSETFIELD,  64).
-define(TSTAMPFIELD,  32).
-define(KEYSIZEFIELD, 16).
-define(TOTALSIZEFIELD, 32).
-define(VALSIZEFIELD, 32).
-define(CRCSIZEFIELD, 32).
-define(HEADER_SIZE,  14). % 4 + 4 + 2 + 4 bytes


main([Dir|Rest]) ->
    case Rest of
        [Filter] ->
            {value, Val, []} = eval(Filter++"."),
            put(filter, Val);
        [] -> ok
    end,
    case file:list_dir(Dir) of
        {ok, Files} ->
            dump_files(Dir, Files);
        {error, enoent} ->
            io:format("bad dir ~n")
    end.

eval(S) ->
    eval(S, []).

eval(S,Environ) ->
    {ok,Scanned,_} = erl_scan:string(S),
    {ok,Parsed} = erl_parse:parse_exprs(Scanned),
    erl_eval:exprs(Parsed,Environ).


dump_files(Dir, Files0) ->
    Files = group_files(Files0),
    %% io:format("files: ~p ~n", [Files]),
    [begin
         Dead = has_setuid_bit(Dir++"/"++Datafile),
         dump_hintfile(Dir++"/"++Hintfile, Dead),
         dump_datafile(Dir++"/"++Datafile, Dead)
     end
     || {Hintfile, Datafile} <- Files].

dump_hintfile(Name, Dead) ->
    case Dead of
        true ->
            io:format("** dumping dead hintfile ~p ~n", [Name]);
        false ->
            io:format("dumping hintfile ~p ~n", [Name])
    end,
    %% this assumes small files or big memory
    {ok, FileBin} = file:read_file(Name),
    dump_hints(FileBin, Dead).

dump_hints(<<>>, _Dead) ->
    ok;
dump_hints(<<0:?TSTAMPFIELD, KeySz:?KEYSIZEFIELD,
             _TotalSz:?TOTALSIZEFIELD, _Offset:?OFFSETFIELD,
             _Key:KeySz/bytes, _Rest/binary>>,
           _Dead) ->
    %% this is when we hit the CRC, so we're done
    ok;
dump_hints(<<Tstamp:?TSTAMPFIELD, KeySz:?KEYSIZEFIELD,
             _TotalSz:?TOTALSIZEFIELD, Offset:?OFFSETFIELD,
             Key:KeySz/bytes, Rest/binary>>,
           Dead) ->
    Prefix =
        case Dead of
            true ->
                "** ";
            false -> 
                ""
        end,
    case get(filter) of
        undefined ->
            io:format(Prefix++"timestamp: ~p key: ~p ~n", [Tstamp, Key]);
        Key ->
            io:format(Prefix++"timestamp: ~p key: ~p offset ~p ~n", 
                      [Tstamp, Key, Offset]);
        _ -> ok
    end,
    dump_hints(Rest, Dead).

dump_datafile(Name, Dead) ->
    case Dead of
        true ->
            io:format("** dumping dead datafile ~p ~n", [Name]);
        false ->
            io:format("dumping datafile ~p ~n", [Name])
    end,
    %% this assumes small files or big memory
    {ok, FileBin} = file:read_file(Name),
    dump_data(FileBin, Dead).

dump_data(<<>>, _Dead) ->
    ok;
dump_data(<<_Crc32:?CRCSIZEFIELD, Tstamp:?TSTAMPFIELD, 
            KeySz:?KEYSIZEFIELD, ValueSz:?VALSIZEFIELD, 
            Key:KeySz/bytes, Value:ValueSz/bytes, Rest/binary>>,
          Dead) ->
    Prefix =
        case Dead of
            true ->
                "** ";
            false -> 
                ""
        end,
    case get(filter) of
        undefined ->
            io:format(Prefix++"timestamp: ~p key: ~p ~n", [Tstamp, Key]),
            case Value of
                ?TOMBSTONE ->
                    io:format(Prefix++"is tombstone ~n");
                _ ->
                    io:format(Prefix++"value size is ~p~n", [ValueSz])
            end;
        Key ->
            io:format(Prefix++"timestamp: ~p key: ~p ~n", [Tstamp, Key]),
            case Value of
                ?TOMBSTONE ->
                    io:format(Prefix++"is tombstone ~n");
                _ ->
                    io:format(Prefix++"value size is ~p~n", [ValueSz])
            end;
        _ -> ok
    end,

    dump_data(Rest, Dead).

group_files(Files) ->
    group_files(Files, {1000000000000000000000, 0}).

group_files([], Acc) ->
    %% io:format("building groups ~n"),
    build_groups(Acc);
group_files([File|Rest], {Min, Max} = Acc) ->
    {Tstamp, Type} = file_tstamp(File),
    case Tstamp of
        -1 ->
            group_files(Rest, Acc);
        _ ->
            case get(Tstamp) of
                undefined ->
                    put(Tstamp, Type);
                Type ->
                    halt(duplicate_tstamp);
                both ->
                    halt(duplicate_tstamp);
                hint -> %% seen hint, but we're data
                    put(Tstamp, both);
                data -> %% seen data, but we're hint
                    put(Tstamp, both)
            end,
            group_files(Rest, {min(Min, Tstamp),
                               max(Max, Tstamp)})
    end.

build_groups({Min, Max}) ->
    [I || I <- [set(N) || N <- lists:seq(Min, Max)],
          I /= none].
          
set(I) ->
    L = integer_to_list(I),
    H = L ++ ".bitcask.hint",
    D = L ++ ".bitcask.data",
    case get(I) of
        undefined ->
            none;
        both ->
            {H, D};
        hint ->
            {H, missing};
        data ->
            {missing, D}
    end.

has_setuid_bit(File) ->
    {ok, FI} = file:read_file_info(File),
    FI#file_info.mode band 8#4000 == 8#4000.

%% need to filter lockfiles and other files here
file_tstamp(Filename) when is_list(Filename) ->
    try
        try 
            {list_to_integer(filename:basename(Filename, ".bitcask.data")),
             data}
        catch _:_ ->
                {list_to_integer(filename:basename(Filename, ".bitcask.hint")),
                 hint}
        end
    catch _:_ ->
            {-1, none}
    end.
