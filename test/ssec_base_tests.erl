-module(ssec_base_tests).

-author("kunal.tyagi").

-include_lib("eunit/include/eunit.hrl").

-ifdef(TEST).
-spec test() -> term(). %% SRSLY can we do better?
-endif.

-ifdef(EUNIT).

%% @doc wrapper to iterate and check from Max to Min (inclusive)
%% @private
check_wrapper(Fn, MinValue, MaxValue) when MaxValue >= MinValue ->
    Fn(MaxValue),
    check_wrapper(Fn, MinValue, MaxValue - 1);
check_wrapper(_Fn, _MinValue, _MaxValue) ->
    true.

-spec(run_test_() -> true|false).
run_test_() ->
    {setup,
     fun()  -> ok end,
     fun(_) -> ok end,
     [
      {"test gen_salt/1 for input 1...100",
       {timeout, timer:seconds(1),
        fun() -> check_wrapper(fun check_salt/1, 1, 100) end}},
      {"test gen_hash/1 for salt size 32...64, key 64",
       {timeout, timer:seconds(1),
        fun() -> check_wrapper(fun check_hash/1, 32, 64) end}}
      {"test gen_salt/1 for input 1...100",
       {timeout, timer:seconds(1), fun test_verification_ssec_key/0}}
     ]}.

%% Test 1
check_salt(Len) when Len >= 32, Len =< 64 ->
%    ?assertMatch({ok, _}, ssec_base:gen_salt(Len)),
    ?assertNotEqual(ssec_base:gen_salt(Len), ssec_base:gen_salt(Len));
check_salt(Len) ->
    ?assertMatch({error, _}, ssec_base:gen_salt(Len)).

%% Test 2
check_hash(Len) ->
    AlgoList = [md5, sha, sha256],
    {ok, Key} = ssec_base:gen_salt(64),
    {ok, Salt} = ssec_base:gen_salt(Len),
    HashList = lists:map(fun(Algo) -> ssec_base:gen_hash(Algo, Key, Salt) end, AlgoList),
    ?assert(lists:all(fun(Hash) -> ssec_base:verify_key(Key, Salt, Hash) =:= true end, HashList)).


%% Test 3
%verify_block_encryption_test_() ->
%    [
%     fun() ->
%         AlgoList = [aes_ecb],
%         PadType = [zero, rfc5652],
%         {ok, Key} = ssec_base:gen_salt(32),
%         Msg = <<"Test Binary Stream">>,
%         MetaDataList = [{Algo, Pad} || Algo <- AlgoList, Pad <- PadType],
%         lists:all(fun(X) -> {true, _} =:= ssec_base:verify_block_encryption(Key, Msg, X) end,
%             MetaDataList)
%     end
%    ].

test_verification_ssec_key() ->
    Key = "556B58703273357638792F413F4428472B4B6250655368566D59713374367739",
    Checksum1 = "64C40DC99A6FE92CF3B7CBD5C22D8A13",
    ?assertMatch({true, _}, verify_ssec_key(base64:encode(Key),
                                {md5, base64:encode(Checksum1)})).
    Checksum2 = lists::droplast(Checksum1) ++ "5".
    ?assertMatch({false, _}, verify_ssec_key(base64:encode(Key),
                                {md5, base64:encode(Checksum2)})).
    ?assertMatch({false, _}, verify_ssec_key(base64:encode(lists:droplast(Key)),
                                {md5, base64:encode(Checksum2)})).
    ?assertMatch({false, _}, verify_ssec_key(base64:encode(Key),
                                {md5, base64:encode(lists:droplast(Checksum2))})).

-endif.
