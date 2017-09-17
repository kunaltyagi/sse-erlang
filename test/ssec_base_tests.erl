-module(ssec_base_tests).

-author("kunal.tyagi").

-include_lib("eunit/include/eunit.hrl").

-ifdef(EUNIT).

%% Test 1
gen_salt_test_() ->
    [
     check_salt_wrapper(100)
    ].
check_salt_wrapper(-1) ->
    true;
check_salt_wrapper(X) when X >= 0 ->
    check_salt(X),
    check_salt_wrapper(X - 1).

check_salt(0) ->
    true.
check_salt(X) when X >= 32, X =< 64 ->
    ?_assert(gen_salt(X) = {ok, _}),
    ?_assert(gen_salt(X) /= gen_salt(X));
check_salt(X) ->
    ?_assert(gen_salt(X) = {error, _}).

%% Test 2
gen_hash_test_() ->
    [
     fun() ->
         AlgoList = [md5, sha, sha256],
         {ok, Key} = gen_salt(64),
         {ok, Salt} = gen_salt(32),
         HashList = [gen_hash(Algo, Key, Salt) || Algo <- AlgoList],
         ?_assert(lists:all(fun(X) -> verify_key(Key, Salt, X) =:= true end, HashList))
     end
    ].

%% Test 3
verify_encryption_test_() ->
    [
     fun() ->
         AlgoList = [aes_ecb],
         PadType = [zero, rfc5652],
         {ok, Key} = gen_salt(32),
         Msg = <<"Test Binary Stream">>,
         MetaDataList = [{Algo, Pad} || Algo <- AlgoList, Pad <- PadType],
         lists:all(fun(X) -> verify_encryption(Key, Msg, X) =:= {true, _} end,
             MetaDataList).

-endif.
