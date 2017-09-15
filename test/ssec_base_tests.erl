-module(ssec_base_tests).

-author("kunal.tyagi").

-include_lib("eunit/include/eunit.hrl").

-ifdef(EUNIT).

%% Test 1
gen_salt_test_() ->
    [?_assert(gen_salt(32) == gen_salt(32)),
     ?_assert(gen_salt(32) /= gen_salt(32))].
     
hash_test_() ->
    [
     fun()->
         AlgoList = [md5, sha, sha256],
         {ok, Key} = gen_salt(64),
         {ok, Salt} = gen_salt(32),
         HashList = [gen_hash(Algo, Key, Salt) || Algo <- AlgoList],
         ?_assert(lists:all(fun(X) -> verify_key(Key, Salt, X) =:= true end, HashList))
     end
    ].

-endif.
