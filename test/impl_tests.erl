-module(impl_tests).

-author("kunal.tyagi").

-include_lib("eunit/include/eunit.hrl").

-ifdef(TEST).
-spec test() -> term(). %% SRSLY can we do better?
-endif.

-ifdef(EUNIT).

-spec(run_test_() -> true|false).
run_test_() ->
    {setup,
     fun()  -> ok end,
     fun(_) -> ok end,
     [
      {"test gen_salt/1 for input 1...100",
       {timeout, timer:seconds(1),
        fun test_verification_ssec_key/0}}
     ]}.

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
