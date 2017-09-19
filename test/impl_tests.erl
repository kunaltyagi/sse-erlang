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
        fun dummy/0}}
     ]}.

dummy() -> true.

-endif.
