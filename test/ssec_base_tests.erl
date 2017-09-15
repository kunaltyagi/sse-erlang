-module(ssec_base_tests).

-author("kunal.tyagi").

-include_lib("eunit/include/eunit.hrl").

-import(ssec_base, [gen_salt/1]).

gen_salt_test_() ->
    [?_assert(gen_salt(32) == gen_salt(32)),
     ?_assert(gen_salt(32) /= gen_salt(32))].
     
