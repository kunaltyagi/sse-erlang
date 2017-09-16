-module(ssec_tests).

-author("kunal.tyagi").

-include_lib("eunit/include/eunit.hrl").

-ifdef(EUNIT).

%% Test 1
gen_salt_test_() ->
    {setup,
     fun () ->
             ok
     end,
     fun (_) ->
             ok
     end,
     [
      {"test salt/1 fun", {timeout, timer:seconds(1), fun salt/0}},
      {"test hash/3 fun", {timeout, timer:seconds(1), fun hash/0}}
     ]}.

salt() ->
    ?assertEqual(false, ssec:gen_salt(32) == ssec:gen_salt(32)),
    ?assertEqual(true, ssec:gen_salt(32) /= ssec:gen_salt(32)),

    %% @TODO
    %% AlgoList = [aes_ecb],
    %% PadType = [zero, rfc5652],
    %% {ok, Key} = ssec:gen_salt(32),
    %% Msg = <<"Test Binary Stream">>,
    %% MetaDataList = [{Algo, Pad} || Algo <- AlgoList, Pad <- PadType],
    %% lists:all(fun(X) ->
    %%                   ssec:verify_encryption(Key, Msg, X) =:= {true, _}
    %%           end, MetaDataList),

    Key = "556B58703273357638792F413F4428472B4B6250655368566D59713374367739",
    Checksum = "64C40DC99A6FE92CF3B7CBD5C22D8A13",
    Ret_1 = ssec:verify_ssec_key(
              base64:encode(Key),
              {md5, base64:encode(Checksum)}),
    ?assertEqual({true, "Verification status"}, Ret_1),
    ok.


hash() ->
    AlgoList = [md5, sha, sha256],
    {ok, Key} = ssec:gen_salt(64),
    {ok, Salt} = ssec:gen_salt(32),
    HashList = [ssec:gen_hash(Algo, Key, Salt) || Algo <- AlgoList],
    ?assertEqual(true, (lists:all(
                          fun(X) ->
                                  ssec:verify_key(Key, Salt, X) =:= true
                          end, HashList))),
    ok.


-endif.
