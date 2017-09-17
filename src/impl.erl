-module(impl).

-author("kunal.tyagi").

-import(ssec_base, [gen_salt/1, gen_hash/3, verify_key/3, encrypt_data/2,
                    encrypt_data/3, decrypt_data/2, decrypt_data/3]).

-export([verify_ssec_algorithm/1,
         verify_ssec_key/2,
         test_verification_ssec_key/0]).

verify_ssec_algorithm(Algorithm) ->
    ValidAlgorithms = ["AES256"],
    {lists:member(Algorithm, ValidAlgorithms), ValidAlgorithms}.

verify_ssec_key(ASCIIKey, Checksum) ->
    % is_list(ASCIIKey)?
    Key = base64:decode(ASCIIKey),
    {HashType, ASCIIHash} = Checksum,
    % is_atom(HashValue)?
    % is_list(ASCIIHash)?
    HashValue = base64:decode(ASCIIHash),
    if
        size(Key) /= 256/4 ->
           {false, "Key is not 256 bit long. Provided: " ++ erlang:integer_to_list(size(Key))};
        HashType /= md5 ->
           {false, "MD5 checksum required. Provided: " ++ erlang:atom_to_list(HashType)};
        size(HashValue) /= 128/4 ->
           {false, "MD5 checksum is not 128 bit long. Provided: " ++ erlang:integer_to_list(size(Key))};
        true ->
            Lhs = erlang:binary_to_list(crypto:hash(HashType, Key)),
            Rhs = erlang:binary_to_integer(HashValue, 16),
            Value = lists:foldl(fun(X, Old) -> X + Old*256 end, 0, Lhs) =:= Rhs,
            {Value, "Verification status"}
    end.

test_verification_ssec_key() ->
    Key = "556B58703273357638792F413F4428472B4B6250655368566D59713374367739",
    Checksum = "64C40DC99A6FE92CF3B7CBD5C22D8A13",
    verify_ssec_key(base64:encode(Key), {md5, base64:encode(Checksum)}).

get_operation(ObjectDetails, RequestHeaders) ->
    {Algorithm, Key, Checksum} = RequestHeaders,
    Md5Checksum = {md5, Checksum},
    get_operation({algo, verify_ssec_algorithm(Algorithm)});
get_operation({algo, {AlgoStatus, _AlgoList}}) ->
    if
        AlgoStatus =:= false ->
            {false, "Expected " ++ AlgoList ++ "Provided: " ++ Algorithm};
        true ->
            {KeyStatus, KeyMessage} = verify_ssec_key(Key, Md5Checksum),
            if
                KeyStatus =:= false ->
                    {KeyStatus, Message};
                true ->
                    {Salt, Hash, Data} = getObject(ObjectDetails),
                    ssec_base:verify_key

getObject(ObjectDetails) ->
    {false, "TODO. Not implemented"}.
