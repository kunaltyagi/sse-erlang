-module(ssec).

-export([gen_salt/1,
         gen_hash/3,
         verify_key/3,
         encrypt_data/2,
         decrypt_data/2]).

-import(crypto, [strong_rand_bytes/1]).

gen_salt(Length) when Length >= 32, Length =< 64 ->
    % erlang:binary_to_list(crypto:strong_rand_bytes(Length)).
    crypto:strong_rand_bytes(Length);
gen_salt(Length) when Length < 32 ->
    {error, "Minimum length is 32. Provided: " ++ erlang:integer_to_list(Length)};
gen_salt(Length) ->
    {error, "Maximum length is 64. Provided: " ++ erlang:integer_to_list(Length)}.

gen_hash(Type, UserKey, Salt) ->
    % save the algorithm used, eg md5, sha, sha256
    {Type, crypto:hmac(Type, Salt, UserKey)}.

verify_key(UserKey, Salt, Hash) ->
    {HashType, _HashValue} = Hash,
    gen_hash(HashType, UserKey, Salt) =:= Hash.

algo_metadata() ->
    % store details such as 
    % - algorithm to use
    % - use IVec or not
    % - use AEAD mode or not
    % Currently doesn't do anything more than supply the algorithm
    Algo = aes_ecb,
    {Algo}.

encrypt_data(UserKey, Data) ->
    Algo = element(1, algo_metadata()),
    PadData = pad_rfc5652(16, Data),
    crypto:block_encrypt(Algo, UserKey, PadData).

decrypt_data(UserKey, Data) ->
    Algo = element(1, algo_metadata()),
    crypto:block_decrypt(Algo, UserKey, Data).

pad_zero(Width, Binary) ->
    case (Width - (size(Binary) rem Width)) rem Width of
        0 -> Binary;
        N -> <<Binary/binary, 0:(N*8)>> % 8 bits in one byte
    end.

pad_rfc5652(Width, Binary) ->
    case (Width - (size(Binary) rem Width)) rem Width of
        0 -> pad_rfc5652(Width, Width, Binary);
        N -> pad_rfc5652(N, N, Binary)
    end.

pad_rfc5652(OrigWidth, Length, Binary) when Length > 0 ->
    pad_rfc5652(OrigWidth, Length-1, <<Binary/binary, OrigWidth:8>>);
pad_rfc5652(_, 0, Binary) ->
    Binary.
