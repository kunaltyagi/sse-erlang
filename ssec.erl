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
    PadData = crypto:block_decrypt(Algo, UserKey, Data),
    unpad_rfc5652(PadData).

pad_zero(Width, Binary) ->
    case (Width - (size(Binary) rem Width)) rem Width of
        0 -> Binary;
        N -> <<Binary/binary, 0:(N*8)>> % 8 bits in one byte
    end.

unpad_zero(Binary) ->
  unpad_zero(Binary, size(Binary) - 1).

unpad_zero(_Binary, -1) ->
  <<>>;
unpad_zero(Binary, Idx) ->
  case binary:at(Binary, Idx) of
    0 -> unpad_zero(Binary, Idx - 1);
    _ -> binary:part(Binary, 0, Idx + 1)
  end.

pad_rfc5652(Width, Binary) ->
    case (Width - (size(Binary) rem Width)) rem Width of
        0 -> pad_rfc5652(Width, Width, Binary);
        N -> pad_rfc5652(N, N, Binary)
    end.

pad_rfc5652(_OrigWidth, 0, Binary) ->
    Binary;
pad_rfc5652(OrigWidth, Length, Binary) ->
    pad_rfc5652(OrigWidth, Length-1, <<Binary/binary, OrigWidth:8>>).


unpad_rfc5652(Binary) ->
    Size = size(Binary),
    Last = binary:at(Binary, Size - 1),
    Suffix = binary:part(Binary, Size, -1 * Last),
    case lists:all(fun(X) -> X =:= Last end, binary:bin_to_list(Suffix)) of
        true -> binary:part(Binary, 0, Size - Last);
        false -> Binary
    end.
