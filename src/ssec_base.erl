-module(ssec_base).

-author("kunal.tyagi").

-export([gen_salt/1,
         gen_hash/3,
         verify_key/3,
         encrypt_data/2, encrypt_data/3,
         decrypt_data/2, decrypt_data/3,
         test_hash/0,
         test_encryption/0]).

-import(crypto, [strong_rand_bytes/1, hmac/3,
                 block_encrypt/3, block_decrypt/3]).

gen_salt(Length) when Length >= 32, Length =< 64 ->
    % erlang:binary_to_list(crypto:strong_rand_bytes(Length)).
    {ok, crypto:strong_rand_bytes(Length)};
gen_salt(Length) when Length < 32 ->
    throw({error, "Minimum length is 32. Provided: " ++ erlang:integer_to_list(Length)});
gen_salt(Length) ->
    throw({error, "Maximum length is 64. Provided: " ++ erlang:integer_to_list(Length)}).

gen_hash(Type, UserKey, Salt) ->
    % save the algorithm used, eg md5, sha, sha256
    {Type, crypto:hmac(Type, Salt, UserKey)}.

verify_key(UserKey, Salt, Hash) ->
    {HashType, _HashValue} = Hash,
    gen_hash(HashType, UserKey, Salt) =:= Hash.

test_hash() ->
    AlgoList = [md5, sha, sha256],
    {ok, Key} = gen_salt(64),
    {ok, Salt} = gen_salt(32),
    HashList = [gen_hash(Algo, Key, Salt) || Algo <- AlgoList],
    lists:all(fun(X) -> verify_key(Key, Salt, X) =:= true end, HashList).

algo_metadata() ->
    % store details such as 
    % - algorithm to use
    % - use IVec or not
    % - use AEAD mode or not
    % Currently doesn't do anything more than supply the algorithm
    Algo = aes_ecb,
    Pad = rfc5652,
    {Algo, Pad}.

encrypt_data(UserKey, Data) ->
    encrypt_data(UserKey, Data, algo_metadata()).
encrypt_data(UserKey, Data, AlgoMetaData) ->
    {Algo, Pad} = AlgoMetaData,
    % Technically 16 should also be in metadata?
    PadData = pad(Pad, 16, Data),
    crypto:block_encrypt(Algo, UserKey, PadData).

decrypt_data(UserKey, Data) ->
    decrypt_data(UserKey, Data, algo_metadata()).
decrypt_data(UserKey, Data, AlgoMetaData) ->
    {Algo, Pad} = AlgoMetaData,
    PadData = crypto:block_decrypt(Algo, UserKey, Data),
    unpad(Pad, PadData).

verify_encryption(Key, Msg, AlgoMetaData) ->
    EncryptedMsg = encrypt_data(Key, Msg, AlgoMetaData),
    Msg =:= decrypt_data(Key, EncryptedMsg, AlgoMetaData).

test_encryption() ->
    AlgoList = [aes_ecb],
    PadType = [zero, rfc5652],
    {ok, Key} = gen_salt(32),
    Msg = <<"Test Binary Stream">>,
    MetaDataList = [{Algo, Pad} || Algo <- AlgoList, Pad <- PadType],
    lists:all(fun(X) -> verify_encryption(Key, Msg, X) =:= true end, MetaDataList).

pad(zero, Width, Binary) ->
    pad_zero(Width, Binary);
pad(rfc5652, Width, Binary) ->
    pad_rfc5652(Width, Binary).

unpad(zero, Binary) ->
    unpad_zero(Binary);
unpad(rfc5652, Binary) ->
    unpad_rfc5652(Binary).

% Alternative pad implementation:
% Pad with symbol X for Y times
% pad_rfc5652/3 does this, but don't use it to pad with zeroes
% Alternative Unpad implementation not done to prevent misuse

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
