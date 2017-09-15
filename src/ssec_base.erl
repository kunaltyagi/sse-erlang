-module(ssec_base).

-author("kunal.tyagi").

-include("eunit/include/eunit.hrl").

-export([gen_salt/1,
         gen_hash/3,
         verify_key/3,
         encrypt_data/2, encrypt_data/3,
         decrypt_data/2, decrypt_data/3,
         test_hash/0,
         test_encryption/0]).

%% @doc generate a random salt
%%
-spec(gen_salt(Length) ->
        {ok, Salt} | {error, ErrorDescription} when Length::integer(),
                                                    Salt::binary(),
                                                    ErrorDescription::string()).
gen_salt(Length) when Length >= 32, Length =< 64 ->
    % erlang:binary_to_list(crypto:strong_rand_bytes(Length)).
    {ok, crypto:strong_rand_bytes(Length)};
gen_salt(Length) when Length < 32 ->
    {error, "Minimum length is 32. Provided: " ++ erlang:integer_to_list(Length)};
gen_salt(Length) ->
    {error, "Maximum length is 64. Provided: " ++ erlang:integer_to_list(Length)}.

%% @doc generate hash of user key using the salt
%%
-spec(gen_hash(Type, UserKey, Salt) ->
        {Type, Mac} when Type::hash_algorithms() - except ripemd160,
                         UserKey::iodata(),
                         Salt::iodata(),
                         Mac::binary()).
hash_algorithms() - except ripemd160
gen_hash(Type, UserKey, Salt) ->
    % save the algorithm used, eg md5, sha, sha256
    {Type, crypto:hmac(Type, Salt, UserKey)}.

%% @doc verify that the userkey and salt combination matches the provided hash
%%
-spec(verify_key(UserKey, Salt, Hash) ->
        true | false when UserKey::iodata(),
                          Salt::iodata(),
                          Hash::{Type, binary()},
                          Type::hash_algorithms() - except ripemd160).
verify_key(UserKey, Salt, Hash) ->
    {HashType, _HashValue} = Hash,
    gen_hash(HashType, UserKey, Salt) =:= Hash.

%% @doc sample implementation for providing custom algorithms to
%%      encrypt and decrypt in a uniform manner
%%
-spec(algo_metadata() ->
        {AlgoType, PadAlgo} where AlgoType = des_ecb | blowfish_ecb | aes_ecb,
                                  PadAlgo = zero | rfc5652).
algo_metadata() ->
    % store details such as 
    % - algorithm to use
    % - use IVec or not
    % - use AEAD mode or not
    % Currently doesn't do anything more than supply the algorithm
    Algo = aes_ecb,
    Pad = rfc5652,
    {Algo, Pad}.

% Integration of block and stream functions not done coz AEAD

%% @doc block encrypt data using the user key
%%
-spec(block_encrypt_data(UserKey, Data, AlgoMetaData) ->
    CipherPadData where UserKey = block_key(),
                        Data = io_data(),
                        AlgoMetaData = algo_metadata(),
                        CipherPadData = binary()).
block_encrypt_data(UserKey, Data) ->
    block_encrypt_data(UserKey, Data, algo_metadata()).
block_encrypt_data(UserKey, Data, AlgoMetaData) ->
    {Algo, Pad} = AlgoMetaData,
    % Technically 16 should also be in metadata?
    PadData = pad(Pad, 16, Data),
    crypto:block_encrypt(Algo, UserKey, PadData).

%% @doc block decrypt data using the user key
%%
-spec(block_decrypt_data(UserKey, Data, AlgoMetaData) ->
        PlainData where UserKey = block_key(),
                        Data = binary(),
                        AlgoMetaData = algo_metadata(),
                        PlainData = iodata()).
block_decrypt_data(UserKey, Data) ->
    block_decrypt_data(UserKey, Data, algo_metadata()).
block_decrypt_data(UserKey, Data, AlgoMetaData) ->
    {Algo, Pad} = AlgoMetaData,
    PadData = crypto:block_decrypt(Algo, UserKey, Data),
    unpad(Pad, PadData).

%% @doc verify that the data is encryted correctly
%%
-spec(verify_block_encryption(Key, Msg, AlgoMetaData) ->
        {true|false, EncryptedMsg} when Key = block_key(),
                                        Msg = io_data(),
                                        AlgoMetaData = algo_metadata(),
                                        EncryptedMsg = binary()).
verify_block_encryption(Key, Msg, AlgoMetaData) ->
    EncryptedMsg = block_encrypt_data(Key, Msg, AlgoMetaData),
    {Msg =:= block_decrypt_data(Key, EncryptedMsg, AlgoMetaData),
         EncryptedMsg}.

test_encryption() ->
    AlgoList = [aes_ecb],
    PadType = [zero, rfc5652],
    {ok, Key} = gen_salt(32),
    Msg = <<"Test Binary Stream">>,
    MetaDataList = [{Algo, Pad} || Algo <- AlgoList, Pad <- PadType],
    lists:all(fun(X) -> verify_encryption(Key, Msg, X) =:= {true, _} end,
              MetaDataList).

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
