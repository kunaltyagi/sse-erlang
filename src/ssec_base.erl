-module(ssec_base).

-author("kunal.tyagi").

-ifdef(TEST).
-include("eunit/include/eunit.hrl").
-endif().

-export([gen_salt/1,
         gen_hash/3,
         verify_key/3,
         verify_block_encryption/3, verify_stream_encryption/3,
         block_encrypt_data/2, block_encrypt_data/3,
         block_decrypt_data/2, block_decrypt_data/3,
         stream_encrypt_data/2, stream_encrypt_data/3,
         stream_decrypt_data/2, stream_decrypt_data/3,
         stream_encrypt_data/4, stream_decrypt_data/4
        ]).

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
        {Type, Mac} when Type::crypto:hash_algorithms(),
                         %% except ripemd160,
                         UserKey::iodata(),
                         Salt::iodata(),
                         Mac::binary()).
gen_hash(Type, UserKey, Salt) ->
    % save the algorithm used, eg md5, sha, sha256
    {Type, crypto:hmac(Type, Salt, UserKey)}.

%% @doc verify that the userkey and salt combination matches the provided hash
%%
-spec(verify_key(UserKey, Salt, Hash) ->
        true | false when UserKey::iodata(),
                          Salt::iodata(),
                          Hash::{Type, binary()},
                          Type::crypto:hash_algorithms()).
                          %% except ripemd160
verify_key(UserKey, Salt, Hash) ->
    {HashType, _HashValue} = Hash,
    gen_hash(HashType, UserKey, Salt) =:= Hash.

%% @doc sample implementation for providing custom algorithms to
%%      encrypt and decrypt in a uniform manner. Use proper algorithm type for
%%      block and stream functions
%%
-spec(algo_metadata() ->
        {AlgoType, PadAlgo} when AlgoType::rc4|des_ecb|blowfish_ecb|aes_ecb,
                                  PadAlgo::zero|rfc5652).
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

%% @doc block encrypt data using the user key and default settings
%%
-spec(block_encrypt_data(UserKey, Data) ->
        CipherPadData when UserKey::crypto:block_key(),
                            Data::crypto:io_data(),
                            CipherPadData::binary()).
block_encrypt_data(UserKey, Data) ->
    block_encrypt_data(UserKey, Data, algo_metadata()).

%% @doc block encrypt data using the user key and custom settings
%%
-spec(block_encrypt_data(UserKey, Data, AlgoMetaData) ->
        CipherPadData when UserKey::crypto:block_key(),
                            Data::crypto:io_data(),
                            AlgoMetaData::algo_metadata(),
                            CipherPadData::binary()).
block_encrypt_data(UserKey, Data, AlgoMetaData) ->
    {Algo, Pad} = AlgoMetaData,
    % Technically 16 should also be in metadata?
    PadData = pad(Pad, 16, Data),
    crypto:block_encrypt(Algo, UserKey, PadData).

%% @doc stream encrypt data using the user key and settings (no default)
%%
-spec(stream_encrypt_data(UserKey, Data, AlgoMetaData) ->
        {State, CipherData} when UserKey::{key, crypto:io_data()} | State,
                                  Data::crypto:io_data(),
                                  AlgoMetaData::algo_metadata(),
                                  State::{state, crypto:opaque()},
                                  CipherData::binary()).
stream_encrypt_data({state, OldState}, Data) ->
    {NewStream, CipherData} = crypto:stream_encrypt(OldState, Data),
    {{state, NewStream}, CipherData};
stream_encrypt_data({key, UserKey}, Data) ->
    stream_encrypt_data({key, UserKey}, Data, algo_metadata()).
stream_encrypt_data({key, UserKey}, Data, AlgoMetaData) ->
    {Algo, _} = AlgoMetaData,
    stream_encrypt_data({state, crypto:stream_init(Algo, UserKey)}, Data).

%% @doc stream encrypt data using the user key and init vector
%%
-spec(stream_encrypt_data(UserKey, Data, IVec, AlgoMetaData) ->
        {State, CipherData} when UserKey::{key, crypto:io_data()},
                                  Data::crypto:io_data(),
                                  IVec::binary(),
                                  AlgoMetaData::algo_metadata(),
                                  State::{state, crypto:opaque()},
                                  CipherData::binary()).
%stream_encrypt_data({key, UserKey}, Data, IVec) ->
%    stream_encrypt_data(UserKey, Data, IVec, algo_metadata()).
stream_encrypt_data({key, UserKey}, Data, IVec, AlgoMetaData) ->
    {Algo, _} = AlgoMetaData,
    stream_encrypt_data({state, crypto:stream_init(Algo, UserKey, IVec)}, Data).

%% @doc block decrypt data using the user key
%%
-spec(block_decrypt_data(UserKey, Data, AlgoMetaData) ->
        PlainData when UserKey::crypto:block_key(),
                        Data::binary(),
                        AlgoMetaData::algo_metadata(),
                        PlainData::iodata()).
block_decrypt_data(UserKey, Data) ->
    block_decrypt_data(UserKey, Data, algo_metadata()).
block_decrypt_data(UserKey, Data, AlgoMetaData) ->
    {Algo, Pad} = AlgoMetaData,
    PadData = crypto:block_decrypt(Algo, UserKey, Data),
    unpad(Pad, PadData).

%% @doc stream decrypt data using the user key
%%
-spec(stream_decrypt_data(UserKey, Data, AlgoMetaData) ->
        {State, CipherData} when UserKey::{key, crypto:io_data()} | State,
                                  Data::crypto:io_data(),
                                  AlgoMetaData::algo_metadata(),
                                  State::{state, crypto:opaque()},
                                  CipherData::binary()).
stream_decrypt_data({state, OldState}, Data) ->
    crypto:stream_decrypt(OldState, Data);
stream_decrypt_data({key, UserKey}, Data) ->
    stream_decrypt_data(UserKey, Data, algo_metadata()).
stream_decrypt_data({key, UserKey}, Data, AlgoMetaData) ->
    {Algo, _} = AlgoMetaData,
    stream_decrypt_data({state, crypto:stream_init(Algo, UserKey)}, Data).

%% @doc stream decrypt data using the user key and init vector
%%
-spec(stream_decrypt_data(UserKey, Data, IVec, AlgoMetaData) ->
        {State, CipherData} when UserKey::{key, crypto:io_data()} | State,
                                  Data::crypto:io_data(),
                                  IVec::binary(),
                                  AlgoMetaData::algo_metadata(),
                                  State::{state, crypto:opaque()},
                                  CipherData::binary()).
%stream_decrypt_data({key, UserKey}, Data, IVec) ->
%    stream_decrypt_data(UserKey, Data, IVec, algo_metadata()).
stream_decrypt_data({key, UserKey}, Data, IVec, AlgoMetaData) ->
    {Algo, _} = AlgoMetaData,
    stream_decrypt_data({state, crypto:stream_init(Algo, UserKey, IVec)}, Data).

%% @doc verify that block data is encrypted correctly
%%
-spec(verify_block_encryption(Key, Msg, AlgoMetaData) ->
        {Status, EncryptedMsg} when Key::crypto:block_key(),
                                    Msg::crypto:io_data(),
                                    AlgoMetaData::algo_metadata(),
                                    Status::true|false,
                                    EncryptedMsg::binary()).
verify_block_encryption(Key, Msg, AlgoMetaData) ->
    EncryptedMsg = block_encrypt_data(Key, Msg, AlgoMetaData),
    {Msg =:= block_decrypt_data(Key, EncryptedMsg, AlgoMetaData),
         EncryptedMsg}.

-spec(verify_stream_encryption(Key, Msg, AlgoMetaData) ->
        {Status, EncryptedMsg} when Key::crypto:stream_key(),
                                    Msg::crypto:io_data(),
                                    AlgoMetaData::algo_metadata(),
                                    Status::true|false,
                                    EncryptedMsg::binary()).
%% @doc verify that stream data is encrypted correctly
verify_stream_encryption(_Key, _Msg, _AlgoMetaData) ->
    {false, "@TODO not implemented yet"}.

%% @doc pad binary data
%%
-spec(pad(zero|rfc5652, Width, Binary) ->
        PaddedBinary when Width::integer(),
                          Binary::binary(),
                          PaddedBinary::binary()).
pad(zero, Width, Binary) ->
    pad_zero(Width, Binary);
pad(rfc5652, Width, Binary) ->
    pad_rfc5652(Width, Binary).

%% @doc unpad binary data
%%
-spec(unpad(zero|rfc5652, Binary) ->
        UnpaddedBinary when Binary::binary(),
                            UnpaddedBinary::binary()).
unpad(zero, Binary) ->
    unpad_zero(Binary);
unpad(rfc5652, Binary) ->
    unpad_rfc5652(Binary).

% Alternative pad implementation:
% Pad with symbol X for Y times
% pad_rfc5652/3 does this, but don't use it to pad with zeroes
% Alternative Unpad implementation not done to prevent misuse

%% @doc pad data with zeroes at the end
%% @private
-spec(pad_zero(Width, Binary) ->
        PaddedBinary when Width::integer(),
                          Binary::binary(),
                          PaddedBinary::binary()).
pad_zero(Width, Binary) when Width /= 0 ->
    case (Width - (size(Binary) rem Width)) rem Width of
        0 -> Binary;
        N -> <<Binary/binary, 0:(N*8)>> % 8 bits in one byte
    end.

%% @doc unpad zeroes from end of data
%%      Handles empty binaries
%%      @see unpad_zero/2
%% @private
-spec(unpad_zero(Binary) ->
        UnpaddedBinary when Binary::binary(),
                            UnpaddedBinary::binary()).
unpad_zero(Binary) ->
  unpad_zero(Binary, size(Binary) - 1).

%% @doc unpad zeroes by counting them
%% @private
-spec(unpad_zero(Binary, Idx) ->
        UnpaddedBinary when Binary::binary(),
                            Idx::integer(),
                            UnpaddedBinary::binary()).
unpad_zero(_Binary, -1) ->
  <<>>;
unpad_zero(Binary, Idx) when Idx > -1 ->
  case binary:at(Binary, Idx) of
    0 -> unpad_zero(Binary, Idx - 1);
    _ -> binary:part(Binary, 0, Idx + 1)
  end.

%% @doc pad data padded a per RFC5652
%%      @see pad_rfc5652/3
%% @private
-spec(pad_rfc5652(Width, Binary) ->
        PaddedBinary when Width::integer(),
                          Binary::binary(),
                          PaddedBinary::binary()).
pad_rfc5652(Width, Binary) when Width /= 0 ->
    case (Width - (size(Binary) rem Width)) rem Width of
        0 -> pad_rfc5652(Width, Width, Binary);
        N -> pad_rfc5652(N, N, Binary)
    end.

%% @doc pads by appending one byte at a time till Length bytes are added
%% @private
-spec(pad_rfc5652(OrigWidth, Length, Binary) ->
        PaddedBinary when OrigWidth::integer(),
                          Length::integer(),
                          Binary::binary(),
                          PaddedBinary::binary()).
pad_rfc5652(_OrigWidth, 0, Binary) ->
    Binary;
pad_rfc5652(OrigWidth, Length, Binary) ->
    pad_rfc5652(OrigWidth, Length - 1, <<Binary/binary, OrigWidth:8>>).

%% @doc unpad data padded a per RFC5652
%%      Can't take empty bianries as input coz invalid input
%% @private
-spec(unpad_rfc5652(Binary) ->
        UnpaddedBinary when Binary::binary(),
                            UnpaddedBinary::binary()).
unpad_rfc5652(Binary) ->
    Size = size(Binary),
    Last = binary:at(Binary, Size - 1),
    Suffix = binary:part(Binary, Size, -1 * Last),
    case lists:all(fun(X) -> X =:= Last end, binary:bin_to_list(Suffix)) of
        true -> binary:part(Binary, 0, Size - Last);
        false -> Binary
    end.
