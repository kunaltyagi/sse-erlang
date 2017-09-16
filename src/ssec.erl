-module(ssec).

-author("kunal.tyagi").

-include_lib("eunit/include/eunit.hrl").

-export([gen_salt/1,
         gen_hash/3,
         verify_key/3,
         algo_metadata/0,
         block_encrypt_data/3,
         block_decrypt_data/3,
         verify_ssec_algorithm/1,
         verify_ssec_key/2
        ]).


%% =========================================================
%% API
%% =========================================================
%% @doc generate a random salt
%%
-spec(gen_salt(Length) ->
             {ok, Salt} | {error, ErrorDescription} when Length::integer(),
                                                         Salt::binary(),
                                                         ErrorDescription::string()).
gen_salt(Length) when Length >= 32, Length =< 64 ->
    %% erlang:binary_to_list(crypto:strong_rand_bytes(Length)).
    {ok, crypto:strong_rand_bytes(Length)};
gen_salt(Length) when Length < 32 ->
    {error, "Minimum length is 32. Provided: " ++ erlang:integer_to_list(Length)};
gen_salt(Length) ->
    {error, "Maximum length is 64. Provided: " ++ erlang:integer_to_list(Length)}.


%% @doc generate hash of user key using the salt
%%
-spec(gen_hash(Type, UserKey, Salt) ->
             {Type, Mac} when Type::atom(),
                              UserKey::iodata(),
                              Salt::iodata(),
                              Mac::binary()).
gen_hash(Type, UserKey, Salt) ->
    %% save the algorithm used, eg md5, sha, sha256
    {Type, crypto:hmac(Type, Salt, UserKey)}.


%% @doc verify that the userkey and salt combination matches the provided hash
%%
-spec(verify_key(UserKey, Salt, Hash) ->
             true | false when UserKey::iodata(),
                               Salt::iodata(),
                               Hash::{Type, binary()},
                               Type::atom()).
verify_key(UserKey, Salt, Hash) ->
    {HashType, _HashValue} = Hash,
    gen_hash(HashType, UserKey, Salt) =:= Hash.


%% @doc sample implementation for providing custom algorithms to
%%      encrypt and decrypt in a uniform manner
%%
-spec(algo_metadata() ->
             {AlgoType, PadAlgo} when AlgoType::des_ecb | blowfish_ecb | aes_ecb,
                                      PadAlgo::zero | rfc5652).
algo_metadata() ->
    %% store details such as
    %% - algorithm to use
    %% - use IVec or not
    %% - use AEAD mode or not
    %% Currently doesn't do anything more than supply the algorithm
    Algo = aes_ecb,
    Pad = rfc5652,
    {Algo, Pad}.


%% Integration of block and stream functions not done coz AEAD

%% @doc block encrypt data using the user key
%%
-spec(block_encrypt_data(UserKey, Data, AlgoMetaData) ->
             CipherPadData when UserKey::binary(),
                                Data::iodata(),
                                AlgoMetaData::tuple(),
                                CipherPadData::binary()).
block_encrypt_data(UserKey, Data, AlgoMetaData) ->
    {Algo, Pad} = AlgoMetaData,
    %% Technically 16 should also be in metadata?
    PadData = pad(Pad, 16, Data),
    crypto:block_encrypt(Algo, UserKey, PadData).


%% @doc block decrypt data using the user key
%%
-spec(block_decrypt_data(UserKey, Data, AlgoMetaData) ->
             PlainData when UserKey::binary(),
                            Data::binary(),
                            AlgoMetaData::tuple(),
                            PlainData::iodata()).
block_decrypt_data(UserKey, Data, AlgoMetaData) ->
    {Algo, Pad} = AlgoMetaData,
    PadData = crypto:block_decrypt(Algo, UserKey, Data),
    unpad(Pad, PadData).


%% @doc verify that the data is encryted correctly
%%
%% -spec(verify_block_encryption(Key, Msg, AlgoMetaData) ->
%%         {true|false, EncryptedMsg} when Key::binary(),
%%                                         Msg::iodata(),
%%                                         AlgoMetaData::tuple(),
%%                                         EncryptedMsg::binary()).
%% verify_block_encryption(Key, Msg, AlgoMetaData) ->
%%     EncryptedMsg = block_encrypt_data(Key, Msg, AlgoMetaData),
%%     {Msg =:= block_decrypt_data(Key, EncryptedMsg, AlgoMetaData),
%%          EncryptedMsg}.


%% @doc
-spec(verify_ssec_algorithm(Algorithm) ->
             boolean() when Algorithm::[]).
verify_ssec_algorithm(Algorithm) ->
    Algorithm =:= "AES256".


%% @doc
-spec(verify_ssec_key(ASCIIKey, Checksum) ->
             {Value, []} when ASCIIKey::binary(),
                              Checksum::non_neg_integer(),
                              Value::boolean()).
verify_ssec_key(ASCIIKey, Checksum) ->
    %% is_list(ASCIIKey)?
    Key = base64:decode(ASCIIKey),
    {HashType, ASCIIHash} = Checksum,
    %% is_atom(HashValue)?
    %% is_list(ASCIIHash)?
    HashValue = base64:decode(ASCIIHash),
    if
        size(Key) /= 256/4 ->
            {false, "Key is not 256 bit long. Provided: " ++ erlang:integer_to_list(size(Key))};
        HashType /= md5 ->
            {false, "MD5 checksum required. Provided: " ++ erlang:atom_to_list(HashType)};
        size(HashValue) /= 128/4 ->
            {false, "MD5 checksum is not 128 bit long. Provided: " ++ erlang:integer_to_list(size(Key))};
        true ->
            %% TODO:
            %% crypto gives <<8 bit integers comma seperated>>
            %% HashValue is <<"Base16string">>
            Lhs = erlang:binary_to_list(crypto:hash(HashType, Key)),
            Rhs = erlang:binary_to_integer(HashValue, 16),
            Value = lists:foldl(
                      fun(X, Old) ->
                              X + Old*256
                      end, 0, Lhs) =:= Rhs,
            {Value, "Verification status"}
    end.

%% =========================================================
%% Inner Functions
%% =========================================================
%% @private
pad(zero, Width, Binary) ->
    pad_zero(Width, Binary);
pad(rfc5652, Width, Binary) ->
    pad_rfc5652(Width, Binary).


%% @private
unpad(zero, Binary) ->
    unpad_zero(Binary);
unpad(rfc5652, Binary) ->
    unpad_rfc5652(Binary).


%% Alternative pad implementation:
%% Pad with symbol X for Y times
%% pad_rfc5652/3 does this, but don't use it to pad with zeroes
%% Alternative Unpad implementation not done to prevent misuse
%% @private
pad_zero(Width, Binary) ->
    case (Width - (size(Binary) rem Width)) rem Width of
        0 -> Binary;
        N -> <<Binary/binary, 0:(N*8)>> % 8 bits in one byte
    end.


%% @private
unpad_zero(Binary) ->
    unpad_zero(Binary, size(Binary) - 1).
unpad_zero(_Binary, -1) ->
    <<>>;
unpad_zero(Binary, Idx) ->
    case binary:at(Binary, Idx) of
        0 -> unpad_zero(Binary, Idx - 1);
        _ -> binary:part(Binary, 0, Idx + 1)
    end.


%% @private
pad_rfc5652(Width, Binary) ->
    case (Width - (size(Binary) rem Width)) rem Width of
        0 -> pad_rfc5652(Width, Width, Binary);
        N -> pad_rfc5652(N, N, Binary)
    end.

pad_rfc5652(_OrigWidth, 0, Binary) ->
    Binary;
pad_rfc5652(OrigWidth, Length, Binary) ->
    pad_rfc5652(OrigWidth, Length-1, <<Binary/binary, OrigWidth:8>>).


%% @private
unpad_rfc5652(Binary) ->
    Size = size(Binary),
    Last = binary:at(Binary, Size - 1),
    Suffix = binary:part(Binary, Size, -1 * Last),
    case lists:all(fun(X) -> X =:= Last end, binary:bin_to_list(Suffix)) of
        true -> binary:part(Binary, 0, Size - Last);
        false -> Binary
    end.
