-module(ssec).

-export([gen_salt/1,
         gen_hash/3,
         verify_key/3,
         encrypt_data/2,
         decrypt_data/2]).

-import(crypto, [strong_rand_bytes/1]).

gen_salt(Length) ->
    % erlang:binary_to_list(crypto:strong_rand_bytes(Length)).
    crypto:strong_rand_bytes(Length).

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
    crypto:block_encrypt(Algo, UserKey, Data).

decrypt_data(UserKey, Data) ->
    Algo = element(1, algo_metadata()),
    crypto:block_decrypt(Algo, UserKey, Data).
