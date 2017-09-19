-module(impl).

-author("kunal.tyagi").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-spec test() -> term(). %% SRSLY can we do better?
-endif.

-export([verify_ssec_algorithm/1,
         verify_ssec_key/2]).

%%-------------------------------------------------------------------------
%% API
%%-------------------------------------------------------------------------

%% @doc verifies that the user demanded the correct algorithm
%%      only AES256 allowed
-spec(verify_ssec_algorithm(Algorithm) ->
        {Status, ValidAlgorithms} when Algorithm::string(),
                                       Status::boolean(),
                                       ValidAlgorithms::[string()]).
verify_ssec_algorithm(Algorithm) ->
    ValidAlgorithms = ["AES256"],
    {lists:member(Algorithm, ValidAlgorithms), ValidAlgorithms}.

%% @doc verifies that the user provided key matches the hash
%%      Key and hash are Base64 encoded
-spec(verify_ssec_key(ASCIIKey, Checksum) ->
        {Status, ErrorDescription} when ASCIIKey::string(),
                                        Checksum::{Type, ASCIIHash},
                                        Type::md5,
                                        ASCIIHash::string(),
                                        Status::boolean(),
                                        ErrorDescription::string()).
verify_ssec_key(ASCIIKey, Checksum) ->
    Key = base64:decode(ASCIIKey),
    {HashType, ASCIIHash} = Checksum,
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

%% @doc GET operation, with user supplied request headers
%%      ObjectDetails is OS suplied
get_operation(ObjectDetails, RequestHeaders) ->
    {Algorithm, Key, Checksum} = RequestHeaders,
    Md5Checksum = {md5, Checksum},
    get_operation({algo, verify_ssec_algorithm(Algorithm)}).
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
                    true
%                    ssec_base:verify_key
            end
    end.

%%-------------------------------------------------------------------------
%% Private
%%-------------------------------------------------------------------------

%% @doc dummy function to get the requested object and its metadata
%% @private
-spec(getObjectMetaData(ObjectDetails)->
        {Salt, Hash, MetaData} when ObjectDetails::binary(),
                                    Salt::binary(),
                                    Hash::binary(),
                                    MetaData::binary()).
getObjectMetaData(ObjectDetails) ->
    {false, "TODO. Not implemented"}.

%% @doc dummy function to get the requested data
%% @private
-spec(getObjectData(ObjectDetails)->
        Data when ObjectDetails::binary(),
                  Data::binary()).
getObjectData(ObjectDetails) ->
    {false, "TODO, not implemented"}.
