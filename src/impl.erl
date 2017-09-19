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
