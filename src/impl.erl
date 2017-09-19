-module(impl).

-author("kunal.tyagi").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-spec test() -> term(). %% SRSLY can we do better?
-endif.

-export([get_operation/2]).

%%-------------------------------------------------------------------------
%% API
%%-------------------------------------------------------------------------

%% @doc GET operation, with user supplied request headers
%%      ObjectDetails is OS suplied
-spec(get_operation(ObjectDetails, RequestHeaders) ->
        {error, ErrorDescription} | Data when ObjectDetails::binary(),
                                              RequestHeaders::any(),
                                              ErrorDescription::string(),
                                              Data::binary()).
get_operation(ObjectDetails, RequestHeaders) ->
    {Algorithm, Key, Checksum} = RequestHeaders,
    Md5Checksum = {md5, Checksum},
    {AlgoStatus, AlgoList} = ssec_base:verify_ssec_algorithm(Algorithm),
    if
        AlgoStatus =:= false ->
            {error, "Expected " ++ AlgoList ++ "Provided: " ++ Algorithm};
        true ->
            {KeyStatus, Error} = ssec_base:verify_ssec_key(Key, Md5Checksum),
            if
                KeyStatus ->
                    {Salt, Hash, _Meta} = get_object_metadata(ObjectDetails),
                    Verification = ssec_base:verify_key(Key, Salt, Hash),
                    if
                        Verification ->
                            ssec_base:block_decrypt_data(Key, get_object_data(ObjectDetails));
                        true ->
                            {error, "Wrong Key provided"}
                    end;
                true ->
                    {error, Error}
            end
    end.

%%-------------------------------------------------------------------------
%% Private
%%-------------------------------------------------------------------------

%% @doc dummy function to get the requested object and its metadata
%% @private
-spec(get_object_metadata(ObjectDetails)->
        {Salt, Hash, MetaData} when ObjectDetails::binary(),
                                    Salt::binary(),
                                    Hash::binary(),
                                    MetaData::binary()).
get_object_metadata(_ObjectDetails) ->
    {false, "TODO. Not implemented"}.

%% @doc dummy function to get the requested data
%% @private
-spec(get_object_data(ObjectDetails)->
        Data when ObjectDetails::binary(),
                  Data::binary()).
get_object_data(_ObjectDetails) ->
    {false, "TODO, not implemented"}.
