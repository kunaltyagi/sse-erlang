# sse-erlang
SSE implementation in Erlang

## Usage
### Stage 1
Assuming ```Key``` is provided by the user
```erlang
% 32 bytes are minimum, 64 max
Salt = ssec:gen_salt(32).

Hash = ssec:gen_hash(sha256, Key, Salt).
```
Don't forget to store Salt and Hash for every new key.

### Stage 2
Later, verify that the user's provided key is the same as before by using the stored ```Salt``` and ```Hash```
```erlang
ssec:verify_key(Key, Salt, Hash).
```
### Stage 3
The key from the user can be used to encrypt or decrypt ```Data``` using
```erlang
EncryptedData = encryptData(Key, Data).
% at a later point of time
Data = decryptData(Key, EncryptedData).
```
Here, ```Data``` and ```EncryptedData``` are ```binary```.

## Deep Dive
In order to understand more, read the functions ```test_hash``` and ```test_encryption```
