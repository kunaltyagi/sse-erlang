# sse-erlang
SSE implementation in Erlang

## Usage
Assuming ```Key``` is provided by the user

```erlang
% 32 bytes are minimum, 64 max
Salt = ssec:gen_salt(32).

Hash = ssec:gen_hash(sha256, Key, Salt).
```
Don't forget to store Salt and Hash for every new key.

Later, verify that the user's provided key is the same as before by using the stored ```Salt``` and ```Hash```
```erlang
ssec:verify_key(Key, Salt, Hash).
```
