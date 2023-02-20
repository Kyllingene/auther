# auther
### a password manager, both lib and bin

#### **auther may not be very cryptographically secure, so**
#### **help getting this right would be greatly appreciated**

parsing from a file (also supports encrypting/decrypting files):

example file:
```toml
[[passwords]]
type = "plain"
pass = "abc123"

[[passwords.location]]
name = "example.com"
email = "user@example.com"
username = "user"

[[passwords]]
type = "encrypted"
pass = "10150643464a"

[[passwords]]
type = "hash"
pass = "95f6dbe5b0c7b7feb458eae5d9bb3c8314d0d8cce1c192fa59127480bb4448541a2872fd69e8d823c0fdc054e93d88ce21eeeafc7c3480e679f2135614a88611"
salt = "5c5a1916d307fc0bc7b116398b2fd15efd05d654d0ffe0f762339c88f694d0dc737ff4a1e2c7fa251b0bec00058eec4b9cb9073712ab308197d62692b19fd851"

[[passwords.location]]
name = "example.net"
username = "user"
```
