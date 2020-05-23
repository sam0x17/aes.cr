# aes.cr

Wrapper for openssl's AES encryption and decryption functionality.

## Installation

OpenSSL development packages are required for this shard to build.
On apt-based systems this can be installed via `sudo apt install libssl-dev`.

Add this to your application's `shard.yml`:

```yaml
dependencies:
  aes:
    github: sam0x17/aes.cr
```

## Usage

```crystal
require "aes"

aes = AES.new
puts aes.decrypt(aes.encrypt("hello world")) # => "hello world"
data = Bytes[0, 33, 128, 145, 77, 43, 32, 189, 250, 123]
puts aes.encrypt(data) # => encrypted bytes
puts aes.iv
puts aes.key
```

See `src/aes.cr` for full API info. Streaming is supported.
