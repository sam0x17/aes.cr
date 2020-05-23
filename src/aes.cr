require "openssl/lib_crypto"

@[Link("openssl")]
lib LibCrypto
  EVP_MAX_BLOCK_LENGTH = 32

  type EvpMd = Void*
  type EvpCipher = Void*
  type Engine = Void*

  struct EvpCipherCtx
    cipher : EvpCipher*
    engine : Engine*
    encrypt : Int32
    buf_len : Int32
    oiv : UInt8[EVP_MAX_IV_LENGTH]
    iv : UInt8[EVP_MAX_IV_LENGTH]
    buf : UInt8[EVP_MAX_BLOCK_LENGTH]
    num : Int32
    app_data : Void*
    key_len : Int32
    flags : Int64
    cipher_data : Void*
    final_used : Int32
    block_mask : Int32
    final : UInt8[EVP_MAX_BLOCK_LENGTH]
  end

  fun evp_decrypt_final_ex = EVP_DecryptFinal_ex(ctx : EvpCipherCtx*, outm : UInt8*, outl : LibC::Int*) : LibC::Int
  fun evp_decrypt_update = EVP_DecryptUpdate(ctx : EvpCipherCtx*, out : UInt8*, outl : LibC::Int*, in : UInt8*, inl : LibC::Int) : LibC::Int
  fun evp_encrypt_final_ex = EVP_EncryptFinal_ex(ctx : EvpCipherCtx*, out : UInt8*, outl : LibC::Int*) : LibC::Int
  fun evp_encrypt_update = EVP_EncryptUpdate(ctx : EvpCipherCtx*, out : UInt8*, outl : LibC::Int*, in : UInt8*, inl : LibC::Int) : LibC::Int
  fun evp_decrypt_init_ex = EVP_DecryptInit_ex(ctx : EvpCipherCtx*, cipher : EvpCipher, impl : Void*, key : UInt8*, iv : UInt8*) : LibC::Int
  fun evp_encrypt_init_ex = EVP_EncryptInit_ex(ctx : EvpCipherCtx*, cipher : EvpCipher, impl : Void*, key : UInt8*, iv : UInt8*) : LibC::Int
  fun evp_aes_128_cbc = EVP_aes_128_cbc : EvpCipher
  fun evp_aes_192_cbc = EVP_aes_192_cbc : EvpCipher
  fun evp_aes_256_cbc = EVP_aes_256_cbc : EvpCipher
  fun evp_cipher_ctx_init = EVP_CIPHER_CTX_reset(c : EvpCipherCtx*) : LibC::Int
end

class AES
  getter encrypt_context : LibCrypto::EvpCipherCtx = LibCrypto::EvpCipherCtx.new
  getter decrypt_context : LibCrypto::EvpCipherCtx = LibCrypto::EvpCipherCtx.new
  getter bits : Int32 = 256
  getter key : Slice(UInt8)
  getter iv : Slice(UInt8)
  property nonce_size : Int32 = 2

  SUPPORTED_BITSIZES = [128, 192, 256]
  READABLE_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~!@#$%^&*()_+=-?/>.<,;:]}[{|".chars
  CHARS = (0_u8..255_u8).to_a

  def self.generate_key(length = 32)
    key = ""
    length.times { key += CHARS.sample(Random::Secure).chr }
    key
  end

  def self.generate_key_readable(length = 32)
    key = ""
    length.times { key += READABLE_CHARS.sample(Random::Secure) }
    key
  end

  def initialize
    initialize(AES.generate_key_readable(32), AES.generate_key_readable(32), 256)
  end

  def initialize(bits : Int32 = 256)
    keysize = bits == 256 ? 32 : 16
    initialize(AES.generate_key_readable(keysize), AES.generate_key_readable(keysize), bits)
  end

  def initialize(key : String, iv : String, bits : Int32 = 256)
    initialize(key.as_slice, iv.as_slice, bits)
  end

  def initialize(key : Slice(UInt8), iv : Slice(UInt8), bits : Int32 = 256)
    en = pointerof(@encrypt_context)
    de = pointerof(@decrypt_context)
    LibCrypto.evp_cipher_ctx_init(en)
    LibCrypto.evp_cipher_ctx_init(de)
    case bits
    when 128
      LibCrypto.evp_encrypt_init_ex(en, LibCrypto.evp_aes_128_cbc(), nil, key, iv)
      LibCrypto.evp_decrypt_init_ex(de, LibCrypto.evp_aes_128_cbc(), nil, key, iv)
    when 192
      LibCrypto.evp_encrypt_init_ex(en, LibCrypto.evp_aes_192_cbc(), nil, key, iv)
      LibCrypto.evp_decrypt_init_ex(de, LibCrypto.evp_aes_192_cbc(), nil, key, iv)
    when 256
      LibCrypto.evp_encrypt_init_ex(en, LibCrypto.evp_aes_256_cbc(), nil, key, iv)
      LibCrypto.evp_decrypt_init_ex(de, LibCrypto.evp_aes_256_cbc(), nil, key, iv)
    else
      raise "bits must be one of #{SUPPORTED_BITSIZES}"
    end
    @bits = bits
    @key = key
    @iv = iv
  end

  def encrypt(data : Slice(UInt8))
    tmp = Slice.new(data.size + nonce_size, 0u8)
    data.copy_to(tmp)
    data = tmp
    nonce_size.times { |i| data[data.size - i - 1] = CHARS.sample(Random::Secure) }
    c_len = data.size + LibCrypto::EVP_MAX_BLOCK_LENGTH
    f_len = 0
    ciphertext = Slice.new(c_len, 0u8)
    LibCrypto.evp_encrypt_init_ex(pointerof(@encrypt_context), nil, nil, nil, nil)
    LibCrypto.evp_encrypt_update(pointerof(@encrypt_context), ciphertext.to_unsafe, pointerof(c_len), data, data.size)
    LibCrypto.evp_encrypt_final_ex(pointerof(@encrypt_context), ciphertext.to_unsafe + c_len, pointerof(f_len))
    ciphertext[0, f_len + c_len]
  end

  def encrypt(str : String)
    encrypt(str.as_slice)
  end

  def decrypt(data : Slice(UInt8))
    p_len = data.size
    len = data.size
    f_len = 0
    plaintext = Slice.new(p_len, 0u8)
    LibCrypto.evp_decrypt_init_ex(pointerof(@decrypt_context), nil, nil, nil, nil)
    LibCrypto.evp_decrypt_update(pointerof(@decrypt_context), plaintext.to_unsafe, pointerof(p_len), data.to_unsafe, len)
    LibCrypto.evp_decrypt_final_ex(pointerof(@decrypt_context), plaintext.to_unsafe + p_len, pointerof(f_len))
    plaintext[0, p_len + f_len - nonce_size]
  end

  def decrypt(str : String)
    decrypt(str.as_slice)
  end
end

class String
  def as_slice
    bts = bytes
    Slice.new(bts.to_unsafe, bts.size)
  end
end
