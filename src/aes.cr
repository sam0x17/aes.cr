@[Link("openssl")]
lib OpenSSL
  EVP_MAX_IV_LENGTH = 16
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

  fun evp_cipher_ctx_cleanup = EVP_CIPHER_CTX_reset(c : EvpCipherCtx*) : LibC::Int
  fun evp_decrypt_final_ex = EVP_DecryptFinal_ex(ctx : EvpCipherCtx*, outm : UInt8*, outl : LibC::Int*) : LibC::Int
  fun evp_decrypt_update = EVP_DecryptUpdate(ctx : EvpCipherCtx*, out : UInt8*, outl : LibC::Int*, in : UInt8*, inl : LibC::Int) : LibC::Int
  fun evp_encrypt_final_ex = EVP_EncryptFinal_ex(ctx : EvpCipherCtx*, out : UInt8*, outl : LibC::Int*) : LibC::Int
  fun evp_encrypt_update = EVP_EncryptUpdate(ctx : EvpCipherCtx*, out : UInt8*, outl : LibC::Int*, in : UInt8*, inl : LibC::Int) : LibC::Int
  fun evp_decrypt_init_ex = EVP_DecryptInit_ex(ctx : EvpCipherCtx*, cipher : EvpCipher, impl : Engine, key : UInt8*, iv : UInt8*) : LibC::Int
  fun evp_encrypt_init_ex = EVP_EncryptInit_ex(ctx : EvpCipherCtx*, cipher : EvpCipher, impl : Engine, key : UInt8*, iv : UInt8*) : LibC::Int
  fun evp_sha1 = EVP_sha1 : EvpMd
  fun evp_sha256 = EVP_sha256 : EvpMd
  fun evp_sha512 = EVP_sha512 : EvpMd
  fun evp_aes_128_cbc = EVP_aes_128_cbc : EvpCipher
  fun evp_aes_192_cbc = EVP_aes_192_cbc : EvpCipher
  fun evp_aes_256_cbc = EVP_aes_256_cbc : EvpCipher
  fun evp_bytes_to_key = EVP_BytesToKey(type : EvpCipher, md : EvpMd, salt : UInt8*, data : UInt8*, datal : LibC::Int, count : LibC::Int, key : UInt8*, iv : UInt8*) : LibC::Int
  fun evp_cipher_ctx_init = EVP_CIPHER_CTX_reset(c : EvpCipherCtx*) : LibC::Int
  fun evp_cipher_init_ex = EVP_CipherInit_ex(ctx : EvpCipherCtx*, cipher : EvpCipher, impl : Engine, key : UInt8*, iv : UInt8*, enc : LibC::Int) : LibC::Int
end

class AES
  getter encrypt_context : OpenSSL::EvpCipherCtx = OpenSSL::EvpCipherCtx.new
  getter decrypt_context : OpenSSL::EvpCipherCtx = OpenSSL::EvpCipherCtx.new
  getter bits : Int32 = 256
  getter key : Slice(UInt8)
  getter iv : Slice(UInt8)

  SUPPORTED_BITSIZES = [128, 192, 256]

  def initialize(key : Slice(UInt8), iv : Slice(UInt8), bits : Int32 = 256)
    en = pointerof(@encrypt_context)
    de = pointerof(@decrypt_context)
    OpenSSL.evp_cipher_ctx_init(en)
    OpenSSL.evp_cipher_ctx_init(de)
    case bits
    when 128
      OpenSSL.evp_encrypt_init_ex(en, OpenSSL.evp_aes_128_cbc(), nil, key, iv)
      OpenSSL.evp_decrypt_init_ex(de, OpenSSL.evp_aes_128_cbc(), nil, key, iv)
    when 192
      OpenSSL.evp_encrypt_init_ex(en, OpenSSL.evp_aes_192_cbc(), nil, key, iv)
      OpenSSL.evp_decrypt_init_ex(de, OpenSSL.evp_aes_192_cbc(), nil, key, iv)
    when 256
      OpenSSL.evp_encrypt_init_ex(en, OpenSSL.evp_aes_256_cbc(), nil, key, iv)
      OpenSSL.evp_decrypt_init_ex(de, OpenSSL.evp_aes_256_cbc(), nil, key, iv)
    else
      raise "bits must be one of #{SUPPORTED_BITSIZES}"
    end
    @bits = bits
    @key = key
    @iv = iv
  end
end

crypto = AES.new("testing".as_slice, "testing".as_slice, 256)

class String
  def as_slice
    bts = bytes
    Slice.new bts.to_unsafe, bts.size
  end
end
