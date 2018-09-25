# usage based on https://github.com/saju/misc/blob/master/misc/openssl_aes.c
# generator template to be used with https://github.com/crystal-lang/crystal_lib
module AES
  @[Include(
    "openssl/crypto.h",
    "openssl/evp.h",
    "openssl/err.h"
  )]
  lib OpenSSL
    fun evp_cipher_ctx_cleanup = EVP_CIPHER_CTX_reset
    fun evp_decrypt_final_ex = EVP_DecryptFinal_ex
    fun evp_decrypt_update = EVP_DecryptUpdate
    fun evp_encrypt_final_ex = EVP_EncryptFinal_ex
    fun evp_encrypt_update = EVP_EncryptUpdate
    fun evp_decrypt_init_ex = EVP_DecryptInit_ex
    fun evp_encrypt_init_ex = EVP_EncryptInit_ex
    fun evp_aes_256_cbc = EVP_aes_256_cbc
    fun evp_sha1 = EVP_sha1
    fun evp_sha256 = EVP_sha256
    fun evp_sha512 = EVP_sha512
    fun evp_aes_256_cbc = EVP_aes_256_cbc
    fun evp_bytes_to_key = EVP_BytesToKey
    fun evp_cipher_ctx_init = EVP_CIPHER_CTX_reset
    fun evp_cipher_init_ex = EVP_CipherInit_ex
  end
end
