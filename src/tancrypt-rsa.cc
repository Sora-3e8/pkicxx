#include "tancrypt-hash.hpp"
#include "tancrypt-hashtypes.hpp"
#include "tancrypt-pkic.hpp"
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <stdexcept>
#include <string>

namespace tancrypt
{
  namespace RSA
  {  
  dutils::dbuffer encrypt(pkic& key,dutils::dbuffer& payload)
  {
    if(!key.isInitialized())
    {
      throw std::logic_error("[tancrypt::RSA::encrypt] The key container was not initialized.");
    }
   
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key,NULL);
    if(!ctx) return dutils::dbuffer();
      
    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    {
      unsigned long _err = ERR_get_error();
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("[tancrypt::RSA::ecrypt] Encryption context init failed.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
      unsigned long _err = ERR_get_error();
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("[tancrypt::RSA::encrypt] Encryption context init failed.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }
    
    size_t len;
    if (EVP_PKEY_encrypt(ctx,NULL,&len,payload.data(),payload.size())<=0)
    {
      unsigned long _err = ERR_get_error();
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("[tancrypt::RSA::encrypt] Encryption failed.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }
    
    dutils::dbuffer encrypted(len);
    if(EVP_PKEY_encrypt(ctx,encrypted.data(),&len,payload.data(),payload.size())<=0)
    {
      unsigned long _err = ERR_get_error();
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("[tancrypt::RSA::encrypt] Encryption failed.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }

    EVP_PKEY_CTX_free(ctx);
    return encrypted;
  }

  dutils::dbuffer decrypt(pkic& key,dutils::dbuffer& payload)
  {
    if(!key.isInitialized())
    {
      throw std::logic_error("[tancrypt::RSA::decrypt] The key container was not initialized.");
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key,NULL);
    if(!ctx) return dutils::dbuffer();
    
    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    {
      unsigned long _err = ERR_get_error();
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("[tancrypt::RSA::decrypt] Decryption context init failed.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0){ return{};}

    size_t len;
    if (EVP_PKEY_decrypt(ctx,NULL,&len,payload.data(),payload.size())<=0)
    {
      unsigned long _err = ERR_get_error();
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("[tancrypt::RSA::decrypt] Decryption failed.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }
    
    dutils::dbuffer decrypted(len);
    if(EVP_PKEY_decrypt(ctx,decrypted.data(),&len,payload.data(),payload.size())<=0)
    {
      unsigned long _err = ERR_get_error();
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("[tancrypt::RSA::decrypt] Decryption failed.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }
    
    decrypted.resize(len);
    EVP_PKEY_CTX_free(ctx);
    
    return decrypted;
  }

  dutils::dbuffer sign(pkic& key,dutils::dbuffer &buffer, hashAlg alg)
  {

    EVP_SIGNATURE* alg_sig = nullptr;
    size_t siglen;
    
    if(!key.isInitialized())
    {
      throw std::logic_error("[tancrypt::RSA::sign] The key container was not initialized.");
    }
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key,NULL);
    
    if(!ctx)
    {
      unsigned long _err = ERR_get_error();
      throw std::runtime_error("[tancrypt::RSA::sign] Could not load the key.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }
    
    dutils::dbuffer buffer_hashed = hash(buffer,alg);
    alg_sig = EVP_SIGNATURE_fetch(NULL, "RSA", NULL);

    if(alg_sig==nullptr)
    {
      int _err = ERR_get_error();
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("[tancrypt::RSA::sign] Could not init signature algorithm.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }

    
    if (EVP_PKEY_sign_init_ex2(ctx,alg_sig,NULL) <= 0)
    {
      int _err = ERR_get_error();
      EVP_PKEY_CTX_free(ctx);
      EVP_SIGNATURE_free(alg_sig);
      throw std::runtime_error("[tancrypt::RSA::sign] Could not load signature algorithm..\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }

    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
    {
      int _err = ERR_get_error();
      EVP_PKEY_CTX_free(ctx);
      EVP_SIGNATURE_free(alg_sig);
      throw std::runtime_error("[tancrypt::RSA::sign] Could not init signature algorithm.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }
    
    if (EVP_PKEY_sign(ctx, NULL, &siglen, buffer_hashed.data(), buffer_hashed.size()) <= 0)
    {
      int _err = ERR_get_error();
      EVP_PKEY_CTX_free(ctx);
      EVP_SIGNATURE_free(alg_sig);
      throw std::runtime_error("[tancrypt::RSA::sign] Could not sign.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }
    dutils::dbuffer signature(siglen);
    
    if (EVP_PKEY_sign(ctx, signature.data(), &siglen, buffer_hashed.data(), buffer_hashed.size()) <= 0)
    {
      int _err = ERR_get_error();
      EVP_PKEY_CTX_free(ctx);
      EVP_SIGNATURE_free(alg_sig);
      throw std::runtime_error("[tancrypt::RSA::sign] Could not sign.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }
    
    EVP_PKEY_CTX_free(ctx);
    EVP_SIGNATURE_free(alg_sig);
    
    return signature;
  }
  
  bool verify(pkic& key, dutils::dbuffer&sig, dutils::dbuffer &buffer, hashAlg alg)
  {
    if(!key.isInitialized())
    {
      throw std::logic_error("[tancrypt::RSA::verify] The key container was not initialized.");
    }
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key,NULL);
    EVP_SIGNATURE *alg_sig = nullptr;
    alg_sig = EVP_SIGNATURE_fetch(NULL,"RSA",NULL);
    
    if(alg_sig == nullptr)
    {
      unsigned long _err = ERR_get_error();
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("[tancrypt::RSA::verfiy] Could not initialize signature algorithm.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }

    dutils::dbuffer hashed_buffer = hash(buffer, alg);
    
    if(EVP_PKEY_verify_init_ex2(ctx,alg_sig,NULL)<=0)
    {
      unsigned long _err = ERR_get_error();
      EVP_SIGNATURE_free(alg_sig);
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("[tancrypt::RSA::verify] Could not init the verify context.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }
    
    if(EVP_PKEY_verify(ctx, sig.data(), sig.size(),hashed_buffer.data(), hashed_buffer.size())<0)
    {
      unsigned long _err = ERR_get_error();
      EVP_SIGNATURE_free(alg_sig);
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("[tancrypt::RSA::verify] Could not verify.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }

    int res = EVP_PKEY_verify(ctx, sig.data(), sig.size(), hashed_buffer.data(), hashed_buffer.size());

    if(res < 0)
    {
      unsigned long _err = ERR_get_error();
      EVP_SIGNATURE_free(alg_sig);
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("[tancrypt::RSA::verify] Could not verify.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }

    EVP_SIGNATURE_free(alg_sig);
    EVP_PKEY_CTX_free(ctx);

    return (res==0);
  }
  
}
}
