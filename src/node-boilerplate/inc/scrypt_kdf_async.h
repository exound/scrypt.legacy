/*
scrypt_kdf_async.h

Copyright (C) 2013 Barry Steyn (http://doctrina.org/Scrypt-Authentication-For-Node.html)

This source code is provided 'as-is', without any express or implied
warranty. In no event will the author be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this source code must not be misrepresented; you must not
   claim that you wrote the original source code. If you use this source code
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original source code.
3. This notice may not be removed or altered from any source distribution.

Barry Steyn barry.steyn@gmail.com
*/

#ifndef _SCRYPT_KDF_ASYNC_H
#define _SCRYPT_KDF_ASYNC_H

#include <napi.h>
#include <vector>
#include <string> // For error messages
#include "scrypt_common.h" // For Params struct and ScryptError

// Scrypt is a C library and there needs c linkings
extern "C" {
  #include "keyderivation.h" // For KDF wrapper function
}

class ScryptKDFAsyncWorker : public Napi::AsyncWorker {
  public:
    ScryptKDFAsyncWorker(const Napi::CallbackInfo& info) :
      Napi::AsyncWorker(info[3].As<Napi::Function>()), // Callback is the 4th argument
      params(info[1].As<Napi::Object>()) // Params object is the 2nd argument
    {
      // Napi::Env env = info.Env(); // Removed unused variable
      // Get key buffer (1st argument)
      Napi::Buffer<uint8_t> key_buffer = info[0].As<Napi::Buffer<uint8_t>>();
      key_ref = Napi::Reference<Napi::Buffer<uint8_t>>::New(key_buffer, 1); // Keep buffer alive
      key_ptr = key_buffer.Data();
      key_size = key_buffer.Length();

      // Get salt buffer (3rd argument)
      Napi::Buffer<uint8_t> salt_buffer = info[2].As<Napi::Buffer<uint8_t>>();
      salt_ref = Napi::Reference<Napi::Buffer<uint8_t>>::New(salt_buffer, 1); // Keep buffer alive
      salt_ptr = salt_buffer.Data();
      salt_size = salt_buffer.Length(); // Need salt size for crypto_scrypt

      // Determine output buffer size (hardcoded as 96 in original code)
      // TODO: Make this configurable or derive from parameters if possible
      result_size = 96;
      result_data.resize(result_size);

      scrypt_result = 0; // Initialize result code
    }

    ~ScryptKDFAsyncWorker() {} // Destructor

    // Executed in background thread
    void Execute() override {
      // Ensure pointers are still valid (though References should handle this)
      // Re-acquire pointers just in case, Napi::Reference::Value() might be safer
      // but requires Env which is not available here. Assuming direct pointers are okay for now.
      // uint8_t* current_key_ptr = key_ref.Value().Data();
      // uint8_t* current_salt_ptr = salt_ref.Value().Data();

      // Call the KDF wrapper function
      // KDF(const uint8_t* key_ptr, size_t key_size, uint8_t* result_ptr, uint32_t N, uint32_t r, uint32_t p, const uint8_t* salt_ptr)
      scrypt_result = KDF(
          key_ptr, key_size,
          result_data.data(), // Output buffer
          params.N, params.r, params.p,
          salt_ptr // Salt buffer
      );
      // Note: salt_size and result_size are not passed directly to KDF wrapper

      if (scrypt_result != 0) {
        // Use the common error function description
        SetError("Scrypt KDF failed: " + std::string(NodeScrypt::ScryptError(Env(), scrypt_result).Message()));
      }
    }

    // Executed in main thread after successful Execute
    void OnOK() override {
      Napi::Env env = Env();
      Napi::HandleScope scope(env);

      // Create a new buffer with the derived key
      Napi::Buffer<uint8_t> result_buffer = Napi::Buffer<uint8_t>::Copy(env, result_data.data(), result_size);

      // Call the JS callback with null error and the result buffer
      Callback().Call({env.Null(), result_buffer});

      // Release references
      key_ref.Reset();
      salt_ref.Reset();
    }

    // Executed in main thread if Execute sets an error
    void OnError(const Napi::Error& e) override {
      Napi::Env env = Env();
      Napi::HandleScope scope(env);

      // Call the JS callback with the error
      Callback().Call({e.Value(), env.Undefined()});

      // Release references
      key_ref.Reset();
      salt_ref.Reset();
    }

  private:
    Napi::Reference<Napi::Buffer<uint8_t>> key_ref;
    Napi::Reference<Napi::Buffer<uint8_t>> salt_ref;
    const uint8_t* key_ptr;
    size_t key_size;
    const uint8_t* salt_ptr;
    size_t salt_size;
    const NodeScrypt::Params params;
    size_t result_size;
    std::vector<uint8_t> result_data;
    int scrypt_result;
};

#endif /* _SCRYPT_KDF_ASYNC_H */
