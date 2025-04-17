/*
scrypt_hash_async.h

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

#ifndef _SCRYPTHASHASYNC_
#define _SCRYPTHASHASYNC_

#include <napi.h>
#include <vector>
#include <string> // For error messages
#include "scrypt_common.h" // For Params struct and ScryptError

// Scrypt is a C library and there needs c linkings
extern "C" {
  #include "hash.h" // For Hash function (assuming it's in hash.h)
}

class ScryptHashAsyncWorker : public Napi::AsyncWorker {
  public:
    ScryptHashAsyncWorker(const Napi::CallbackInfo& info) :
      Napi::AsyncWorker(info[4].As<Napi::Function>()), // Callback is the 5th argument
      params(info[1].As<Napi::Object>()), // Params object is the 2nd argument
      hash_size(info[2].As<Napi::Number>().Int64Value()) // Hash size is the 3rd argument
    {
      // Get key buffer (1st argument)
      Napi::Buffer<uint8_t> key_buffer = info[0].As<Napi::Buffer<uint8_t>>();
      key_ref = Napi::Reference<Napi::Buffer<uint8_t>>::New(key_buffer, 1); // Keep buffer alive
      key_ptr = key_buffer.Data();
      key_size = key_buffer.Length();

      // Get salt buffer (4th argument)
      Napi::Buffer<uint8_t> salt_buffer = info[3].As<Napi::Buffer<uint8_t>>();
      salt_ref = Napi::Reference<Napi::Buffer<uint8_t>>::New(salt_buffer, 1); // Keep buffer alive
      salt_ptr = salt_buffer.Data();
      salt_size = salt_buffer.Length();

      // Allocate space for the hash result
      result_data.resize(hash_size);

      hash_result = 0; // Initialize result code
    }

    ~ScryptHashAsyncWorker() {} // Destructor

    // Executed in background thread
    void Execute() override {
      // Call the core scrypt Hash function
      // Assuming signature: Hash(key_ptr, key_size, params.N, params.r, params.p, salt_ptr, salt_size, result_data.data(), hash_size)
      hash_result = Hash(
          key_ptr, key_size,
          salt_ptr, salt_size,
          params.N, params.r, params.p,
          result_data.data(), hash_size
      );

      if (hash_result != 0) {
        // Use the common error function description
        SetError("Scrypt Hash failed: " + std::string(NodeScrypt::ScryptError(Env(), hash_result).Message()));
      }
    }

    // Executed in main thread after successful Execute
    void OnOK() override {
      Napi::Env env = Env();
      Napi::HandleScope scope(env);

      // Create a new buffer with the hash result
      Napi::Buffer<uint8_t> result_buffer = Napi::Buffer<uint8_t>::Copy(env, result_data.data(), hash_size);

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
    const NodeScrypt::Params params;
    const size_t hash_size;
    const uint8_t* salt_ptr;
    size_t salt_size;
    std::vector<uint8_t> result_data;
    int hash_result; // Store result from Hash
};

#endif /* _SCRYPTHASHASYNC_ */
