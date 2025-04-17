/*
scrypt_kdf_verify_async.h

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

#ifndef _KDF_VERIFY_ASYNC_H
#define _KDF_VERIFY_ASYNC_H

#include <napi.h>
#include <vector>
#include <string> // For error messages
#include "scrypt_common.h" // For ScryptError (if needed for Verify errors)

// Scrypt is a C library and there needs c linkings
extern "C" {
  #include "keyderivation.h" // For Verify function
}

class ScryptKDFVerifyAsyncWorker : public Napi::AsyncWorker {
  public:
    ScryptKDFVerifyAsyncWorker(const Napi::CallbackInfo& info) :
      Napi::AsyncWorker(info[2].As<Napi::Function>()) // Callback is the 3rd argument
    {
      // Napi::Env env = info.Env(); // Unused variable
      // Get KDF buffer (1st argument)
      Napi::Buffer<uint8_t> kdf_buffer = info[0].As<Napi::Buffer<uint8_t>>();
      kdf_ref = Napi::Reference<Napi::Buffer<uint8_t>>::New(kdf_buffer, 1); // Keep buffer alive
      kdf_ptr = kdf_buffer.Data();
      // Assuming Verify function needs the KDF buffer size (often fixed, e.g., 96)
      kdf_size = kdf_buffer.Length(); // Get size from buffer

      // Get key buffer (2nd argument)
      Napi::Buffer<uint8_t> key_buffer = info[1].As<Napi::Buffer<uint8_t>>();
      key_ref = Napi::Reference<Napi::Buffer<uint8_t>>::New(key_buffer, 1); // Keep buffer alive
      key_ptr = key_buffer.Data();
      key_size = key_buffer.Length();

      match = false; // Initialize match result
      verify_result = 0; // Initialize verification result code
    }

    ~ScryptKDFVerifyAsyncWorker() {} // Destructor

    // Executed in background thread
    void Execute() override {
      // Call the core scrypt KDF verification function
      // Note: The original Verify function signature might differ slightly.
      // Assuming it takes kdf_ptr, key_ptr, key_size
      verify_result = Verify(kdf_ptr, key_ptr, key_size);

      // Check the result
      if (verify_result == 0) {
        match = true; // Verification successful
      } else if (verify_result == 11) { // Specific error code for mismatch in scrypt library
        match = false; // Verification failed (mismatch)
      } else {
        // Handle other potential errors from Verify
        // Use the common error function description if available for Verify errors
        // Or provide a generic error message.
        SetError("Scrypt KDF verification failed with error code: " + std::to_string(verify_result));
      }
    }

    // Executed in main thread after successful Execute
    void OnOK() override {
      Napi::Env env = Env();
      Napi::HandleScope scope(env);

      // Create a boolean result value
      Napi::Boolean result_value = Napi::Boolean::New(env, match);

      // Call the JS callback with null error and the boolean result
      Callback().Call({env.Null(), result_value});

      // Release references
      kdf_ref.Reset();
      key_ref.Reset();
    }

    // Executed in main thread if Execute sets an error
    void OnError(const Napi::Error& e) override {
      Napi::Env env = Env();
      Napi::HandleScope scope(env);

      // Call the JS callback with the error
      Callback().Call({e.Value(), env.Undefined()});

      // Release references
      kdf_ref.Reset();
      key_ref.Reset();
    }

  private:
    Napi::Reference<Napi::Buffer<uint8_t>> kdf_ref;
    Napi::Reference<Napi::Buffer<uint8_t>> key_ref;
    const uint8_t* kdf_ptr;
    size_t kdf_size; // Added size for KDF buffer
    const uint8_t* key_ptr;
    size_t key_size;
    bool match;
    int verify_result; // Store result from Verify
};

#endif /* _KDF_VERIFY_ASYNC_H */
