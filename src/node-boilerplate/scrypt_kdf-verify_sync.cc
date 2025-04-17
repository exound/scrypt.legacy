#include <napi.h> // Replace nan.h and node.h
#include "scrypt_common.h" // For ScryptError

// Scrypt is a C library and there needs c linkings
extern "C" {
  #include "keyderivation.h" // For Verify function
}

// Synchronous KDF Verification function using Napi
Napi::Value kdfVerifySync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::HandleScope scope(env);

  // Argument validation
  if (info.Length() < 2) {
    Napi::TypeError::New(env, "Expected 2 arguments: kdfBuffer, keyBuffer").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (!info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Argument 1 must be a buffer (KDF)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (!info[1].IsBuffer()) {
    Napi::TypeError::New(env, "Argument 2 must be a buffer (key)").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  //
  // Arguments from JavaScript using Napi
  //
  Napi::Buffer<uint8_t> kdf_buffer = info[0].As<Napi::Buffer<uint8_t>>();
  const uint8_t* kdf_ptr = kdf_buffer.Data();
  // Assuming Verify needs the KDF buffer size - Not needed for Verify(kdf_ptr, key_ptr, key_size)
  // const size_t kdf_size = kdf_buffer.Length(); // Unused variable

  Napi::Buffer<uint8_t> key_buffer = info[1].As<Napi::Buffer<uint8_t>>();
  const uint8_t* key_ptr = key_buffer.Data();
  const size_t key_size = key_buffer.Length();

  //
  // Scrypt KDF Verification
  // Assuming Verify takes kdf_ptr, kdf_size, key_ptr, key_size
  //
  const unsigned int result = Verify(kdf_ptr, key_ptr, key_size);

  //
  // Return result (or error) using Napi
  //
  if (result && result != 11) { // 11 is the "error" code for an incorrect match
    NodeScrypt::ScryptError(env, result).ThrowAsJavaScriptException();
    return env.Undefined(); // Return undefined on error
  }

  // Return true if result is 0 (match), false otherwise (including mismatch code 11)
  return Napi::Boolean::New(env, (result == 0));
}
