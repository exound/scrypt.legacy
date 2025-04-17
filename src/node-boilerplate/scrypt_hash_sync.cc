#include <napi.h> // Replace nan.h and node.h
#include "scrypt_common.h" // For Params struct and ScryptError

// Scrypt is a C library and there needs c linkings
extern "C" {
  #include "hash.h" // For Hash function
}

// Synchronous Hash function using Napi
Napi::Value hashSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::HandleScope scope(env);

  // Argument validation
  if (info.Length() < 4) {
    Napi::TypeError::New(env, "Expected 4 arguments: keyBuffer, paramsObject, hashSize, saltBuffer").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (!info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Argument 1 must be a buffer (key)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (!info[1].IsObject()) {
    Napi::TypeError::New(env, "Argument 2 must be an object (params)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (!info[2].IsNumber()) {
    Napi::TypeError::New(env, "Argument 3 must be a number (hashSize)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (!info[3].IsBuffer()) {
    Napi::TypeError::New(env, "Argument 4 must be a buffer (salt)").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  //
  // Arguments from JavaScript using Napi
  //
  Napi::Buffer<uint8_t> key_buffer = info[0].As<Napi::Buffer<uint8_t>>();
  const uint8_t* key_ptr = key_buffer.Data();
  const size_t key_size = key_buffer.Length();

  const NodeScrypt::Params params(info[1].As<Napi::Object>());

  const size_t hash_size = info[2].As<Napi::Number>().Int64Value();

  Napi::Buffer<uint8_t> salt_buffer = info[3].As<Napi::Buffer<uint8_t>>();
  const uint8_t* salt_ptr = salt_buffer.Data();
  const size_t salt_size = salt_buffer.Length();

  //
  // Create result buffer using Napi
  //
  Napi::Buffer<uint8_t> hash_result_buffer = Napi::Buffer<uint8_t>::New(env, hash_size);
  uint8_t* hash_ptr = hash_result_buffer.Data();

  //
  // Scrypt hash function
  // Assuming signature: Hash(key_ptr, key_size, salt_ptr, salt_size, params.N, params.r, params.p, hash_ptr, hash_size)
  //
  const unsigned int result = Hash(key_ptr, key_size, salt_ptr, salt_size, params.N, params.r, params.p, hash_ptr, hash_size);

  //
  // Error handling using Napi
  //
  if (result) {
    NodeScrypt::ScryptError(env, result).ThrowAsJavaScriptException();
    return env.Undefined(); // Return undefined on error
  }

  return hash_result_buffer; // Return the result buffer
}
