#include "scrypt_kdf-verify_async.h" // Includes napi.h, keyderivation.h, etc.

// Asynchronous KDF Verification function using Napi
Napi::Value kdfVerify(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  // Argument validation
  if (info.Length() < 3) {
    Napi::TypeError::New(env, "Expected 3 arguments: kdfBuffer, keyBuffer, callback").ThrowAsJavaScriptException();
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
  if (!info[2].IsFunction()) {
    Napi::TypeError::New(env, "Argument 3 must be a function (callback)").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  // Create and queue the worker
  ScryptKDFVerifyAsyncWorker* worker = new ScryptKDFVerifyAsyncWorker(info);
  worker->Queue();

  // Return undefined, result is handled by the callback
  return env.Undefined();
}
