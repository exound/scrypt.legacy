#include "scrypt_kdf_async.h" // Includes napi.h, scrypt_common.h, keyderivation.h

// Asynchronous KDF function using Napi
Napi::Value kdf(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  // Argument validation
  if (info.Length() < 4) {
    Napi::TypeError::New(env, "Expected 4 arguments: keyBuffer, paramsObject, saltBuffer, callback").ThrowAsJavaScriptException();
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
  if (!info[2].IsBuffer()) {
    Napi::TypeError::New(env, "Argument 3 must be a buffer (salt)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (!info[3].IsFunction()) {
    Napi::TypeError::New(env, "Argument 4 must be a function (callback)").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  // Create and queue the worker
  ScryptKDFAsyncWorker* worker = new ScryptKDFAsyncWorker(info);
  worker->Queue();

  // Return undefined, result is handled by the callback
  return env.Undefined();
}
