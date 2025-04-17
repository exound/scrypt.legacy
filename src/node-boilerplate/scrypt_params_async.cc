#include "scrypt_params_async.h" // Includes napi.h and pickparams.h transitively

// Asynchronous access to scrypt params using Napi
Napi::Value params(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  // Basic argument validation (ensure callback is a function)
  if (info.Length() < 5 || !info[4].IsFunction()) {
    Napi::TypeError::New(env, "Callback function expected as fifth argument").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  // TODO: Add more robust validation for other arguments (types, ranges) if needed

  // Create and queue the worker
  ScryptParamsAsyncWorker* worker = new ScryptParamsAsyncWorker(info);
  worker->Queue();

  // Return undefined, the result is passed asynchronously via the callback
  return env.Undefined();
}
