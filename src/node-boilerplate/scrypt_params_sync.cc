#include <napi.h> // Replace nan.h and node.h
#include "scrypt_common.h" // For ScryptError

// Scrypt is a C library and there needs c linkings
extern "C" {
  #include "pickparams.h"
}

// Synchronous access to scrypt params using Napi
Napi::Value paramsSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::HandleScope scope(env); // Napi HandleScope

  // Basic argument validation
  if (info.Length() < 4 || !info[0].IsNumber() || !info[1].IsNumber() || !info[2].IsNumber() || !info[3].IsNumber()) {
      Napi::TypeError::New(env, "Expected 4 numeric arguments: maxtime, maxmemfrac, maxmem, osfreemem").ThrowAsJavaScriptException();
      return env.Undefined();
  }

  //
  // Variable Declaration
  //
  int logN = 0;
  uint32_t r = 0;
  uint32_t p = 0;

  //
  // Arguments from JavaScript using Napi
  //
  const double maxtime = info[0].As<Napi::Number>().DoubleValue();
  const double maxmemfrac = info[1].As<Napi::Number>().DoubleValue();
  // Use Int64Value for size_t, assuming it fits within Node.js limits
  const size_t maxmem = info[2].As<Napi::Number>().Int64Value();
  const size_t osfreemem = info[3].As<Napi::Number>().Int64Value();


  //
  // Scrypt: calculate input parameters
  //
  const unsigned int result = pickparams(&logN, &r, &p, maxtime, maxmem, maxmemfrac, osfreemem);

  //
  // Error handling using Napi
  //
  if (result) {
    // Use the ScryptError function (already refactored) from scrypt_common.cc
    NodeScrypt::ScryptError(env, result).ThrowAsJavaScriptException();
    return env.Undefined(); // Return undefined on error
  }

  //
  // Return values in JSON object using Napi
  //
  Napi::Object obj = Napi::Object::New(env);
  obj.Set(Napi::String::New(env, "N"), Napi::Number::New(env, logN));
  obj.Set(Napi::String::New(env, "r"), Napi::Number::New(env, r));
  obj.Set(Napi::String::New(env, "p"), Napi::Number::New(env, p));

  return obj; // Return the result object
}
