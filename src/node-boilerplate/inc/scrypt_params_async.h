/*
scrypt_params_async.h

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

#ifndef _SCRYPT_PARAMS_ASYNC_H
#define _SCRYPT_PARAMS_ASYNC_H

#include <napi.h> // Replace scrypt_async.h and nan includes implicitly
#include <string> // For std::to_string in error handling

// Scrypt is a C library and there needs c linkings
extern "C" {
  #include "pickparams.h" // Keep C library include
}

// Async class derived from Napi::AsyncWorker
class ScryptParamsAsyncWorker : public Napi::AsyncWorker {
  public:
    ScryptParamsAsyncWorker(const Napi::CallbackInfo& info) :
      Napi::AsyncWorker(info[4].As<Napi::Function>()), // Pass callback directly
      maxtime(info[0].As<Napi::Number>().DoubleValue()),
      maxmemfrac(info[1].As<Napi::Number>().DoubleValue()),
      maxmem(info[2].As<Napi::Number>().Int64Value()), // Assuming size_t fits int64_t for Node.js limits
      osfreemem(info[3].As<Napi::Number>().Int64Value()) // Assuming size_t fits int64_t
    {
      logN = 0;
      r = 0;
      p = 0;
      result = 0; // Initialize result
    }

    ~ScryptParamsAsyncWorker() {} // Destructor needed for Napi::AsyncWorker

    // This method is executed in a separate thread.
    void Execute() override {
      // Scrypt: calculate input parameters
      result = pickparams(&logN, &r, &p, maxtime, maxmem, maxmemfrac, osfreemem);
      // Check for errors from pickparams if necessary
      if (result != 0) {
         // SetError can be used to signal failure to OnError
         SetError("Scrypt pickparams failed with error code: " + std::to_string(result));
      }
    }

    // This method is executed in the main thread after Execute() completes.
    void OnOK() override {
      Napi::Env env = Env();
      Napi::HandleScope scope(env);

      // Returned params in JSON object
      Napi::Object obj = Napi::Object::New(env);
      obj.Set(Napi::String::New(env, "N"), Napi::Number::New(env, logN));
      obj.Set(Napi::String::New(env, "r"), Napi::Number::New(env, r));
      obj.Set(Napi::String::New(env, "p"), Napi::Number::New(env, p));

      // Call the JS callback with null error and the result object
      Callback().Call({env.Null(), obj});
    }

    // Optional: Handle errors if Execute fails
    void OnError(const Napi::Error& e) override {
        Napi::Env env = Env();
        Napi::HandleScope scope(env);
        // Call the JS callback with the error object
        Callback().Call({e.Value(), env.Undefined()});
    }


  private:
    const double maxtime;
    const double maxmemfrac;
    const size_t maxmem;
    const size_t osfreemem;

    int logN;
    uint32_t r;
    uint32_t p;
    int result; // Store result from pickparams
};

#endif /* _SCRYPT_PARAMS_ASYNC_H */
