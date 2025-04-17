/*
scrypt_hash_async.cc

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

#include "scrypt_hash_async.h" // Includes napi.h, scrypt_common.h, hash.h

// Asynchronous Hash function using Napi
Napi::Value hash(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  // Argument validation
  if (info.Length() < 5) {
    Napi::TypeError::New(env, "Expected 5 arguments: keyBuffer, paramsObject, hashSize, saltBuffer, callback").ThrowAsJavaScriptException();
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
  if (!info[4].IsFunction()) {
    Napi::TypeError::New(env, "Argument 5 must be a function (callback)").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  // Create and queue the worker
  ScryptHashAsyncWorker* worker = new ScryptHashAsyncWorker(info);
  worker->Queue();

  // Return undefined, result is handled by the callback
  return env.Undefined();
}
