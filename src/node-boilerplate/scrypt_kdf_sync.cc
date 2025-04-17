#include <napi.h> // Replace nan.h and node.h
#include "scrypt_common.h" // For Params struct and ScryptError

// Scrypt is a C library and there needs c linkings
extern "C" {
	#include "keyderivation.h" // For KDF function
}

// Synchronous Scrypt KDF function using Napi
Napi::Value kdfSync(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::HandleScope scope(env);

    // Argument validation
    if (info.Length() < 3) {
        Napi::TypeError::New(env, "Expected 3 arguments: keyBuffer, paramsObject, saltBuffer").ThrowAsJavaScriptException();
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

    //
    // Arguments from JavaScript using Napi
    //
    Napi::Buffer<uint8_t> key_buffer = info[0].As<Napi::Buffer<uint8_t>>();
    const uint8_t* key_ptr = key_buffer.Data();
    const size_t keySize = key_buffer.Length();

    // Use the Params constructor (already refactored)
    const NodeScrypt::Params params(info[1].As<Napi::Object>());

    Napi::Buffer<uint8_t> salt_buffer = info[2].As<Napi::Buffer<uint8_t>>();
    const uint8_t* salt_ptr = salt_buffer.Data();
    // Note: KDF wrapper might not need salt size explicitly, unlike crypto_scrypt

    //
    // Create result buffer using Napi (size hardcoded as 96 in original)
    //
    size_t result_size = 96;
    Napi::Buffer<uint8_t> kdfResultBuffer = Napi::Buffer<uint8_t>::New(env, result_size);
    uint8_t* kdfResult_ptr = kdfResultBuffer.Data();


    //
    // Scrypt key derivation function (using the existing KDF wrapper)
    //
    const unsigned int result = KDF(key_ptr, keySize, kdfResult_ptr, params.N, params.r, params.p, salt_ptr);

    //
    // Error handling using Napi
    //
    if (result) {
        NodeScrypt::ScryptError(env, result).ThrowAsJavaScriptException();
        return env.Undefined(); // Return undefined on error
    }

    return kdfResultBuffer; // Return the result buffer
}
