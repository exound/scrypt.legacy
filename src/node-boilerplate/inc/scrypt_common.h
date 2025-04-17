/*
scrypt_common.h

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

#ifndef _SCRYPTCOMMON_H_
#define _SCRYPTCOMMON_H_

#include <napi.h> // Include Napi
#include <cstdint> // Include for uint32_t

namespace NodeScrypt {

  //
  // Holds N,r and p parameters
  //
  struct Params {
    const uint32_t N;
    const uint32_t r;
    const uint32_t p;

    // Constructor using Napi::Object
    Params(Napi::Object obj) :
      N(obj.Get("N").As<Napi::Number>().Uint32Value()),
      r(obj.Get("r").As<Napi::Number>().Uint32Value()),
      p(obj.Get("p").As<Napi::Number>().Uint32Value()) {}
  };

  //
  // Create a Scrypt error (already refactored in scrypt_common.cc, update signature here)
  //
  Napi::Error ScryptError(Napi::Env env, const unsigned int error);
};

#endif /* _SCRYPTCOMMON_H_ */
