// TypeScript migration of index.js

import * as Os from "node:os";
import * as Crypto from "node:crypto";
import scryptNative from "./build/Release/scrypt.node";

interface ScryptParams {
  N: number;
  r: number;
  p: number;
  [key: string]: any;
}

type Callback<T> = (err: Error | null, result?: T) => void;

function checkNumberOfArguments(args: any[], message = "No arguments present", numberOfArguments = 1): void {
  if (args.length < numberOfArguments) {
    throw new SyntaxError(message);
  }
}

function checkAsyncArguments(args: any[], callback_least_needed_pos: number, message: string): number | undefined {
  checkNumberOfArguments(args);

  let callback_index: number | undefined = undefined;
  for (let i = 0; i < args.length; i++) {
    if (typeof args[i] === "function") {
      callback_index = i;
      break;
    }
  }

  if (callback_index === undefined) {
    if (typeof Promise !== "undefined") return undefined;
    throw new SyntaxError("No callback function present, and Promises are not available");
  }

  if (callback_index < callback_least_needed_pos) {
    throw new SyntaxError(message);
  }

  return callback_index;
}

function checkScryptParametersObject(params: any): void {
  let error: Error | undefined = undefined;

  if (typeof params !== "object") {
    error = new TypeError("Scrypt parameters type is incorrect: It must be a JSON object");
  }

  if (!error && !Object.prototype.hasOwnProperty.call(params, "N")) {
    error = new TypeError("Scrypt params object does not have 'N' property present");
  }

  if (!error && params.N !== parseInt(params.N)) {
    error = new TypeError("Scrypt params object 'N' property is not an integer");
  }

  if (!error && !Object.prototype.hasOwnProperty.call(params, "r")) {
    error = new TypeError("Scrypt params object does not have 'r' property present");
  }

  if (!error && params.r !== parseInt(params.r)) {
    error = new TypeError("Scrypt params object 'r' property is not an integer");
  }

  if (!error && !Object.prototype.hasOwnProperty.call(params, "p")) {
    error = new TypeError("Scrypt params object does not have 'p' property present");
  }

  if (!error && params.p !== parseInt(params.p)) {
    error = new TypeError("Scrypt params object 'p' property is not an integer");
  }

  if (error) {
    (error as any).propertyName = "Scrypt parameters object";
    (error as any).propertyValue = params;
    throw error;
  }
}

function processParamsArguments(args: any[]): any[] {
  let error: Error | undefined = undefined;

  checkNumberOfArguments(args, "At least one argument is needed - the maxtime", 1);

  if (args[1] === undefined) args[1] = 0;
  if (args[2] === undefined) args[2] = 0.5;

  for (let i = 0; i < Math.min(3, args.length); i++) {
    const propertyName = i === 0 ? "maxtime" : i === 1 ? "maxmem" : "max_memfrac";

    if (!error && typeof args[i] !== "number") {
      error = new TypeError(`${propertyName} must be a number`);
    }

    if (!error) {
      switch (i) {
        case 0:
          if (args[0] <= 0) error = new RangeError(`${propertyName} must be greater than 0`);
          break;
        case 1:
          if (!Number.isInteger(args[1])) error = new TypeError(`${propertyName} must be an integer`);
          if (!error && args[1] < 0) error = new RangeError(`${propertyName} must be greater than or equal to 0`);
          break;
        case 2:
          if (args[2] < 0.0 || args[2] > 1.0) error = new RangeError(`${propertyName} must be between 0.0 and 1.0 inclusive`);
          break;
      }
    }

    if (error) {
      (error as any).propertyName = propertyName;
      (error as any).propertyValue = args[i];
      throw error;
    }
  }

  return args;
}

function processKDFArguments(args: any[]): any[] {
  checkNumberOfArguments(args, "At least two arguments are needed - the key and the Scrypt paramaters object", 2);

  if (typeof args[0] === "string") args[0] = Buffer.from(args[0]);
  else if (!Buffer.isBuffer(args[0])) {
    const error = new TypeError("Key type is incorrect: It can only be of type string or Buffer");
    (error as any).propertyName = "key";
    (error as any).propertyValue = args[0];
    throw error;
  }

  checkScryptParametersObject(args[1]);
  return args;
}

function processVerifyArguments(args: any[]): any[] {
  checkNumberOfArguments(args, "At least two arguments are needed - the KDF and the key", 2);

  if (typeof args[0] === "string") args[0] = Buffer.from(args[0]);
  else if (!Buffer.isBuffer(args[0])) {
    const error = new TypeError("KDF type is incorrect: It can only be of type string or Buffer");
    (error as any).propertyName = "KDF";
    (error as any).propertyValue = args[0];
    throw error;
  }

  if (typeof args[1] === "string") args[1] = Buffer.from(args[1]);
  else if (!Buffer.isBuffer(args[1])) {
    const error = new TypeError("Key type is incorrect: It can only be of type string or Buffer");
    (error as any).propertyName = "key";
    (error as any).propertyValue = args[1];
    throw error;
  }

  return args;
}

function processHashArguments(args: any[]): any[] {
  checkNumberOfArguments(args, "At least four arguments are needed - the key to hash, the scrypt params object, the output length of the hash and the salt", 4);

  if (typeof args[0] === "string") args[0] = Buffer.from(args[0]);
  else if (!Buffer.isBuffer(args[0])) {
    const error = new TypeError("Key type is incorrect: It can only be of type string or Buffer");
    (error as any).propertyName = "KDF";
    (error as any).propertyValue = args[0];
    throw error;
  }

  checkScryptParametersObject(args[1]);

  if (typeof args[2] !== "number" || !Number.isInteger(args[2])) {
    throw new TypeError("Hash length must be an integer");
  }

  if (typeof args[3] === "string") args[3] = Buffer.from(args[3]);
  else if (!Buffer.isBuffer(args[3])) {
    const error = new TypeError("Salt type is incorrect: It can only be of type string or Buffer");
    (error as any).propertyName = "salt";
    (error as any).propertyValue = args[3];
    throw error;
  }

  return args;
}

export function paramsSync(...args: any[]): ScryptParams {
  const processed = processParamsArguments(args);
  return scryptNative.paramsSync(processed[0], processed[1], processed[2], Os.totalmem());
}

export function params(...args: any[]): Promise<ScryptParams> | void {
  const callback_index = checkAsyncArguments(args, 1, "At least one argument is needed before the callback - the maxtime");

  if (callback_index === undefined) {
    return new Promise((resolve, reject) => {
      const processed = processParamsArguments(args);
      scryptNative.params(processed[0], processed[1], processed[2], Os.totalmem(), (err: Error | null, params: ScryptParams) => {
        if (err) reject(err);
        else resolve(params);
      });
    });
  } else {
    const callback = args[callback_index];
    delete args[callback_index];
    const processed = processParamsArguments(args);
    processed[3] = callback;
    scryptNative.params(processed[0], processed[1], processed[2], Os.totalmem(), processed[3]);
  }
}

export function kdfSync(...args: any[]): Buffer {
  const processed = processKDFArguments(args);
  return scryptNative.kdfSync(processed[0], processed[1], Crypto.randomBytes(256));
}

export function kdf(...args: any[]): Promise<Buffer> | void {
  const callback_index = checkAsyncArguments(args, 2, "At least two arguments are needed before the call back function - the key and the Scrypt parameters object");

  const processed = processKDFArguments(args);

  if (callback_index === undefined) {
    return new Promise((resolve, reject) => {
      Crypto.randomBytes(256, (err, salt) => {
        if (err) reject(err);
        else {
          scryptNative.kdf(processed[0], processed[1], salt, (err: Error | null, kdfResult: Buffer) => {
            if (err) reject(err);
            else resolve(kdfResult);
          });
        }
      });
    });
  } else {
    Crypto.randomBytes(256, (err, salt) => {
      if (err) processed[2](err);
      else scryptNative.kdf(processed[0], processed[1], salt, processed[2]);
    });
  }
}

export function verifyKdfSync(...args: any[]): boolean {
  const processed = processVerifyArguments(args);
  return scryptNative.verifySync(processed[0], processed[1]);
}

export function verifyKdf(...args: any[]): Promise<boolean> | void {
  const callback_index = checkAsyncArguments(args, 2, "At least two arguments are needed before the callback function - the KDF and the key");

  if (callback_index === undefined) {
    return new Promise((resolve, reject) => {
      const processed = processVerifyArguments(args);
      scryptNative.verify(processed[0], processed[1], (err: Error | null, match: boolean) => {
        if (err) reject(err);
        else resolve(match);
      });
    });
  } else {
    const processed = processVerifyArguments(args);
    scryptNative.verify(processed[0], processed[1], processed[2]);
  }
}

export function hashSync(...args: any[]): Buffer {
  const processed = processHashArguments(args);
  return scryptNative.hashSync(processed[0], processed[1], processed[2], processed[3]);
}

export function hash(...args: any[]): Promise<Buffer> | void {
  const callback_index = checkAsyncArguments(args, 4, "At least four arguments are needed before the callback - the key to hash, the scrypt params object, the output length of the hash and the salt");

  const processed = processHashArguments(args);

  if (callback_index === undefined) {
    return new Promise((resolve, reject) => {
      scryptNative.hash(processed[0], processed[1], processed[2], processed[3], (err: Error | null, hash: Buffer) => {
        if (err) reject(err);
        else resolve(hash);
      });
    });
  } else {
    scryptNative.hash(processed[0], processed[1], processed[2], processed[3], processed[4]);
  }
}