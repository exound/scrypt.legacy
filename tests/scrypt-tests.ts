// TypeScript migration of scrypt-tests.js

import { Buffer } from "node:buffer";
import { expect, use as chaiUse } from "chai";
import chaiAsPromised from "chai-as-promised";

import * as scrypt from "../";

chaiUse(chaiAsPromised);

function examine(obj: any, err?: Error | null) {
  expect(err).to.not.exist;
  expect(obj).to.be.a("Object").and.to.have.all.keys("N", "r", "p");
  expect(obj).to.have.property("N").and.to.be.a("Number");
  expect(obj).to.have.property("r").and.to.be.a("Number");
  expect(obj).to.have.property("p").and.to.be.a("Number");
}

describe("Scrypt Node Module Tests", function () {
  // Scrypt Params Function tests
  describe("Scrypt Params Function", function () {
    describe("Synchronous functionality with incorrect arguments", function () {
      it("Will throw SyntexError exception if called without arguments", function () {
        expect(() => scrypt.paramsSync()).to.throw(SyntaxError).to.match(/^SyntaxError: At least one argument is needed - the maxtime$/);
      });

      it("Will throw a RangeError exception if maxtime argument is less than zero", function () {
        expect(() => scrypt.paramsSync(-1)).to.throw(RangeError).to.match(/^RangeError: maxtime must be greater than 0$/);
      });

      it("Will throw a TypeError exception if maxmem is not an integer", function () {
        expect(() => scrypt.paramsSync(1, 2.4)).to.throw(TypeError).to.match(/^TypeError: maxmem must be an integer$/);
      });

      it("Will throw a RangeError exception if maxmem is less than 0", function () {
        expect(() => scrypt.paramsSync(1, -2)).to.throw(RangeError).to.match(/^RangeError: maxmem must be greater than or equal to 0$/);
      });

      it("Will throw a RangeError exception if max_memfrac is not between 0.0 and 1.0", function () {
        expect(() => scrypt.paramsSync(1, 2, -0.1)).to.throw(RangeError).to.match(/^RangeError: max_memfrac must be between 0.0 and 1.0 inclusive$/);
        expect(() => scrypt.paramsSync(1, 2, 1.1)).to.throw(RangeError).to.match(/^RangeError: max_memfrac must be between 0.0 and 1.0 inclusive$/);
      });

      it("Will throw a TypeError if any arguments are not numbers", function () {
        const args = [1, 2, 0.9];
        for (let i = 0; i < args.length; i++) {
          const temp = args[i];
          args[i] = "not a number" as any;
          expect(() => scrypt.paramsSync(args[0], args[1], args[2])).to.throw(TypeError).to.match(/^TypeError: (maxtime|maxmem|max_memfrac) must be a number$/);
          args[i] = temp;
        }
      });
    });

    describe("Synchronous functionality with correct arguments", function () {
      it("Should return a JSON object when only maxtime is defined", function () {
        const params = scrypt.paramsSync(1);
        examine(params);
      });

      it("Should return a JSON object when only maxtime and maxmem are defined", function () {
        const params = scrypt.paramsSync(1, 2);
        examine(params);
      });

      it("Should return a JSON object when maxtime, maxmem and max_memfrac are defined", function () {
        const params = scrypt.paramsSync(1, 2, 0.5);
        examine(params);
      });
    });

    describe("Asynchronous functionality with incorrect arguments", function () {
      let promise: any = undefined;
      before(function () {
        if (typeof Promise !== "undefined") {
          promise = Promise;
          // @ts-ignore
          (global as any).Promise = undefined;
        }
      });
      after(function () {
        if (typeof Promise === "undefined" && promise) {
          // @ts-ignore
          (global as any).Promise = promise;
        }
      });

      it("Will throw SyntexError exception if called without arguments", function () {
        expect(() => scrypt.params()).to.throw(SyntaxError).to.match(/^SyntaxError: No arguments present$/);
      });

      it("Will throw a SyntaxError if no callback function is present", function () {
        expect(() => scrypt.params(1)).to.throw(SyntaxError).to.match(/^SyntaxError: No callback function present, and Promises are not available$/);
      });

      it("Will throw a SyntaxError if callback function is the first argument present", function () {
        expect(() => scrypt.params(() => {})).to.throw(SyntaxError).to.match(/^SyntaxError: At least one argument is needed before the callback - the maxtime$/);
      });

      it("Will throw a RangeError exception if maxtime argument is less than zero", function () {
        expect(() => scrypt.params(-1, () => {})).to.throw(RangeError).to.match(/^RangeError: maxtime must be greater than 0$/);
      });

      it("Will throw a TypeError exception if maxmem is not an integer", function () {
        expect(() => scrypt.params(1, 2.4, () => {})).to.throw(TypeError).to.match(/^TypeError: maxmem must be an integer$/);
      });

      it("Will throw a RangeError exception if maxmem is less than 0", function () {
        expect(() => scrypt.params(1, -2, () => {})).to.throw(RangeError).to.match(/^RangeError: maxmem must be greater than or equal to 0$/);
      });

      it("Will throw a RangeError exception if max_memfrac is not between 0.0 and 1.0", function () {
        expect(() => scrypt.params(1, 2, -0.1, () => {})).to.throw(RangeError).to.match(/^RangeError: max_memfrac must be between 0.0 and 1.0 inclusive$/);
        expect(() => scrypt.params(1, 2, 1.1, () => {})).to.throw(RangeError).to.match(/^RangeError: max_memfrac must be between 0.0 and 1.0 inclusive$/);
      });

      it("Will throw a TypeError if any arguments are not numbers", function () {
        const args = [1, 2, 0.9];
        for (let i = 0; i < args.length; i++) {
          const temp = args[i];
          args[i] = "not a number" as any;
          expect(() => scrypt.params(args[0], args[1], args[2], () => {})).to.throw(TypeError).to.match(/^TypeError: (maxtime|maxmem|max_memfrac) must be a number$/);
          args[i] = temp;
        }
      });
    });

    describe("Asynchronous functionality with correct arguments", function () {
      it("Should return a JSON object when only maxtime is defined", function (done) {
        scrypt.params(1, (err: Error | null, params: any) => {
          examine(params, err);
          done();
        });
      });

      it("Should return a JSON object when only maxtime and maxmem are defined", function (done) {
        scrypt.params(1, 2, (err: Error | null, params: any) => {
          examine(params, err);
          done();
        });
      });

      it("Should return a JSON object when maxtime, maxmem and max_memfrac are defined", function (done) {
        scrypt.params(1, 2, 0.5, (err: Error | null, params: any) => {
          examine(params, err);
          done();
        });
      });
    });

    describe("Promise asynchronous functionality with correct arguments", function () {
      if (typeof Promise !== "undefined") {
        it("Should return a JSON object when only maxtime is defined", function (done) {
          scrypt.params(1)!.then((params: any) => {
            examine(params);
            done();
          });
        });

        it("Should return a JSON object when only maxtime and maxmem are defined", function (done) {
          scrypt.params(1, 2)!.then((params: any) => {
            examine(params);
            done();
          });
        });

        it("Should return a JSON object when maxtime, maxmem and max_memfrac are defined", function (done) {
          scrypt.params(1, 2, 0.5)!.then((params: any) => {
            examine(params);
            done();
          });
        });
      }
    });
  });

  // Scrypt KDF Function tests
  describe("Scrypt KDF Function", function () {
    describe("Synchronous functionality with incorrect arguments", function () {
      it("Will throw SyntexError exception if called without arguments", function () {
        expect(() => scrypt.kdfSync()).to.throw(SyntaxError).to.match(/^SyntaxError: At least two arguments are needed - the key and the Scrypt paramaters object$/);
      });

      it("Will throw a TypeError if the key is not a string or a Buffer object", function () {
        expect(() => scrypt.kdfSync(1123, { N: 1, r: 1, p: 1 })).to.throw(TypeError).to.match(/^TypeError: Key type is incorrect: It can only be of type string or Buffer$/);
      });

      it("Will throw a TypeError if the Scrypt params object is incorrect", function () {
        expect(() => scrypt.kdfSync("password", { N: 1, p: 1 })).to.throw(TypeError).to.match(/^TypeError: Scrypt params object does not have 'r' property present$/);
      });
    });

    describe("Synchronous functionality with correct arguments", function () {
      it("Will return a buffer object containing the KDF with a string input", function () {
        const result = scrypt.kdfSync("password", { N: 1, r: 1, p: 1 });
        expect(result).to.be.an.instanceof(Buffer);
        expect(result).to.have.length.above(0);
      });
    });

    describe("Asynchronous functionality with incorrect arguments", function () {
      let promise: any = undefined;

      before(function () {
        if (typeof Promise !== "undefined") {
          promise = Promise;
          // @ts-ignore
          (global as any).Promise = undefined;
        }
      });
      after(function () {
        if (typeof Promise === "undefined" && promise) {
          // @ts-ignore
          (global as any).Promise = promise;
        }
      });

      it("Will throw SyntexError exception if called without arguments", function () {
        expect(() => scrypt.kdf()).to.throw(SyntaxError).to.match(/^SyntaxError: No arguments present$/);
      });

      it("Will throw a SyntaxError if no callback function is present", function () {
        expect(() => scrypt.kdf(Buffer.from("password"), { N: 1, r: 1, p: 1 })).to.throw(SyntaxError).to.match(/^SyntaxError: No callback function present, and Promises are not available$/);
      });

      it("Will throw a TypeError if the key is not a string or a Buffer object", function () {
        expect(() => scrypt.kdf(1123, { N: 1, r: 1, p: 1 }, () => {})).to.throw(TypeError).to.match(/^TypeError: Key type is incorrect: It can only be of type string or Buffer$/);
      });

      it("Will throw a TypeError if the Scrypt params object is incorrect", function () {
        expect(() => scrypt.kdf("password", { N: 1, r: 1 }, () => {})).to.throw(TypeError).to.match(/^TypeError: Scrypt params object does not have 'p' property present$/);
      });
    });

    describe("Asynchronous functionality with correct arguments", function () {
      it("Will return a buffer object containing the KDF with a buffer input", function (done) {
        scrypt.kdf(Buffer.from("password"), { N: 1, r: 1, p: 1 }, (err: Error | null, result: Buffer) => {
          expect(result).to.be.an.instanceof(Buffer);
          expect(result).to.have.length.above(0);
          expect(err).to.not.exist;
          done();
        });
      });
    });

    describe("Promise asynchronous functionality with correct arguments", function () {
      if (typeof Promise !== "undefined") {
        it("Will return a buffer object containing the KDF with a buffer input", function (done) {
          scrypt.kdf(Buffer.from("password"), { N: 16, r: 1, p: 1 })!.then((result: Buffer) => {
            expect(result).to.be.an.instanceof(Buffer);
            expect(result).to.have.length.above(0);
            done();
          });
        });
      }
    });
  });

  // Scrypt Hash Function tests
  describe("Scrypt Hash Function", function () {
    describe("Create Hash", function () {
      describe("Synchronous functionality with incorrect arguments", function () {
        it("Will throw SyntexError exception if called without arguments", function () {
          expect(() => scrypt.hashSync()).to.throw(SyntaxError).to.match(/^SyntaxError: At least four arguments are needed - the key to hash, the scrypt params object, the output length of the hash and the salt$/);
        });

        it("Will throw a TypeError if the key is not a string or a Buffer object", function () {
          expect(() => scrypt.hashSync(1123, { N: 1, r: 1, p: 1 }, 32, "NaCl")).to.throw(TypeError).to.match(/^TypeError: Key type is incorrect: It can only be of type string or Buffer$/);
        });

        it("Will throw a TypeError if the Scrypt params object is incorrect", function () {
          expect(() => scrypt.hashSync("hash something", { N: 1, r: 1 }, 32, "NaCl")).to.throw(TypeError).to.match(/^TypeError: Scrypt params object does not have 'p' property present$/);
        });

        it("Will throw a TypeError if the hash length is not an integer", function () {
          expect(() => scrypt.hashSync("hash something", { N: 1, r: 1, p: 1 }, 32.5, Buffer.from("NaCl"))).to.throw(TypeError).to.match(/^TypeError: Hash length must be an integer$/);
          expect(() => scrypt.hashSync("hash something", { N: 1, r: 1, p: 1 }, "thirty-two", "NaCl")).to.throw(TypeError).to.match(/^TypeError: Hash length must be an integer$/);
        });

        it("Will throw a TypeError if the salt is not a string or a Buffer object", function () {
          expect(() => scrypt.hashSync("hash something", { N: 1, r: 1, p: 1 }, 32, 45)).to.throw(TypeError).to.match(/^TypeError: Salt type is incorrect: It can only be of type string or Buffer$/);
        });
      });

      describe("Synchronous functionality with correct arguments", function () {
        const hash_length = Math.floor(Math.random() * 100) + 1;
        it("Will return a buffer object containing the hash with a string input", function () {
          const result = scrypt.hashSync("hash something", { N: 16, r: 1, p: 1 }, hash_length, "NaCl");
          expect(result).to.be.an.instanceof(Buffer);
          expect(result).to.have.length(hash_length);
        });
      });

      describe("Asynchronous functionality with incorrect arguments", function () {
        let promise: any = undefined;
        before(function () {
          if (typeof Promise !== "undefined") {
            promise = Promise;
            // @ts-ignore
            (global as any).Promise = undefined;
          }
        });
        after(function () {
          if (typeof Promise === "undefined" && promise) {
            // @ts-ignore
            (global as any).Promise = promise;
          }
        });

        it("Will throw SyntexError exception if called without arguments", function () {
          expect(() => scrypt.hash()).to.throw(SyntaxError).to.match(/^SyntaxError: No arguments present$/);
        });

        it("Will throw a SyntaxError if no callback function is present", function () {
          expect(() => scrypt.hash("hash something", { N: 16, r: 1, p: 1 }, 64, "NaCl")).to.throw(SyntaxError).to.match(/^SyntaxError: No callback function present, and Promises are not available$/);
        });

        it("Will throw a TypeError if the key is not a string or a Buffer object", function () {
          expect(() => scrypt.hash(1123, { N: 16, r: 1, p: 1 }, 32, "NaCl", () => {})).to.throw(TypeError).to.match(/^TypeError: Key type is incorrect: It can only be of type string or Buffer$/);
        });

        it("Will throw a TypeError if the Scrypt params object is incorrect", function () {
          expect(() => scrypt.hash("hash something", { N: 16, r: 1 }, 32, "NaCl", () => {})).to.throw(TypeError).to.match(/^TypeError: Scrypt params object does not have 'p' property present$/);
        });

        it("Will throw a TypeError if the hash length is not an integer", function () {
          expect(() => scrypt.hash("hash something", { N: 16, r: 1, p: 1 }, 32.5, Buffer.from("NaCl"), () => {})).to.throw(TypeError).to.match(/^TypeError: Hash length must be an integer$/);
          expect(() => scrypt.hash("hash something", { N: 16, r: 1, p: 1 }, "thirty-two", "NaCl", () => {})).to.throw(TypeError).to.match(/^TypeError: Hash length must be an integer$/);
        });

        it("Will throw a TypeError if the salt is not a string or a Buffer object", function () {
          expect(() => scrypt.hash("hash something", { N: 16, r: 1, p: 1 }, 32, 45, () => {})).to.throw(TypeError).to.match(/^TypeError: Salt type is incorrect: It can only be of type string or Buffer$/);
        });
      });

      describe("Asynchronous functionality with correct arguments", function () {
        const hash_length = Math.floor(Math.random() * 100) + 1;
        it("Will return a buffer object containing the hash with a string input", function (done) {
          scrypt.hash("hash something", { N: 16, r: 1, p: 1 }, hash_length, "NaCl", (err: Error | null, result: Buffer) => {
            expect(result).to.be.an.instanceof(Buffer);
            expect(result).to.have.length(hash_length);
            expect(err).to.not.exist;
            done();
          });
        });
      });

      describe("Promise asynchronous functionality with correct arguments", function () {
        if (typeof Promise !== "undefined") {
          const hash_length = Math.floor(Math.random() * 100) + 1;
          it("Will return a buffer object containing the hash with a string input", function (done) {
            scrypt.hash("hash something", { N: 16, r: 1, p: 1 }, hash_length, "NaCl")!.then((result: Buffer) => {
              expect(result).to.be.an.instanceof(Buffer);
              expect(result).to.have.length(hash_length);
              done();
            });
          });
        }
      });
    });

    describe("Verify Hash", function () {
      describe("Synchronous functionality with incorrect arguments", function () {
        it("Will throw SyntexError exception if called without arguments", function () {
          expect(() => scrypt.verifyKdfSync()).to.throw(SyntaxError).to.match(/^SyntaxError: At least two arguments are needed - the KDF and the key$/);
        });

        it("Will throw a TypeError if the KDF is not a string or a Buffer object", function () {
          expect(() => scrypt.verifyKdfSync(1232, "key")).to.throw(TypeError).to.match(/^TypeError: KDF type is incorrect: It can only be of type string or Buffer$/);
        });

        it("Will throw a TypeError if the key is not a string or a Buffer object", function () {
          expect(() => scrypt.verifyKdfSync("KDF", 1232)).to.throw(TypeError).to.match(/^TypeError: Key type is incorrect: It can only be of type string or Buffer$/);
        });

        it("Will throw an Error if KDF buffer is not a valid scrypt-encrypted block", function () {
          expect(() => scrypt.verifyKdfSync("KDF", "key")).to.throw(Error).to.match(/^Error: data is not a valid scrypt-encrypted block$/);
        });
      });

      describe("Synchronous functionality with correct arguments", function () {
        const key = "kdf";
        const kdf = scrypt.kdfSync(key, { N: 16, r: 1, p: 1 });
        it("Will produce a boolean value", function () {
          expect(scrypt.verifyKdfSync(kdf, key)).to.be.a("boolean");
          expect(scrypt.verifyKdfSync(kdf, "different key")).to.be.a("boolean");
        });
      });

      describe("Asynchronous functionality with incorrect arguments", function () {
        let promise: any = undefined;
        before(function () {
          if (typeof Promise !== "undefined") {
            promise = Promise;
            // @ts-ignore
            (global as any).Promise = undefined;
          }
        });
        after(function () {
          if (typeof Promise === "undefined" && promise) {
            // @ts-ignore
            (global as any).Promise = promise;
          }
        });

        it("Will throw SyntexError exception if called without arguments", function () {
          expect(() => scrypt.verifyKdf()).to.throw(SyntaxError).to.match(/^SyntaxError: No arguments present$/);
        });

        it("Will throw a SyntaxError if no callback function is present", function () {
          const key = "kdf";
          const kdf = scrypt.kdfSync(key, { N: 16, r: 1, p: 1 });
          expect(() => scrypt.verifyKdf(kdf, key)).to.throw(SyntaxError).to.match(/^SyntaxError: No callback function present, and Promises are not available$/);
        });

        it("Will throw a TypeError if the KDF is not a string or a Buffer object", function () {
          expect(() => scrypt.verifyKdf(1232, "key", () => {})).to.throw(TypeError).to.match(/^TypeError: KDF type is incorrect: It can only be of type string or Buffer$/);
        });

        it("Will throw a TypeError if the key is not a string or a Buffer object", function () {
          expect(() => scrypt.verifyKdfSync("KDF", 1232, () => {})).to.throw(TypeError).to.match(/^TypeError: Key type is incorrect: It can only be of type string or Buffer$/);
        });

        it("Will throw an Error if KDF buffer is not a valid scrypt-encrypted block", function () {
          expect(() => scrypt.verifyKdfSync("KDF", "key", () => {})).to.throw(Error).to.match(/^Error: data is not a valid scrypt-encrypted block$/);
        });
      });

      describe("Asynchronous functionality with correct arguments", function () {
        const key = "kdf";
        const kdf = scrypt.kdfSync(key, { N: 16, r: 1, p: 1 });
        it("Will produce a boolean value", function (done) {
          scrypt.verifyKdf(kdf, key, (err: Error | null, result: boolean) => {
            expect(result).to.be.a("boolean").to.equal(true);
            expect(err).to.not.exist;
            scrypt.verifyKdf(kdf, "different key", (err2: Error | null, result2: boolean) => {
              expect(result2).to.be.a("boolean").to.equal(false);
              expect(err2).to.not.exist;
              done();
            });
          });
        });
      });

      describe("Promise asynchronous functionality with correct arguments", function () {
        const key = "kdf";
        const kdf = scrypt.kdfSync(key, { N: 16, r: 1, p: 1 });
        if (typeof Promise !== "undefined") {
          it("Will produce a boolean value", function (done) {
            scrypt.verifyKdf(kdf, key)!.then((result: boolean) => {
              expect(result).to.be.a("boolean").to.equal(true);
              scrypt.verifyKdf(kdf, "different key")!.then((result2: boolean) => {
                expect(result2).to.be.a("boolean").to.equal(false);
                done();
              });
            });
          });
        }
      });
    });
  });

  // Logic tests
  describe("Logic", function () {
    describe("Test vectors", function () {
      describe("Synchronous", function () {
        it("Vector 1: Will produce an identical vector to scrypt paper", function () {
          const result = scrypt.hashSync("", { N: 4, r: 1, p: 1 }, 64, "");
          expect(result.toString("hex")).to.equal("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906");
        });

        it("Vector 2: Will produce an identical vector to scrypt paper", function () {
          const result = scrypt.hashSync("password", { N: 10, r: 8, p: 16 }, 64, Buffer.from("NaCl"));
          expect(result.toString("hex")).to.equal("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640");
        });

        it("Vector 3: Will produce an identical vector to scrypt paper", function () {
          const result = scrypt.hashSync(Buffer.from("pleaseletmein"), { N: 14, r: 8, p: 1 }, 64, "SodiumChloride");
          expect(result.toString("hex")).to.equal("7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887");
        });
      });

      describe("Aynchronous", function () {
        it("Vector 1: Will produce an identical vector to scrypt paper", function (done) {
          scrypt.hash("", { N: 4, r: 1, p: 1 }, 64, "", (err: Error | null, result: Buffer) => {
            expect(result.toString("hex")).to.equal("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906");
            expect(err).to.not.exist;
            done();
          });
        });

        it("Vector 2: Will produce an identical vector to scrypt paper", function (done) {
          scrypt.hash(Buffer.from("password"), { N: 10, r: 8, p: 16 }, 64, Buffer.from("NaCl"), (err: Error | null, result: Buffer) => {
            expect(result.toString("hex")).to.equal("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640");
            expect(err).to.not.exist;
            done();
          });
        });

        it("Vector 3: Will produce an identical vector to scrypt paper", function (done) {
          scrypt.hash("pleaseletmein", { N: 14, r: 8, p: 1 }, 64, "SodiumChloride", (err: Error | null, result: Buffer) => {
            expect(result.toString("hex")).to.equal("7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887");
            expect(err).to.not.exist;
            done();
          });
        });
      });
    });

    describe("Kdf Logic", function () {
      describe("Synchronous", function () {
        it("Will use random salt to ensure no two KDFs are the same, even if the keys are identical", function () {
          const result1 = scrypt.kdfSync("password", { N: 16, r: 1, p: 1 });
          const result2 = scrypt.kdfSync("password", { N: 16, r: 1, p: 1 });
          expect(result1.toString("base64")).to.not.equal(result2.toString("base64"));
        });

        it("Will correctly verify hash as true if identical keys are used for kdf and verify", function () {
          const key = "this is a key";
          const kdf = scrypt.kdfSync(key, { N: 16, r: 1, p: 1 });
          const result = scrypt.verifyKdfSync(kdf, key);
          expect(result).to.be.a("boolean").to.equal(true);
        });

        it("Will correctly verify hash as false if different keys are used for kdf and verify", function () {
          const key = "this is a key";
          const kdf = scrypt.kdfSync(key, { N: 16, r: 1, p: 1 });
          const result = scrypt.verifyKdfSync(kdf, Buffer.from("Another key"));
          expect(result).to.be.a("boolean").to.equal(false);
        });
      });

      describe("Asynchronous", function () {
        it("Will use random salt to ensure no two KDFs are the same, even if the keys are identical", function (done) {
          scrypt.kdf("password", { N: 16, r: 1, p: 1 }, (err: Error | null, result1: Buffer) => {
            expect(err).to.not.exist;
            scrypt.kdf("password", { N: 16, r: 1, p: 1 }, (err2: Error | null, result2: Buffer) => {
              expect(err2).to.not.exist;
              expect(result1.toString("base64")).to.not.equal(result2.toString("base64"));
              done();
            });
          });
        });

        it("Will correctly verify hash as true if identical keys are used for kdf and verify", function (done) {
          const key = "this is a key";
          const kdf = scrypt.kdfSync(key, { N: 16, r: 1, p: 1 });
          scrypt.verifyKdf(kdf, key, (err: Error | null, result: boolean) => {
            expect(result).to.be.a("boolean").to.equal(true);
            expect(err).to.not.exist;
            done();
          });
        });

        it("Will correctly verify hash as false if different keys are used for kdf and verify", function (done) {
          const key = "this is a key";
          const kdf = scrypt.kdfSync(key, { N: 16, r: 1, p: 1 });
          scrypt.verifyKdf(kdf, "Another Key", (err: Error | null, result: boolean) => {
            expect(result).to.be.a("boolean").to.equal(false);
            expect(err).to.not.exist;
            done();
          });
        });
      });
    });

    describe("Hash Logic", function () {
      const hash_length = Math.floor(Math.random() * 100) + 1;
      describe("Synchronous", function () {
        it("Will be deterministic if salts are identical", function () {
          const result1 = scrypt.hashSync(Buffer.from("hash something"), { N: 16, r: 1, p: 1 }, hash_length, "NaCl");
          expect(result1).to.be.an.instanceof(Buffer);
          expect(result1).to.have.length(hash_length);

          const result2 = scrypt.hashSync("hash something", { N: 16, r: 1, p: 1 }, hash_length, Buffer.from("NaCl"));
          expect(result2).to.be.an.instanceof(Buffer);
          expect(result2).to.have.length(hash_length);

          expect(result1.toString("base64")).to.equal(result2.toString("base64"));
        });
      });

      describe("Asynchronous", function () {
        it("Will be deterministic if salts are identical", function (done) {
          scrypt.hash(Buffer.from("hash something"), { N: 16, r: 1, p: 1 }, hash_length, "NaCl", (err: Error | null, result1: Buffer) => {
            expect(result1).to.be.an.instanceof(Buffer);
            expect(result1).to.have.length(hash_length);
            expect(err).to.not.exist;

            scrypt.hash("hash something", { N: 16, r: 1, p: 1 }, hash_length, Buffer.from("NaCl"), (err2: Error | null, result2: Buffer) => {
              expect(result2).to.be.an.instanceof(Buffer);
              expect(result2).to.have.length(hash_length);
              expect(err2).to.not.exist;

              expect(result1.toString("base64")).to.equal(result2.toString("base64"));
              done();
            });
          });
        });
      });
    });
  });
});