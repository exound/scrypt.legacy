// Type definitions for the native scrypt module

export interface ScryptParams {
  N: number;
  r: number;
  p: number;
  [key: string]: any;
}

export function paramsSync(
  maxtime: number,
  maxmem?: number,
  max_memfrac?: number,
  totalmem?: number
): ScryptParams;

export function params(
  maxtime: number,
  maxmem?: number,
  max_memfrac?: number,
  totalmem?: number,
  cb?: (err: Error | null, params: ScryptParams) => void
): void | Promise<ScryptParams>;

export function kdfSync(
  key: Buffer | string,
  params: ScryptParams,
  salt?: Buffer
): Buffer;

export function kdf(
  key: Buffer | string,
  params: ScryptParams,
  cb: (err: Error | null, kdfResult: Buffer) => void
): void;
export function kdf(
  key: Buffer | string,
  params: ScryptParams
): Promise<Buffer>;

export function verifyKdfSync(
  kdf: Buffer | string,
  key: Buffer | string
): boolean;

export function verifyKdf(
  kdf: Buffer | string,
  key: Buffer | string,
  cb: (err: Error | null, match: boolean) => void
): void;
export function verifyKdf(
  kdf: Buffer | string,
  key: Buffer | string
): Promise<boolean>;

export function hashSync(
  key: Buffer | string,
  params: ScryptParams,
  outlen: number,
  salt: Buffer | string
): Buffer;

export function hash(
  key: Buffer | string,
  params: ScryptParams,
  outlen: number,
  salt: Buffer | string,
  cb: (err: Error | null, hash: Buffer) => void
): void;
export function hash(
  key: Buffer | string,
  params: ScryptParams,
  outlen: number,
  salt: Buffer | string
): Promise<Buffer>;