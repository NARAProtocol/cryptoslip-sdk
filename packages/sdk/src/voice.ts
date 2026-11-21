import { p256, hashToCurve } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import * as scryptMod from 'scrypt-js';

const scrypt: typeof scryptMod.scrypt =
  (scryptMod as unknown as { default?: { scrypt: typeof scryptMod.scrypt } }).default?.scrypt ??
  scryptMod.scrypt;
import {
  bytesToHex as viemBytesToHex,
  formatUnits,
  getAddress,
  isHex,
  recoverMessageAddress,
  type Address,
  type Hex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import {
  BASE_CHAIN_ID,
  CANONICAL_SHARE_ORIGIN,
  ISSUE_VAULT,
  VAULTS,
  VOICE_GATEWAY_URL,
  VOICE_MIN_USD_MICRO,
  decimalsForAsset,
  normalizeSdkAsset,
  resolveAssetMetadata,
  vaultTagForAddress,
  type AnyAssetSymbol,
  type SdkAssetSymbol,
  type VaultTag,
} from './constants.js';
import {
  assertFragmentSafeUrl,
  encodeSlipUrl,
  isWellFormedClaimCode,
  normalizeClaimCode,
  parseSlipUrl,
} from './link.js';

export { VOICE_GATEWAY_URL, VOICE_MIN_USD_MICRO } from './constants.js';
export { VOICE_KEY_FRAGMENT_RE } from './link.js';

// ============================================================================
// Wire Constants (`shared/voiceEnvelope.mjs` + 32 KB SDK Block-Padding)
// ============================================================================

/** Exact 32 KB (`32,768` bytes) plaintext block quantum for `encryptVoiceEnvelope` / `decryptVoiceEnvelope`. */
export const VOICE_ENVELOPE_BLOCK_BYTES = 32_768 as const;
export const VOICE_ENVELOPE_MAX_AUDIO_BYTES = 10 * 1024 * 1024; // 10 MiB safety ceiling

export const VOICE_CSV1_MAGIC = new Uint8Array([0x43, 0x53, 0x56, 0x31]); // "CSV1"
export const VOICE_CSV2_MAGIC = new Uint8Array([0x43, 0x53, 0x56, 0x32]); // "CSV2" (32 KB padded MIME envelope)
export const VOICE_UPLOAD_MAGIC = new Uint8Array([0x43, 0x53, 0x56, 0x45]); // "CSVE"

export const VOICE_FORMAT_VERSION = 1 as const;
export const VOICE_UPLOAD_VERSION = 1 as const;
export const VOICE_CODEC_IMA_ADPCM_12K = 1 as const;
export const VOICE_CODEC_RAW_OPAQUE = 2 as const;
export const VOICE_SAMPLE_RATE = 12_000 as const;
export const VOICE_MIN_DURATION_MS = 300 as const;
export const VOICE_MAX_DURATION_MS = 10_000 as const;

export const VOICE_CSV1_HEADER_BYTES = 16 as const;
export const VOICE_CSV1_MAX_AUDIO_BYTES = 60_016 as const;
export const VOICE_CSV1_PLAINTEXT_BYTES = 60_032 as const; // 16 + 60,016
export const VOICE_GCM_IV_BYTES = 12 as const;
export const VOICE_GCM_TAG_BYTES = 16 as const;
export const VOICE_ENCRYPTED_PAYLOAD_BYTES = 60_060 as const; // 12 + 60,032 + 16
export const VOICE_UPLOAD_HEADER_BYTES = 106 as const;
export const VOICE_UPLOAD_ENVELOPE_BYTES = 60_166 as const; // 106 + 60,060

export const VOICE_MIN_TTL_SEC = 3_600 as const;
export const VOICE_DEFAULT_TTL_SEC = 7 * 86_400; // 604,800s (7 days)
export const VOICE_MAX_TTL_SEC = 7 * 86_400;
export const VOICE_ACTION_MAX_SKEW_SEC = 120 as const;
export const VOICE_SHARD_COUNT = 64 as const;

const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_HALF_N = SECP256K1_N >> 1n;
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

const SCRYPT_N = 1 << 14;
const SCRYPT_R = 8;
const SCRYPT_P = 1;

const HEX64_RE = /^[0-9a-f]{64}$/;
const HEX32_RE = /^[0-9a-f]{32}$/;
const SIG65_RE = /^0x[0-9a-f]{130}$/;
const HOST_RE = /^[a-z0-9.-]{1,128}(?::\d{1,5})?$/;
const B64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const te = new TextEncoder();
const td = new TextDecoder();

// ============================================================================
// Pure Zero-DOM Byte, Base64Url & Zeroization Utilities
// ============================================================================

function utf8Bytes(str: string): Uint8Array {
  return te.encode(str);
}

function concatUint8(...parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function rawBytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += (bytes[i] ?? 0).toString(16).padStart(2, '0');
  }
  return s;
}

function rawHexToBytes(hex: string, expectedLen?: number): Uint8Array {
  const clean = String(hex || '').replace(/^0x/i, '').trim().toLowerCase();
  if (clean.length % 2 !== 0 || !/^[0-9a-f]*$/.test(clean)) {
    throw new Error('Voice note could not be accepted');
  }
  const len = clean.length / 2;
  if (expectedLen !== undefined && len !== expectedLen) {
    throw new Error('Voice note could not be accepted');
  }
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function voiceBytesToBase64Url(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  while (i + 2 < bytes.length) {
    const n = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out +=
      (B64URL_ALPHABET[(n >> 18) & 63] ?? '') +
      (B64URL_ALPHABET[(n >> 12) & 63] ?? '') +
      (B64URL_ALPHABET[(n >> 6) & 63] ?? '') +
      (B64URL_ALPHABET[n & 63] ?? '');
    i += 3;
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = (bytes[i] ?? 0) << 16;
    out += (B64URL_ALPHABET[(n >> 18) & 63] ?? '') + (B64URL_ALPHABET[(n >> 12) & 63] ?? '');
  } else if (rem === 2) {
    const n = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8);
    out +=
      (B64URL_ALPHABET[(n >> 18) & 63] ?? '') +
      (B64URL_ALPHABET[(n >> 12) & 63] ?? '') +
      (B64URL_ALPHABET[(n >> 6) & 63] ?? '');
  }
  return out;
}

export function voiceBase64UrlToBytes(str: string): Uint8Array {
  const clean = String(str || '').trim();
  if (!clean || !/^[A-Za-z0-9_-]+$/.test(clean) || clean.length % 4 === 1) {
    throw new Error('Voice note could not be accepted');
  }
  const outLen = Math.floor((clean.length * 3) / 4);
  const out = new Uint8Array(outLen);
  let outIdx = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < clean.length; i++) {
    const val = B64URL_ALPHABET.indexOf(clean[i] ?? '');
    if (val < 0) throw new Error('Voice note could not be accepted');
    acc = (acc << 6) | val;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (outIdx < outLen) {
        out[outIdx++] = (acc >> bits) & 0xff;
      }
    }
  }
  return out;
}

function constantTimeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

function fillRandomBytes(target: Uint8Array): Uint8Array {
  const cryptoObj = globalThis.crypto;
  if (!cryptoObj || typeof cryptoObj.getRandomValues !== 'function') {
    throw new Error('WebCrypto CSPRNG is required for encrypted voice notes');
  }
  // WebCrypto getRandomValues caps each call at 65,536 bytes
  const MAX_CHUNK = 65_536;
  for (let offset = 0; offset < target.length; offset += MAX_CHUNK) {
    const chunkLen = Math.min(MAX_CHUNK, target.length - offset);
    const chunk = new Uint8Array(chunkLen);
    cryptoObj.getRandomValues(chunk);
    target.set(chunk, offset);
    chunk.fill(0);
  }
  return target;
}

/** Ensures a `Uint8Array` backed by a plain `ArrayBuffer` for strict TS 6 WebCrypto `BufferSource` signatures. */
function toWebCryptoBytes(src: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(src.byteLength);
  copy.set(src);
  return copy;
}

/**
 * Deterministically overwrites sensitive key/plaintext typed arrays with zeros in place.
 */
export function zeroizeVoiceBuffers(
  ...buffers: Array<{ fill(value: number): unknown } | null | undefined>
): void {
  for (const buf of buffers) {
    if (buf && typeof buf.fill === 'function') {
      try {
        buf.fill(0);
      } catch {
        // Best-effort zeroization on detached/frozen views
      }
    }
  }
}

// ============================================================================
// $1.00+ Economic Anti-Spam Floor (`workers/cryptoslip-voice/index.ts:100, 263`)
// ============================================================================

/**
 * Exact minimum token units corresponding to the `$1.00` USD anti-spam floor enforced by
 * `workers/cryptoslip-voice/index.ts:100-105`.
 */
export const VOICE_MIN_TOKEN_AMOUNTS_AT_1_USD: Readonly<Record<SdkAssetSymbol, bigint>> = {
  USDC: 1_000_000n, // $1.00 USDC (6 decimals)
  ETH: 400_000_000_000_000n, // 0.0004 ETH (~$1.00 at $2,500/ETH)
  cbBTC: 1_000n, // 1,000 sats (~$1.00 at $100k/BTC)
  NARA: 400_000_000_000_000n, // 0.0004 NARA
} as const;

export class VoiceEconomicFloorError extends Error {
  readonly asset: SdkAssetSymbol;
  readonly amount: bigint;
  readonly requiredAmount: bigint;
  readonly minUsdMicro: bigint;

  constructor(params: {
    asset: SdkAssetSymbol;
    amount: bigint;
    requiredAmount: bigint;
    minUsdMicro: bigint;
  }) {
    const dec = decimalsForAsset(params.asset);
    super(
      `Encrypted voice notes require a slip value of at least ${formatUnits(params.requiredAmount, dec)} ${params.asset} ($1.00 USD floor); received ${formatUnits(params.amount, dec)} ${params.asset}.`,
    );
    this.name = 'VoiceEconomicFloorError';
    this.asset = params.asset;
    this.amount = params.amount;
    this.requiredAmount = params.requiredAmount;
    this.minUsdMicro = params.minUsdMicro;
  }
}

/**
 * Computes the exact minimum raw token amount required for a voice-enabled slip at `minUsdMicro`
 * (defaults to `VOICE_MIN_USD_MICRO = 1_000_000n` = `$1.00`).
 * Byte-for-byte parity with `workers/cryptoslip-voice/index.ts:271`.
 */
export function minVoiceSlipAmount(
  assetOrAddress: AnyAssetSymbol | string,
  minUsdMicro: bigint = VOICE_MIN_USD_MICRO,
): bigint {
  if (minUsdMicro <= 0n) return 1n;
  const meta = resolveAssetMetadata(assetOrAddress);
  const baseAt1Usd = VOICE_MIN_TOKEN_AMOUNTS_AT_1_USD[meta.symbol];
  return (baseAt1Usd * minUsdMicro + 999_999n) / 1_000_000n;
}

/**
 * Returns `true` iff `rawAmount` meets the `$1.00+` USD equivalent voice floor (`workers/cryptoslip-voice/index.ts:262`).
 */
export function meetsVoiceEconomicFloor(
  assetOrAddress: AnyAssetSymbol | string,
  rawAmount: bigint,
  minUsdMicro: bigint = VOICE_MIN_USD_MICRO,
): boolean {
  if (rawAmount <= 0n) return false;
  if (minUsdMicro <= 0n) return true;
  try {
    const required = minVoiceSlipAmount(assetOrAddress, minUsdMicro);
    return rawAmount >= required;
  } catch {
    return false;
  }
}

/**
 * Hard-enforces the `>= $1.00` USD equivalent slip value floor before encrypting or uploading audio.
 */
export function assertVoiceEconomicFloor(
  assetOrAddress: AnyAssetSymbol | string,
  rawAmount: bigint,
  minUsdMicro: bigint = VOICE_MIN_USD_MICRO,
): void {
  const meta = resolveAssetMetadata(assetOrAddress);
  const required = minVoiceSlipAmount(meta.symbol, minUsdMicro);
  if (rawAmount < required) {
    throw new VoiceEconomicFloorError({
      asset: meta.symbol,
      amount: rawAmount,
      requiredAmount: required,
      minUsdMicro,
    });
  }
}

/** Human-decimal convenience check matching `client/src/lib/voiceGateway.ts:meetsVoiceSlipMinimum`. */
export function meetsVoiceSlipMinimum(asset: AnyAssetSymbol | string, humanAmount: number): boolean {
  if (!Number.isFinite(humanAmount) || humanAmount <= 0) return false;
  try {
    const sym = normalizeSdkAsset(asset);
    if (sym === 'USDC') return humanAmount >= 1;
    if (sym === 'ETH') return humanAmount >= 0.0004;
    if (sym === 'cbBTC') return humanAmount >= 0.00001;
    if (sym === 'NARA') return humanAmount >= 0.0004;
    return false;
  } catch {
    return false;
  }
}

// ============================================================================
// Standalone 32 KB Block-Padded AES-256-GCM Voice Envelope (`encryptVoiceEnvelope`)
// ============================================================================

export interface EncryptVoiceEnvelopeOptions {
  /** Optional slip asset to enforce the `$1.00` economic floor before encryption. */
  asset?: AnyAssetSymbol | string;
  /** Optional raw slip amount (atomic units) checked against `VOICE_MIN_USD_MICRO`. */
  slipAmount?: bigint;
  /** Alias for `slipAmount`. */
  amount?: bigint;
  /** Override minimum micro-USD floor (defaults to `1_000_000n` = `$1.00`). */
  minUsdMicro?: bigint;
  /** Optional caller-supplied 256-bit Base64Url key (43 chars). Generated randomly when omitted. */
  voiceKeyBase64Url?: string;
  /** Optional custom Additional Authenticated Data (defaults to `"cs-voice-envelope-v2"`). */
  aad?: Uint8Array;
  /** When `true`, overwrites the caller's input `audioBytes` buffer with zeros after encryption. */
  zeroizeInput?: boolean;
}

export interface EncryptedVoiceEnvelope {
  /** `12-byte IV || AES-256-GCM ciphertext (multiple of 32,768 bytes) || 16-byte GCM tag`. */
  ciphertextBytes: Uint8Array;
  /** URL-safe Base64 256-bit key suitable for `#...&vk=<key>` fragment transport (never query string!). */
  voiceKeyBase64Url: string;
  /** Exact padded plaintext size in bytes (always a positive multiple of `32,768`). */
  paddedPlaintextBytes: number;
  /** Block padding quantum (`32,768` bytes). */
  blockSizeBytes: 32768;
  /** Normalized audio MIME type stored inside the encrypted header. */
  mimeType: string;
  /** Scrubs `ciphertextBytes` in place. */
  zeroize: () => void;
}

export interface DecryptVoiceEnvelopeOptions {
  aad?: Uint8Array;
  /** When `true`, overwrites the caller's `ciphertextBytes` buffer with zeros after decryption. */
  zeroizeCiphertext?: boolean;
}

export interface DecryptedVoiceEnvelope {
  audioBytes: Uint8Array;
  mimeType: string;
  paddedPlaintextBytes: number;
  /** Scrubs `audioBytes` in place after playback. */
  zeroize: () => void;
}

const DEFAULT_ENVELOPE_AAD = utf8Bytes('cs-voice-envelope-v2');

/**
 * Encrypts `audioBytes` + `mimeType` with WebCrypto `AES-256-GCM` using **32 KB (`32,768`-byte)
 * CSPRNG block padding** so ciphertext byte length never leaks short message content, and
 * immediately zeroizes temporary key & padded-plaintext buffers before returning.
 */
export async function encryptVoiceEnvelope(
  audioBytes: Uint8Array,
  mimeType = 'audio/ogg',
  options: EncryptVoiceEnvelopeOptions = {},
): Promise<EncryptedVoiceEnvelope> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error('globalThis.crypto.subtle is required for AES-256-GCM voice encryption');
  }

  const candidateSlipAmount = options.slipAmount ?? options.amount;
  if (options.asset !== undefined && candidateSlipAmount !== undefined) {
    assertVoiceEconomicFloor(options.asset, candidateSlipAmount, options.minUsdMicro ?? VOICE_MIN_USD_MICRO);
  } else if (candidateSlipAmount !== undefined) {
    assertVoiceEconomicFloor('USDC', candidateSlipAmount, options.minUsdMicro ?? VOICE_MIN_USD_MICRO);
  }

  if (!(audioBytes instanceof Uint8Array) || audioBytes.length === 0) {
    throw new Error('audioBytes must be a non-empty Uint8Array');
  }
  if (audioBytes.length > VOICE_ENVELOPE_MAX_AUDIO_BYTES) {
    throw new Error('Voice note exceeds maximum allowed size');
  }

  const normalizedMime = String(mimeType || 'audio/ogg').trim().toLowerCase();
  const mimeBytes = utf8Bytes(normalizedMime);
  if (mimeBytes.length === 0 || mimeBytes.length > 127) {
    throw new Error('Invalid voice MIME type');
  }

  // CSV2 Plaintext Layout:
  // [0..3]   "CSV2" (4B)
  // [4]      version = 1 (1B)
  // [5]      mimeLength (1B)
  // [6..9]   audioByteLength uint32BE (4B)
  // [10..]   mimeBytes || audioBytes || CSPRNG padding to next 32,768-byte boundary
  const headerAndBodyLen = 10 + mimeBytes.length + audioBytes.length;
  const paddedPlaintextLen = Math.max(
    VOICE_ENVELOPE_BLOCK_BYTES,
    Math.ceil(headerAndBodyLen / VOICE_ENVELOPE_BLOCK_BYTES) * VOICE_ENVELOPE_BLOCK_BYTES,
  );

  const paddedPlaintext = new Uint8Array(paddedPlaintextLen);
  const keyBytes = options.voiceKeyBase64Url
    ? voiceBase64UrlToBytes(options.voiceKeyBase64Url)
    : fillRandomBytes(new Uint8Array(32));

  if (keyBytes.length !== 32) {
    zeroizeVoiceBuffers(keyBytes, paddedPlaintext);
    throw new Error('Voice encryption key must be exactly 32 bytes (256 bits)');
  }

  const voiceKeyBase64Url = voiceBytesToBase64Url(keyBytes);
  let keyCopy: Uint8Array<ArrayBuffer> | null = null;
  let plainCopy: Uint8Array<ArrayBuffer> | null = null;

  try {
    const view = new DataView(paddedPlaintext.buffer);
    paddedPlaintext.set(VOICE_CSV2_MAGIC, 0);
    view.setUint8(4, VOICE_FORMAT_VERSION);
    view.setUint8(5, mimeBytes.length);
    view.setUint32(6, audioBytes.length, false);
    paddedPlaintext.set(mimeBytes, 10);
    paddedPlaintext.set(audioBytes, 10 + mimeBytes.length);
    if (headerAndBodyLen < paddedPlaintextLen) {
      fillRandomBytes(paddedPlaintext.subarray(headerAndBodyLen));
    }

    const iv = toWebCryptoBytes(fillRandomBytes(new Uint8Array(VOICE_GCM_IV_BYTES)));
    const aad = toWebCryptoBytes(options.aad ?? DEFAULT_ENVELOPE_AAD);
    keyCopy = toWebCryptoBytes(keyBytes);
    plainCopy = toWebCryptoBytes(paddedPlaintext);

    const cryptoKey = await subtle.importKey('raw', keyCopy, 'AES-GCM', false, ['encrypt']);
    const encryptedBuf = await subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad },
      cryptoKey,
      plainCopy,
    );
    const ctWithTag = new Uint8Array(encryptedBuf);
    const ciphertextBytes = concatUint8(iv, ctWithTag);
    ctWithTag.fill(0);

    return {
      ciphertextBytes,
      voiceKeyBase64Url,
      paddedPlaintextBytes: paddedPlaintextLen,
      blockSizeBytes: VOICE_ENVELOPE_BLOCK_BYTES,
      mimeType: normalizedMime,
      zeroize: () => {
        ciphertextBytes.fill(0);
      },
    };
  } finally {
    zeroizeVoiceBuffers(paddedPlaintext, keyBytes, keyCopy, plainCopy);
    if (options.zeroizeInput) {
      zeroizeVoiceBuffers(audioBytes);
    }
  }
}

/**
 * Decrypts a 32 KB block-padded `AES-256-GCM` voice envelope and immediately zeroizes both the
 * decoded key buffer and the full padded plaintext buffer before returning `audioBytes`.
 */
export async function decryptVoiceEnvelope(
  ciphertextBytes: Uint8Array,
  voiceKeyBase64Url: string,
  options: DecryptVoiceEnvelopeOptions = {},
): Promise<DecryptedVoiceEnvelope> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error('globalThis.crypto.subtle is required for AES-256-GCM voice decryption');
  }
  const minCipherLen = VOICE_GCM_IV_BYTES + VOICE_ENVELOPE_BLOCK_BYTES + VOICE_GCM_TAG_BYTES;
  if (!(ciphertextBytes instanceof Uint8Array) || ciphertextBytes.length < minCipherLen) {
    throw new Error('Voice ciphertext is truncated or missing 32 KB block padding');
  }
  const paddedLen = ciphertextBytes.length - VOICE_GCM_IV_BYTES - VOICE_GCM_TAG_BYTES;
  if (paddedLen % VOICE_ENVELOPE_BLOCK_BYTES !== 0) {
    throw new Error('Voice ciphertext is not aligned to 32 KB padding blocks');
  }

  const keyBytes = voiceBase64UrlToBytes(voiceKeyBase64Url);
  if (keyBytes.length !== 32) {
    zeroizeVoiceBuffers(keyBytes);
    throw new Error('Voice decryption key must be 32 bytes (256 bits)');
  }

  let keyCopy: Uint8Array<ArrayBuffer> | null = null;
  let ctCopy: Uint8Array<ArrayBuffer> | null = null;
  let plainBytes: Uint8Array | null = null;

  try {
    const iv = toWebCryptoBytes(ciphertextBytes.subarray(0, VOICE_GCM_IV_BYTES));
    ctCopy = toWebCryptoBytes(ciphertextBytes.subarray(VOICE_GCM_IV_BYTES));
    const aad = toWebCryptoBytes(options.aad ?? DEFAULT_ENVELOPE_AAD);
    keyCopy = toWebCryptoBytes(keyBytes);

    const cryptoKey = await subtle.importKey('raw', keyCopy, 'AES-GCM', false, ['decrypt']);
    const plainBuf = await subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: aad },
      cryptoKey,
      ctCopy,
    );
    plainBytes = new Uint8Array(plainBuf);

    if (plainBytes.length !== paddedLen || plainBytes.length < 12) {
      throw new Error('Decrypted voice envelope length mismatch');
    }
    for (let i = 0; i < 4; i++) {
      if (plainBytes[i] !== VOICE_CSV2_MAGIC[i]) {
        throw new Error('Invalid voice envelope magic header');
      }
    }
    const view = new DataView(plainBytes.buffer, plainBytes.byteOffset, plainBytes.byteLength);
    const version = view.getUint8(4);
    const mimeLen = view.getUint8(5);
    const audioLen = view.getUint32(6, false);
    if (
      version !== VOICE_FORMAT_VERSION ||
      mimeLen < 1 ||
      mimeLen > 127 ||
      audioLen < 1 ||
      10 + mimeLen + audioLen > plainBytes.length
    ) {
      throw new Error('Malformed voice envelope frame metadata');
    }

    const mimeType = td.decode(plainBytes.subarray(10, 10 + mimeLen));
    const audioBytes = new Uint8Array(audioLen);
    audioBytes.set(plainBytes.subarray(10 + mimeLen, 10 + mimeLen + audioLen));

    return {
      audioBytes,
      mimeType,
      paddedPlaintextBytes: plainBytes.length,
      zeroize: () => {
        audioBytes.fill(0);
      },
    };
  } finally {
    zeroizeVoiceBuffers(keyBytes, keyCopy, ctCopy, plainBytes);
    if (options.zeroizeCiphertext) {
      zeroizeVoiceBuffers(ciphertextBytes);
    }
  }
}

// ============================================================================
// RFC 9497 P-256 VOPRF (`OPRFV1-\x01-P256-SHA256`) + Chaum-Pedersen DLEQ Proofs
// Byte-for-byte parity with `shared/voiceVoprf.mjs`
// ============================================================================

const VOPRF_CONTEXT_STRING = utf8Bytes('OPRFV1-\x01-P256-SHA256');
const HASH_TO_GROUP_DST = concatUint8(utf8Bytes('HashToGroup-'), VOPRF_CONTEXT_STRING);
const HASH_TO_SCALAR_DST = concatUint8(utf8Bytes('HashToScalar-'), VOPRF_CONTEXT_STRING);
const CHALLENGE_SEED_PREFIX = concatUint8(utf8Bytes('Seed-'), VOPRF_CONTEXT_STRING);
const FINALIZE_SUFFIX = utf8Bytes('Finalize');

function i2osp2(n: number): Uint8Array {
  return new Uint8Array([(n >> 8) & 0xff, n & 0xff]);
}

function modP256(a: bigint, m: bigint = P256_N): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  let b = modP256(base, m);
  let e = exp;
  while (e > 0n) {
    if ((e & 1n) === 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

export function modInverseP256(a: bigint): bigint {
  const v = modP256(a, P256_N);
  if (v === 0n) throw new Error('Voice note could not be accepted');
  return modPow(v, P256_N - 2n, P256_N);
}

function scalarToBytes32(s: bigint): Uint8Array {
  const hex = modP256(s, P256_N).toString(16).padStart(64, '0');
  return rawHexToBytes(hex, 32);
}

function bytesToScalarP256(bytes: Uint8Array): bigint {
  const s = BigInt('0x' + rawBytesToHex(bytes));
  if (s < 1n || s >= P256_N) throw new Error('Voice note could not be accepted');
  return s;
}

function defaultRandomBytes(len: number): Uint8Array {
  return fillRandomBytes(new Uint8Array(len));
}

function randomNonZeroScalar(randomBytesFn: (len: number) => Uint8Array): bigint {
  for (let i = 0; i < 64; i++) {
    const raw = randomBytesFn(48);
    const s = (BigInt('0x' + rawBytesToHex(raw)) % (P256_N - 1n)) + 1n;
    raw.fill(0);
    if (s >= 1n && s < P256_N) return s;
  }
  throw new Error('Voice note could not be accepted');
}

function hashToScalarP256(msgBytes: Uint8Array, dst: Uint8Array = HASH_TO_SCALAR_DST): bigint {
  const b1 = sha256(concatUint8(dst, new Uint8Array([0x01]), i2osp2(msgBytes.length), msgBytes));
  const b2 = sha256(concatUint8(dst, new Uint8Array([0x02]), b1, i2osp2(msgBytes.length), msgBytes));
  const wide = BigInt('0x' + rawBytesToHex(concatUint8(b1, b2)));
  return modP256(wide, P256_N);
}

type P256Point = InstanceType<typeof p256.ProjectivePoint>;

function computeDleqChallenge(
  G: P256Point,
  pkS: P256Point,
  B: P256Point,
  Z: P256Point,
  t2: P256Point,
  t3: P256Point,
): bigint {
  const gB = G.toRawBytes(true);
  const pkB = pkS.toRawBytes(true);
  const bB = B.toRawBytes(true);
  const zB = Z.toRawBytes(true);
  const t2B = t2.toRawBytes(true);
  const t3B = t3.toRawBytes(true);
  const transcript = concatUint8(
    CHALLENGE_SEED_PREFIX,
    i2osp2(gB.length),
    gB,
    i2osp2(pkB.length),
    pkB,
    i2osp2(bB.length),
    bB,
    i2osp2(zB.length),
    zB,
    i2osp2(t2B.length),
    t2B,
    i2osp2(t3B.length),
    t3B,
  );
  return hashToScalarP256(transcript, HASH_TO_SCALAR_DST);
}

function finalizeVoprfHash(inputBytes: Uint8Array, unblindedPoint: P256Point): Uint8Array {
  const nBytes = unblindedPoint.toRawBytes(true);
  return sha256(
    concatUint8(
      i2osp2(inputBytes.length),
      inputBytes,
      i2osp2(nBytes.length),
      nBytes,
      FINALIZE_SUFFIX,
    ),
  );
}

export interface VoiceVoprfBlindResult {
  blindScalarHex: string;
  blindedHex: string;
}

export interface VoiceVoprfEvaluationResult {
  evaluatedHex: string;
  proofHex: string;
  pkHex: string;
}

export interface VoiceEpochKeypair {
  epochId: number;
  skHex: string;
  pkHex: string;
}

export interface VoiceVoprfEngine {
  hashToGroup(inputBytes: Uint8Array): P256Point;
  deriveEpochKeypair(masterSecretBytes: Uint8Array, epochId: number): VoiceEpochKeypair;
  getPublicKeyHex(skHex: string): string;
  blind(inputBytes: Uint8Array, randomBytesFn?: (len: number) => Uint8Array): VoiceVoprfBlindResult;
  blindEvaluate(
    skHex: string,
    blindedHex: string,
    randomBytesFn?: (len: number) => Uint8Array,
  ): VoiceVoprfEvaluationResult;
  finalize(
    inputBytes: Uint8Array,
    blindScalarHex: string,
    pkHex: string,
    evaluatedHex: string,
    proofHex: string,
  ): Uint8Array;
  verifyFinalized(skHex: string, inputBytes: Uint8Array, candidateOutput32B: Uint8Array): boolean;
}

/**
 * Creates an RFC 9497 `VOPRF(P-256, SHA-256)` engine with Chaum-Pedersen DLEQ verification,
 * matching `shared/voiceVoprf.mjs` byte-for-byte.
 */
export function createVoiceVoprf(): VoiceVoprfEngine {
  const Point = p256.ProjectivePoint;
  const G = Point.BASE;

  function hashToGroup(inputBytes: Uint8Array): P256Point {
    const h2cPoint = hashToCurve(inputBytes, { DST: HASH_TO_GROUP_DST });
    const pt = Point.fromAffine(h2cPoint.toAffine());
    if (pt.equals(Point.ZERO)) throw new Error('Voice note could not be accepted');
    return pt;
  }

  function deriveEpochKeypair(masterSecretBytes: Uint8Array, epochId: number): VoiceEpochKeypair {
    if (!Number.isInteger(epochId) || epochId < 0 || epochId > 255) {
      throw new Error('Voice note could not be accepted');
    }
    const seed = concatUint8(
      utf8Bytes('cs-voice-voprf-epoch-v1:'),
      new Uint8Array([epochId]),
      masterSecretBytes,
    );
    const sk = (hashToScalarP256(seed) % (P256_N - 1n)) + 1n;
    seed.fill(0);
    const pk = G.multiply(sk);
    const skBytes = scalarToBytes32(sk);
    const skHex = rawBytesToHex(skBytes);
    skBytes.fill(0);
    return {
      epochId,
      skHex,
      pkHex: pk.toHex(true),
    };
  }

  function getPublicKeyHex(skHex: string): string {
    const skBytes = rawHexToBytes(skHex, 32);
    try {
      const sk = bytesToScalarP256(skBytes);
      return G.multiply(sk).toHex(true);
    } finally {
      skBytes.fill(0);
    }
  }

  function blind(
    inputBytes: Uint8Array,
    randomBytesFn: (len: number) => Uint8Array = defaultRandomBytes,
  ): VoiceVoprfBlindResult {
    if (!(inputBytes instanceof Uint8Array) || inputBytes.length === 0) {
      throw new Error('Voice note could not be accepted');
    }
    const r = randomNonZeroScalar(randomBytesFn);
    const P = hashToGroup(inputBytes);
    const B = P.multiply(r);
    if (B.equals(Point.ZERO)) throw new Error('Voice note could not be accepted');
    const rBytes = scalarToBytes32(r);
    const blindScalarHex = rawBytesToHex(rBytes);
    rBytes.fill(0);
    return {
      blindScalarHex,
      blindedHex: B.toHex(true),
    };
  }

  function blindEvaluate(
    skHex: string,
    blindedHex: string,
    randomBytesFn: (len: number) => Uint8Array = defaultRandomBytes,
  ): VoiceVoprfEvaluationResult {
    const skBytes = rawHexToBytes(skHex, 32);
    try {
      const sk = bytesToScalarP256(skBytes);
      const pkS = G.multiply(sk);
      let B: P256Point;
      try {
        B = Point.fromHex(rawHexToBytes(blindedHex, 33));
      } catch {
        throw new Error('Voice note could not be accepted');
      }
      if (B.equals(Point.ZERO)) throw new Error('Voice note could not be accepted');
      const Z = B.multiply(sk);
      if (Z.equals(Point.ZERO)) throw new Error('Voice note could not be accepted');

      const k = randomNonZeroScalar(randomBytesFn);
      const t2 = G.multiply(k);
      const t3 = B.multiply(k);
      const c = computeDleqChallenge(G, pkS, B, Z, t2, t3);
      const s = modP256(k - c * sk, P256_N);

      const cBytes = scalarToBytes32(c);
      const sBytes = scalarToBytes32(s);
      const proofHex = rawBytesToHex(cBytes) + rawBytesToHex(sBytes);
      cBytes.fill(0);
      sBytes.fill(0);

      return {
        evaluatedHex: Z.toHex(true),
        proofHex,
        pkHex: pkS.toHex(true),
      };
    } finally {
      skBytes.fill(0);
    }
  }

  function finalize(
    inputBytes: Uint8Array,
    blindScalarHex: string,
    pkHex: string,
    evaluatedHex: string,
    proofHex: string,
  ): Uint8Array {
    const rBytes = rawHexToBytes(blindScalarHex, 32);
    try {
      const r = bytesToScalarP256(rBytes);
      const P = hashToGroup(inputBytes);
      const B = P.multiply(r);
      let pkS: P256Point;
      let Z: P256Point;
      try {
        pkS = Point.fromHex(rawHexToBytes(pkHex, 33));
        Z = Point.fromHex(rawHexToBytes(evaluatedHex, 33));
      } catch {
        throw new Error('Voice note could not be accepted');
      }
      if (pkS.equals(Point.ZERO) || Z.equals(Point.ZERO)) {
        throw new Error('Voice note could not be accepted');
      }
      const proofBytes = rawHexToBytes(proofHex, 64);
      const c = BigInt('0x' + rawBytesToHex(proofBytes.subarray(0, 32)));
      const s = BigInt('0x' + rawBytesToHex(proofBytes.subarray(32, 64)));
      if (c >= P256_N || s >= P256_N) {
        throw new Error('Voice note could not be accepted');
      }

      const t2 = (s === 0n ? Point.ZERO : G.multiply(s)).add(c === 0n ? Point.ZERO : pkS.multiply(c));
      const t3 = (s === 0n ? Point.ZERO : B.multiply(s)).add(c === 0n ? Point.ZERO : Z.multiply(c));
      const expectedC = computeDleqChallenge(G, pkS, B, Z, t2, t3);
      if (!constantTimeEqualBytes(scalarToBytes32(c), scalarToBytes32(expectedC))) {
        throw new Error('Voice note could not be accepted');
      }

      const rInv = modInverseP256(r);
      const N = Z.multiply(rInv);
      return finalizeVoprfHash(inputBytes, N);
    } finally {
      rBytes.fill(0);
    }
  }

  function verifyFinalized(
    skHex: string,
    inputBytes: Uint8Array,
    candidateOutput32B: Uint8Array,
  ): boolean {
    if (!(candidateOutput32B instanceof Uint8Array) || candidateOutput32B.length !== 32) {
      return false;
    }
    const skBytes = rawHexToBytes(skHex, 32);
    try {
      const sk = bytesToScalarP256(skBytes);
      const P = hashToGroup(inputBytes);
      const N = P.multiply(sk);
      const expected = finalizeVoprfHash(inputBytes, N);
      return constantTimeEqualBytes(expected, candidateOutput32B);
    } catch {
      return false;
    } finally {
      skBytes.fill(0);
    }
  }

  return {
    hashToGroup,
    deriveEpochKeypair,
    getPublicKeyHex,
    blind,
    blindEvaluate,
    finalize,
    verifyFinalized,
  };
}

export const voiceVoprf: VoiceVoprfEngine = createVoiceVoprf();

export function currentVoiceEpochId(nowMs: number = Date.now()): number {
  const d = new Date(nowMs);
  const monthsSince2026 = (d.getUTCFullYear() - 2026) * 12 + d.getUTCMonth();
  return ((monthsSince2026 % 256) + 256) % 256;
}

export function previousVoiceEpochId(epochId: number): number {
  return (epochId + 255) % 256;
}

// ============================================================================
// Wire-Exact Voice Identity, CSV1/CSVE Framing & Edge Action Signatures
// Byte-for-byte parity with `client/src/lib/voiceCrypto.ts` & `shared/voiceEnvelope.mjs`
// ============================================================================

export function generateFragmentVoiceKey(): string {
  const raw = fillRandomBytes(new Uint8Array(16));
  const out = voiceBytesToBase64Url(raw);
  raw.fill(0);
  return out;
}

export function randomVoiceNonceHex16Bytes(): string {
  const raw = fillRandomBytes(new Uint8Array(16));
  const out = rawBytesToHex(raw);
  raw.fill(0);
  return out;
}

function normalizeVoiceVaultAddress(vaultAddress: string): string {
  const clean = String(vaultAddress || '').trim().toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(clean) || /^0x0{40}$/.test(clean)) {
    throw new Error('Voice note could not be accepted');
  }
  return clean;
}

function normalizeVoiceSlipIdDecimal(slipId: string | bigint | number): string {
  const raw = String(slipId ?? '').trim();
  if (!/^\d{1,24}$/.test(raw)) {
    throw new Error('Voice note could not be accepted');
  }
  const bi = BigInt(raw);
  if (bi <= 0n) throw new Error('Voice note could not be accepted');
  return bi.toString(10);
}

async function hkdfSha256WebCrypto(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  lengthBytes = 32,
): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('Voice note could not be accepted');
  const ikmCopy = toWebCryptoBytes(ikm);
  const saltCopy = toWebCryptoBytes(salt);
  const infoCopy = toWebCryptoBytes(info);
  try {
    const key = await subtle.importKey('raw', ikmCopy, 'HKDF', false, ['deriveBits']);
    const bits = await subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: saltCopy, info: infoCopy },
      key,
      lengthBytes * 8,
    );
    return new Uint8Array(bits);
  } finally {
    zeroizeVoiceBuffers(ikmCopy, saltCopy, infoCopy);
  }
}

export function deriveVoiceSalt(vaultAddress: string, slipId: string | bigint | number): Uint8Array {
  const vaultNorm = normalizeVoiceVaultAddress(vaultAddress);
  const slipIdDec = normalizeVoiceSlipIdDecimal(slipId);
  return sha256(utf8Bytes(`cryptoslip-voice-v1:${vaultNorm}:${slipIdDec}`));
}

export async function deriveVoiceAuthPrivateKeyBytes(
  rootKeyBytes32: Uint8Array,
  saltBytes32: Uint8Array,
): Promise<Uint8Array> {
  if (rootKeyBytes32.length !== 32 || saltBytes32.length !== 32) {
    throw new Error('Voice note could not be accepted');
  }
  const prefix = utf8Bytes('cs-voice-auth-v1:');
  for (let counter = 0; counter < 256; counter++) {
    const info = concatUint8(prefix, new Uint8Array([counter]));
    const candidate = await hkdfSha256WebCrypto(rootKeyBytes32, saltBytes32, info, 32);
    const scalar = BigInt('0x' + rawBytesToHex(candidate));
    if (scalar >= 1n && scalar < SECP256K1_N) {
      return candidate;
    }
    candidate.fill(0);
  }
  throw new Error('Voice note could not be accepted');
}

export async function deriveVoiceAudioKeyBytes(
  rootKeyBytes32: Uint8Array,
  saltBytes32: Uint8Array,
  vkBytes?: Uint8Array | null,
): Promise<Uint8Array> {
  if (rootKeyBytes32.length !== 32 || saltBytes32.length !== 32) {
    throw new Error('Voice note could not be accepted');
  }
  const ikm = vkBytes && vkBytes.length > 0 ? concatUint8(rootKeyBytes32, vkBytes) : rootKeyBytes32;
  try {
    return await hkdfSha256WebCrypto(ikm, saltBytes32, utf8Bytes('cs-voice-aes256gcm-v1'), 32);
  } finally {
    if (ikm !== rootKeyBytes32) ikm.fill(0);
  }
}

export function deriveVoiceKeyIdFromSignerAddress(signerAddress: string): Uint8Array {
  const addrBytes = rawHexToBytes(normalizeVoiceVaultAddress(signerAddress), 20);
  return sha256(concatUint8(utf8Bytes('cs-voice-id-v1:'), addrBytes));
}

export function deriveVoucherVoprfInput(
  voiceKeyIdBytes32: Uint8Array,
  voucherNonceBytes32: Uint8Array,
): Uint8Array {
  if (voiceKeyIdBytes32.length !== 32 || voucherNonceBytes32.length !== 32) {
    throw new Error('Voice note could not be accepted');
  }
  return sha256(
    concatUint8(utf8Bytes('cs-voice-voucher-v1:'), voiceKeyIdBytes32, voucherNonceBytes32),
  );
}

export function shardNameForVoiceKeyId(
  voiceKeyIdHex: string,
  shardCount: number = VOICE_SHARD_COUNT,
): string {
  const clean = String(voiceKeyIdHex || '').trim().toLowerCase();
  if (!HEX64_RE.test(clean)) throw new Error('Voice note could not be accepted');
  const firstByte = parseInt(clean.slice(0, 2), 16);
  const shardIdx = firstByte % shardCount;
  return `voice-shard-${shardIdx.toString(16).padStart(2, '0')}`;
}

async function deriveCodeModeVoiceRoot(claimCode: string, codeSaltHex: string): Promise<Uint8Array> {
  if (!isWellFormedClaimCode(claimCode)) throw new Error('Voice note could not be accepted');
  if (!/^[0-9a-fA-F]{32}$/.test(codeSaltHex)) throw new Error('Voice note could not be accepted');
  const password = utf8Bytes(`cryptoslip-voice-kdf-v1:${normalizeClaimCode(claimCode)}`);
  const salt = rawHexToBytes(`${codeSaltHex.toLowerCase()}00`, 17);
  try {
    return await scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, 32);
  } finally {
    password.fill(0);
    salt.fill(0);
  }
}

export interface DerivedVoiceIdentity {
  voiceKeyIdHex: string;
  voiceKeyIdBytes: Uint8Array;
  voiceAuthAddress: Address;
  voiceAuthSignMessage: (message: string) => Promise<Hex>;
  voiceAudioKeyBytes: Uint8Array;
  fragmentVoiceKey?: string;
  zeroize: () => void;
}

/**
 * Derives `voiceKeyId`, `voiceAuth` EIP-191 signer, and 256-bit `voiceAudioKey` with
 * exact byte parity against `client/src/lib/voiceCrypto.ts:deriveVoiceIdentity`.
 */
export async function deriveVoiceIdentity(params: {
  vaultAddress: string;
  slipId: string | bigint | number;
  mode: 'open' | 'code';
  claimPrivateKey?: string;
  fragmentVoiceKey?: string;
  claimCode?: string;
  codeSalt?: string;
}): Promise<DerivedVoiceIdentity> {
  const salt = deriveVoiceSalt(params.vaultAddress, params.slipId);
  let rootKeyBytes: Uint8Array | null = null;
  let vkBytes: Uint8Array | null = null;
  let authKeyBytes: Uint8Array | null = null;
  let fragmentVoiceKey: string | undefined;

  try {
    if (params.mode === 'code') {
      if (!params.claimCode || !params.codeSalt) {
        throw new Error('Voice note could not be accepted');
      }
      rootKeyBytes = await deriveCodeModeVoiceRoot(params.claimCode, params.codeSalt);
    } else {
      if (!params.claimPrivateKey) {
        throw new Error('Voice note could not be accepted');
      }
      rootKeyBytes = rawHexToBytes(params.claimPrivateKey, 32);
      if (params.fragmentVoiceKey) {
        vkBytes = voiceBase64UrlToBytes(params.fragmentVoiceKey);
        fragmentVoiceKey = params.fragmentVoiceKey;
      }
    }

    authKeyBytes = await deriveVoiceAuthPrivateKeyBytes(rootKeyBytes, salt);
    const authAccount = privateKeyToAccount(viemBytesToHex(authKeyBytes));
    const voiceKeyIdBytes = deriveVoiceKeyIdFromSignerAddress(authAccount.address);
    const voiceAudioKeyBytes = await deriveVoiceAudioKeyBytes(rootKeyBytes, salt, vkBytes);

    let authDestroyed = false;
    return {
      voiceKeyIdHex: rawBytesToHex(voiceKeyIdBytes),
      voiceKeyIdBytes,
      voiceAuthAddress: authAccount.address,
      voiceAuthSignMessage: async (message: string) => {
        if (authDestroyed) throw new Error('Voice identity has been zeroized');
        return authAccount.signMessage({ message });
      },
      voiceAudioKeyBytes,
      ...(fragmentVoiceKey ? { fragmentVoiceKey } : {}),
      zeroize: () => {
        authDestroyed = true;
        zeroizeVoiceBuffers(voiceAudioKeyBytes, voiceKeyIdBytes);
      },
    };
  } finally {
    zeroizeVoiceBuffers(rootKeyBytes, vkBytes, authKeyBytes, salt);
  }
}

export function zeroVoiceIdentity(identity: DerivedVoiceIdentity | null | undefined): void {
  identity?.zeroize();
}

export function buildVoiceAad(
  voiceKeyIdBytes32: Uint8Array,
  plaintextLen: number = VOICE_CSV1_PLAINTEXT_BYTES,
): Uint8Array {
  if (voiceKeyIdBytes32.length !== 32) {
    throw new Error('Voice note could not be accepted');
  }
  const prefix = utf8Bytes('cs-voice-aad-v1:');
  const tail = new Uint8Array(5);
  const view = new DataView(tail.buffer);
  view.setUint8(0, VOICE_FORMAT_VERSION);
  view.setUint32(1, plaintextLen, false);
  return concatUint8(prefix, voiceKeyIdBytes32, tail);
}

/**
 * Packs audio bytes (`<= 60,016` bytes) into a fixed `60,032`-byte `CSV1` frame with CSPRNG tail
 * padding so every Worker upload has identical `60,060`-byte encrypted payload size.
 * Accepts pre-packed `60,032`-byte `CSV1` frames directly.
 */
export function packVoiceCsv1Plaintext(
  audioBytes: Uint8Array,
  options: { durationMs?: number; codecId?: number } = {},
): Uint8Array {
  if (
    audioBytes.length === VOICE_CSV1_PLAINTEXT_BYTES &&
    audioBytes[0] === VOICE_CSV1_MAGIC[0] &&
    audioBytes[1] === VOICE_CSV1_MAGIC[1] &&
    audioBytes[2] === VOICE_CSV1_MAGIC[2] &&
    audioBytes[3] === VOICE_CSV1_MAGIC[3]
  ) {
    const copy = new Uint8Array(VOICE_CSV1_PLAINTEXT_BYTES);
    copy.set(audioBytes);
    return copy;
  }

  if (audioBytes.length < 1 || audioBytes.length > VOICE_CSV1_MAX_AUDIO_BYTES) {
    throw new Error(
      `Voice payload for CSV1 frame must be 1..${VOICE_CSV1_MAX_AUDIO_BYTES} bytes (got ${audioBytes.length})`,
    );
  }
  const durationMs = Math.max(
    VOICE_MIN_DURATION_MS,
    Math.min(VOICE_MAX_DURATION_MS, Math.round(options.durationMs ?? 2_000)),
  );
  const codecId = options.codecId ?? VOICE_CODEC_IMA_ADPCM_12K;

  const out = new Uint8Array(VOICE_CSV1_PLAINTEXT_BYTES);
  const view = new DataView(out.buffer);
  out.set(VOICE_CSV1_MAGIC, 0);
  view.setUint8(4, VOICE_FORMAT_VERSION);
  view.setUint8(5, codecId);
  view.setUint16(6, durationMs, false);
  view.setUint32(8, audioBytes.length, false);
  view.setInt16(12, 0, false);
  view.setUint8(14, 0);
  view.setUint8(15, 0);
  out.set(audioBytes, VOICE_CSV1_HEADER_BYTES);
  const padOffset = VOICE_CSV1_HEADER_BYTES + audioBytes.length;
  if (padOffset < VOICE_CSV1_PLAINTEXT_BYTES) {
    fillRandomBytes(out.subarray(padOffset));
  }
  return out;
}

export function unpackVoiceCsv1Plaintext(plaintext60032: Uint8Array): {
  audioBytes: Uint8Array;
  durationMs: number;
  codecId: number;
} {
  if (plaintext60032.length !== VOICE_CSV1_PLAINTEXT_BYTES) {
    throw new Error('Voice note could not be accepted');
  }
  for (let i = 0; i < 4; i++) {
    if (plaintext60032[i] !== VOICE_CSV1_MAGIC[i]) {
      throw new Error('Voice note could not be accepted');
    }
  }
  const view = new DataView(
    plaintext60032.buffer,
    plaintext60032.byteOffset,
    plaintext60032.byteLength,
  );
  const version = view.getUint8(4);
  const codecId = view.getUint8(5);
  const durationMs = view.getUint16(6, false);
  const payloadLen = view.getUint32(8, false);
  if (
    version !== VOICE_FORMAT_VERSION ||
    durationMs < VOICE_MIN_DURATION_MS ||
    durationMs > VOICE_MAX_DURATION_MS ||
    payloadLen < 1 ||
    payloadLen > VOICE_CSV1_MAX_AUDIO_BYTES
  ) {
    throw new Error('Voice note could not be accepted');
  }
  const audioBytes = new Uint8Array(payloadLen);
  audioBytes.set(
    plaintext60032.subarray(VOICE_CSV1_HEADER_BYTES, VOICE_CSV1_HEADER_BYTES + payloadLen),
  );
  return { audioBytes, durationMs, codecId };
}

export async function encryptVoicePlaintext(
  plaintext60032: Uint8Array,
  audioKey32: Uint8Array,
  voiceKeyId32: Uint8Array,
  iv12?: Uint8Array | null,
): Promise<Uint8Array> {
  if (plaintext60032.length !== VOICE_CSV1_PLAINTEXT_BYTES) {
    throw new Error('Voice note could not be accepted');
  }
  const iv = toWebCryptoBytes(iv12 ?? fillRandomBytes(new Uint8Array(VOICE_GCM_IV_BYTES)));
  if (iv.length !== VOICE_GCM_IV_BYTES) throw new Error('Voice note could not be accepted');
  const aad = toWebCryptoBytes(buildVoiceAad(voiceKeyId32, plaintext60032.length));
  const keyCopy = toWebCryptoBytes(audioKey32);
  const plainCopy = toWebCryptoBytes(plaintext60032);
  try {
    const key = await globalThis.crypto.subtle.importKey('raw', keyCopy, 'AES-GCM', false, [
      'encrypt',
    ]);
    const ctWithTag = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad },
        key,
        plainCopy,
      ),
    );
    const out = concatUint8(iv, ctWithTag);
    ctWithTag.fill(0);
    if (out.length !== VOICE_ENCRYPTED_PAYLOAD_BYTES) {
      throw new Error('Voice note could not be accepted');
    }
    return out;
  } finally {
    zeroizeVoiceBuffers(keyCopy, plainCopy);
  }
}

export async function decryptVoiceCiphertext(
  encrypted60060: Uint8Array,
  audioKey32: Uint8Array,
  voiceKeyId32: Uint8Array,
): Promise<Uint8Array> {
  if (encrypted60060.length !== VOICE_ENCRYPTED_PAYLOAD_BYTES) {
    throw new Error('Voice note could not be accepted');
  }
  const iv = toWebCryptoBytes(encrypted60060.subarray(0, VOICE_GCM_IV_BYTES));
  const ctWithTag = toWebCryptoBytes(encrypted60060.subarray(VOICE_GCM_IV_BYTES));
  const aad = toWebCryptoBytes(buildVoiceAad(voiceKeyId32, VOICE_CSV1_PLAINTEXT_BYTES));
  const keyCopy = toWebCryptoBytes(audioKey32);
  try {
    const key = await globalThis.crypto.subtle.importKey('raw', keyCopy, 'AES-GCM', false, [
      'decrypt',
    ]);
    const plainBuf = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: aad },
      key,
      ctWithTag,
    );
    const plain = new Uint8Array(plainBuf);
    if (plain.length !== VOICE_CSV1_PLAINTEXT_BYTES) {
      plain.fill(0);
      throw new Error('Voice note could not be accepted');
    }
    return plain;
  } finally {
    zeroizeVoiceBuffers(keyCopy, ctWithTag);
  }
}

export function packUploadEnvelope(params: {
  epochId: number;
  ttlSec?: number;
  voiceKeyIdBytes: Uint8Array;
  voucherNonceBytes: Uint8Array;
  voprfOutputBytes: Uint8Array;
  encryptedPayloadBytes: Uint8Array;
}): Uint8Array {
  const ttlSec = params.ttlSec ?? VOICE_DEFAULT_TTL_SEC;
  if (!Number.isInteger(params.epochId) || params.epochId < 0 || params.epochId > 255) {
    throw new Error('Voice note could not be accepted');
  }
  if (!Number.isInteger(ttlSec) || ttlSec < VOICE_MIN_TTL_SEC || ttlSec > VOICE_MAX_TTL_SEC) {
    throw new Error('Voice note could not be accepted');
  }
  if (
    params.voiceKeyIdBytes.length !== 32 ||
    params.voucherNonceBytes.length !== 32 ||
    params.voprfOutputBytes.length !== 32 ||
    params.encryptedPayloadBytes.length !== VOICE_ENCRYPTED_PAYLOAD_BYTES
  ) {
    throw new Error('Voice note could not be accepted');
  }
  const out = new Uint8Array(VOICE_UPLOAD_ENVELOPE_BYTES);
  const view = new DataView(out.buffer);
  out.set(VOICE_UPLOAD_MAGIC, 0);
  view.setUint8(4, VOICE_UPLOAD_VERSION);
  view.setUint8(5, params.epochId);
  view.setUint32(6, ttlSec, false);
  out.set(params.voiceKeyIdBytes, 10);
  out.set(params.voucherNonceBytes, 42);
  out.set(params.voprfOutputBytes, 74);
  out.set(params.encryptedPayloadBytes, VOICE_UPLOAD_HEADER_BYTES);
  return out;
}

export function parseUploadEnvelope(rawBytes: Uint8Array) {
  if (rawBytes.length !== VOICE_UPLOAD_ENVELOPE_BYTES) {
    throw new Error('Voice note could not be accepted');
  }
  for (let i = 0; i < 4; i++) {
    if (rawBytes[i] !== VOICE_UPLOAD_MAGIC[i]) {
      throw new Error('Voice note could not be accepted');
    }
  }
  const view = new DataView(rawBytes.buffer, rawBytes.byteOffset, rawBytes.byteLength);
  const version = view.getUint8(4);
  if (version !== VOICE_UPLOAD_VERSION) {
    throw new Error('Voice note could not be accepted');
  }
  const epochId = view.getUint8(5);
  const rawTtlSec = view.getUint32(6, false);
  const ttlSec = Math.max(VOICE_MIN_TTL_SEC, Math.min(VOICE_MAX_TTL_SEC, rawTtlSec));
  const voiceKeyIdBytes = rawBytes.slice(10, 42);
  const voucherNonceBytes = rawBytes.slice(42, 74);
  const voprfOutputBytes = rawBytes.slice(74, 106);
  const encryptedPayloadBytes = rawBytes.slice(VOICE_UPLOAD_HEADER_BYTES);
  return {
    version,
    epochId,
    ttlSec,
    voiceKeyIdBytes,
    voiceKeyIdHex: rawBytesToHex(voiceKeyIdBytes),
    voucherNonceBytes,
    voprfOutputBytes,
    encryptedPayloadBytes,
  };
}

export type VoiceActionKind = 'STATUS' | 'PLAY' | 'ACK' | 'BURN';

export function buildVoiceActionMessage(params: {
  action: VoiceActionKind;
  host: string;
  voiceKeyIdHex: string;
  timestampSec: number;
  nonceHex: string;
}): string {
  const upperAction = String(params.action || '').toUpperCase();
  if (!['STATUS', 'PLAY', 'ACK', 'BURN'].includes(upperAction)) {
    throw new Error('Voice note could not be accepted');
  }
  const cleanHost = String(params.host || '').trim().toLowerCase();
  if (!HOST_RE.test(cleanHost)) throw new Error('Voice note could not be accepted');
  const cleanId = String(params.voiceKeyIdHex || '').trim().toLowerCase();
  const cleanNonce = String(params.nonceHex || '').trim().toLowerCase();
  if (!HEX64_RE.test(cleanId) || !HEX32_RE.test(cleanNonce)) {
    throw new Error('Voice note could not be accepted');
  }
  if (!Number.isSafeInteger(params.timestampSec) || params.timestampSec <= 0) {
    throw new Error('Voice note could not be accepted');
  }
  return `CRYPTOSLIP_VOICE_${upperAction}_V1:8453:${cleanHost}:${cleanId}:${params.timestampSec}:${cleanNonce}`;
}

export async function signVoiceAction(params: {
  action: VoiceActionKind;
  host: string;
  identity: Pick<DerivedVoiceIdentity, 'voiceKeyIdHex' | 'voiceAuthSignMessage'>;
  nonceHex?: string;
  timestampSec?: number;
}): Promise<{
  voiceKeyId: string;
  timestampSec: number;
  nonce: string;
  signature: Hex;
}> {
  const timestampSec = params.timestampSec ?? Math.floor(Date.now() / 1000);
  const nonce = (params.nonceHex || randomVoiceNonceHex16Bytes()).toLowerCase();
  const msg = buildVoiceActionMessage({
    action: params.action,
    host: params.host,
    voiceKeyIdHex: params.identity.voiceKeyIdHex,
    timestampSec,
    nonceHex: nonce,
  });
  const signature = await params.identity.voiceAuthSignMessage(msg);
  return {
    voiceKeyId: params.identity.voiceKeyIdHex.toLowerCase(),
    timestampSec,
    nonce,
    signature,
  };
}

export async function verifyVoiceActionSignature(params: {
  action: VoiceActionKind;
  host: string;
  voiceKeyIdHex: string;
  timestampSec: number;
  nonceHex: string;
  signature: string;
  nowSec?: number;
}): Promise<{ signer: string; voiceKeyIdHex: string; nonceHex: string }> {
  const nowSec = params.nowSec ?? Math.floor(Date.now() / 1000);
  const cleanId = String(params.voiceKeyIdHex || '').trim().toLowerCase();
  const cleanSig = String(params.signature || '').trim().toLowerCase();
  if (!HEX64_RE.test(cleanId) || !SIG65_RE.test(cleanSig)) {
    throw new Error('Voice note could not be accepted');
  }
  if (
    !Number.isSafeInteger(params.timestampSec) ||
    Math.abs(nowSec - params.timestampSec) > VOICE_ACTION_MAX_SKEW_SEC
  ) {
    throw new Error('Voice note could not be accepted');
  }
  const sBig = BigInt('0x' + cleanSig.slice(66, 130));
  if (sBig < 1n || sBig > SECP256K1_HALF_N) {
    throw new Error('Voice note could not be accepted');
  }
  const msg = buildVoiceActionMessage({
    action: params.action,
    host: params.host,
    voiceKeyIdHex: cleanId,
    timestampSec: params.timestampSec,
    nonceHex: params.nonceHex,
  });
  const signer = await recoverMessageAddress({ message: msg, signature: cleanSig as Hex });
  const derivedIdBytes = deriveVoiceKeyIdFromSignerAddress(signer);
  const expectedIdBytes = rawHexToBytes(cleanId, 32);
  if (!constantTimeEqualBytes(derivedIdBytes, expectedIdBytes)) {
    throw new Error('Voice note could not be accepted');
  }
  return {
    signer: signer.toLowerCase(),
    voiceKeyIdHex: cleanId,
    nonceHex: params.nonceHex.toLowerCase(),
  };
}

// ============================================================================
// EIP-712 Voice Voucher & CryptoSlipVoicePassV1 Pack Helpers (`voicePass.ts`)
// ============================================================================

export const VOICE_VOUCHER_TYPES = {
  VoiceVoucherRequest: [
    { name: 'slipId', type: 'uint256' },
    { name: 'blindedDigest', type: 'bytes32' },
    { name: 'deadline', type: 'uint256' },
  ],
} as const;

export const VOICE_PASS_TIER = {
  SINGLE: 1,
  PACK_10: 2,
  PACK_50: 3,
  PRO_10: 4,
} as const;
export type VoicePassTier = (typeof VOICE_PASS_TIER)[keyof typeof VOICE_PASS_TIER];

export const VOICE_PASS_SPLIT_BPS = {
  DENOMINATOR: 10_000n,
  REFERRER: 5_000n,
  HOLDERS_WITH_REF: 3_500n,
  TREASURY_WITH_REF: 1_500n,
  HOLDERS_NO_REF: 7_000n,
  TREASURY_NO_REF: 3_000n,
} as const;

export const VOICE_PASS_REDEEM_TYPES = {
  VoicePassRedeem: [
    { name: 'passId', type: 'uint256' },
    { name: 'blindedListDigest', type: 'bytes32' },
    { name: 'count', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
} as const;

export function previewVoicePassSplit(
  grossAmount: bigint,
  hasReferrer: boolean,
): { referrerShare: bigint; naraHoldersShare: bigint; treasuryShare: bigint } {
  const referrerShare = hasReferrer
    ? (grossAmount * VOICE_PASS_SPLIT_BPS.REFERRER) / VOICE_PASS_SPLIT_BPS.DENOMINATOR
    : 0n;
  const naraHoldersShare =
    (grossAmount *
      (hasReferrer ? VOICE_PASS_SPLIT_BPS.HOLDERS_WITH_REF : VOICE_PASS_SPLIT_BPS.HOLDERS_NO_REF)) /
    VOICE_PASS_SPLIT_BPS.DENOMINATOR;
  const treasuryShare = grossAmount - referrerShare - naraHoldersShare;
  return { referrerShare, naraHoldersShare, treasuryShare };
}

export interface UniversalTypedDataSigner {
  signTypedData(params: any, maybeTypes?: any, maybeValue?: any): Promise<string>;
}

async function signTypedWithUniversal(
  signer: UniversalTypedDataSigner,
  domain: { name: string; version: string; chainId: number; verifyingContract: Address },
  types: Record<string, ReadonlyArray<{ name: string; type: string }>>,
  primaryType: string,
  message: Record<string, unknown>,
): Promise<Hex> {
  if (signer.signTypedData.length >= 3) {
    const mutableTypes: Record<string, Array<{ name: string; type: string }>> = {};
    for (const [k, v] of Object.entries(types)) {
      mutableTypes[k] = [...v];
    }
    const sig = await signer.signTypedData(domain, mutableTypes, message);
    if (!isHex(sig)) throw new Error('Invalid EIP-712 signature');
    return sig;
  }
  const sig = await signer.signTypedData({
    domain,
    types,
    primaryType,
    message,
  });
  if (!isHex(sig)) throw new Error('Invalid EIP-712 signature');
  return sig;
}

export async function prepareBlindedVoucherRequest(params: {
  beneficiarySigner: UniversalTypedDataSigner;
  vaultAddress: string;
  slipId: string | bigint | number;
  voiceKeyIdBytes: Uint8Array;
  nowSec?: number;
}) {
  const cleanVault = getAddress(normalizeVoiceVaultAddress(params.vaultAddress));
  const slipIdDec = normalizeVoiceSlipIdDecimal(params.slipId);
  const voucherNonceBytes = fillRandomBytes(new Uint8Array(32));
  const voprfInput = deriveVoucherVoprfInput(params.voiceKeyIdBytes, voucherNonceBytes);
  const { blindScalarHex, blindedHex } = voiceVoprf.blind(voprfInput);

  const deadlineSec = (params.nowSec ?? Math.floor(Date.now() / 1000)) + 300;
  const blindedDigestHex = `0x${rawBytesToHex(sha256(rawHexToBytes(blindedHex, 33)))}` as Hex;

  const signature = await signTypedWithUniversal(
    params.beneficiarySigner,
    {
      name: 'CryptoSLIP Voice Voucher',
      version: '1',
      chainId: BASE_CHAIN_ID,
      verifyingContract: cleanVault,
    },
    VOICE_VOUCHER_TYPES,
    'VoiceVoucherRequest',
    {
      slipId: BigInt(slipIdDec),
      blindedDigest: blindedDigestHex,
      deadline: BigInt(deadlineSec),
    },
  );

  return {
    voucherNonceBytes,
    voprfInput,
    blindScalarHex,
    requestBody: {
      vaultAddress: cleanVault.toLowerCase(),
      slipId: slipIdDec,
      blindedHex,
      deadlineSec,
      signature,
    },
  };
}

export function finalizeVoucherAndPackEnvelope(params: {
  voprfInput: Uint8Array;
  blindScalarHex: string;
  expectedPkHex: string;
  epochId: number;
  evaluatedHex: string;
  proofHex: string;
  voiceKeyIdBytes: Uint8Array;
  voucherNonceBytes: Uint8Array;
  encryptedPayloadBytes: Uint8Array;
  ttlSec?: number;
}): Uint8Array {
  const voprfOutputBytes = voiceVoprf.finalize(
    params.voprfInput,
    params.blindScalarHex,
    params.expectedPkHex,
    params.evaluatedHex,
    params.proofHex,
  );
  try {
    return packUploadEnvelope({
      epochId: params.epochId,
      ttlSec: params.ttlSec ?? VOICE_DEFAULT_TTL_SEC,
      voiceKeyIdBytes: params.voiceKeyIdBytes,
      voucherNonceBytes: params.voucherNonceBytes,
      voprfOutputBytes,
      encryptedPayloadBytes: params.encryptedPayloadBytes,
    });
  } finally {
    voprfOutputBytes.fill(0);
  }
}

export async function prepareBlindPassRedeemRequest(params: {
  payerSigner: UniversalTypedDataSigner;
  passContract: string;
  passId: string | bigint | number;
  voiceKeyIdsHex: readonly string[];
  turnstileToken?: string;
  nowSec?: number;
}) {
  if (params.voiceKeyIdsHex.length < 1 || params.voiceKeyIdsHex.length > 50) {
    throw new Error('Voice note could not be accepted');
  }
  const cleanContract = getAddress(normalizeVoiceVaultAddress(params.passContract));
  const passIdDec = normalizeVoiceSlipIdDecimal(params.passId);
  const slots: Array<{
    voiceKeyIdHex: string;
    voucherNonceHex: string;
    voprfInputHex: string;
    blindScalarHex: string;
  }> = [];
  const blindedHexList: string[] = [];
  const blindedBytesList: Uint8Array[] = [];

  for (const rawId of params.voiceKeyIdsHex) {
    const idBytes = rawHexToBytes(rawId, 32);
    const voucherNonceBytes = fillRandomBytes(new Uint8Array(32));
    const voprfInput = deriveVoucherVoprfInput(idBytes, voucherNonceBytes);
    const { blindScalarHex, blindedHex } = voiceVoprf.blind(voprfInput);
    blindedHexList.push(blindedHex);
    blindedBytesList.push(rawHexToBytes(blindedHex, 33));
    slots.push({
      voiceKeyIdHex: rawBytesToHex(idBytes),
      voucherNonceHex: rawBytesToHex(voucherNonceBytes),
      voprfInputHex: rawBytesToHex(voprfInput),
      blindScalarHex,
    });
    voucherNonceBytes.fill(0);
    voprfInput.fill(0);
  }

  const blindedListDigestHex = `0x${rawBytesToHex(sha256(concatUint8(...blindedBytesList)))}` as Hex;
  const deadlineSec = (params.nowSec ?? Math.floor(Date.now() / 1000)) + 300;
  const signature = await signTypedWithUniversal(
    params.payerSigner,
    {
      name: 'CryptoSLIP Voice Pass',
      version: '1',
      chainId: BASE_CHAIN_ID,
      verifyingContract: cleanContract,
    },
    VOICE_PASS_REDEEM_TYPES,
    'VoicePassRedeem',
    {
      passId: BigInt(passIdDec),
      blindedListDigest: blindedListDigestHex,
      count: BigInt(blindedHexList.length),
      deadline: BigInt(deadlineSec),
    },
  );

  return {
    requestBody: {
      passId: passIdDec,
      blindedHexList,
      deadlineSec,
      signature,
      ...(params.turnstileToken ? { turnstileToken: params.turnstileToken } : {}),
    },
    slots,
  };
}

export function finalizeBlindPassPackResponse(params: {
  slots: ReadonlyArray<{
    voiceKeyIdHex: string;
    voucherNonceHex: string;
    voprfInputHex: string;
    blindScalarHex: string;
  }>;
  expectedPkHex: string;
  epochId: number;
  tier: number;
  items: ReadonlyArray<{ evaluatedHex: string; proofHex: string }>;
}) {
  if (params.items.length !== params.slots.length) {
    throw new Error('Voice note could not be accepted');
  }
  return params.slots.map((slot, i) => {
    const item = params.items[i];
    if (!item) throw new Error('Voice note could not be accepted');
    const outBytes = voiceVoprf.finalize(
      rawHexToBytes(slot.voprfInputHex, 32),
      slot.blindScalarHex,
      params.expectedPkHex,
      item.evaluatedHex,
      item.proofHex,
    );
    const voprfOutputHex = rawBytesToHex(outBytes);
    outBytes.fill(0);
    return {
      epochId: params.epochId,
      tier: params.tier,
      voiceKeyIdHex: slot.voiceKeyIdHex,
      voucherNonceHex: slot.voucherNonceHex,
      voprfOutputHex,
    };
  });
}

// ============================================================================
// High-Level Burn-on-Play Client (`uploadBurnOnPlayVoice` & `playAndBurnVoice`)
// ============================================================================

function validateVoiceServerUrl(raw?: string): { baseUrl: string; host: string } {
  const trimmed = String(raw || VOICE_GATEWAY_URL).trim().replace(/\/+$/, '');
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error('Invalid voice server URL');
  }
  const isLoopback = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
  if (parsed.protocol !== 'https:' && !(isLoopback && parsed.protocol === 'http:')) {
    throw new Error('Voice server URL must use https:// (or loopback http://127.0.0.1 for local tests)');
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error('Voice server URL cannot contain credentials, query parameters, or fragments');
  }
  return {
    baseUrl: parsed.toString().replace(/\/+$/, ''),
    host: parsed.host.toLowerCase(),
  };
}

/**
 * Injects `_vn1` into the slip payload and appends `&vk=<fragmentVoiceKey>` strictly inside the
 * URL `#` fragment (never in query strings or `t.me` URLs!).
 */
export function attachVoiceToSlipUrl(rawSlipUrl: string, fragmentVoiceKey?: string): string {
  assertFragmentSafeUrl(rawSlipUrl);
  const parsed = parseSlipUrl(rawSlipUrl);
  if (!parsed) {
    throw new Error('Invalid CryptoSLIP URL for voice attachment');
  }
  let origin: string = CANONICAL_SHARE_ORIGIN;
  if (/^https?:/i.test(rawSlipUrl)) {
    origin = new URL(rawSlipUrl).origin;
  }
  const encoded = encodeSlipUrl({
    id: parsed.id,
    amount: parsed.amount,
    asset: parsed.asset,
    vault: parsed.vault,
    mode: parsed.mode,
    claimKey: parsed.claimKey,
    claimKeyPrefix: parsed.claimKeyPrefix,
    codeSalt: parsed.codeSalt,
    cancelLockedUntil: parsed.cancelLockedUntil,
    hasVoiceNote: true,
    origin,
    voiceKey: fragmentVoiceKey ?? parsed.voiceKey,
    note: parsed.note,
    socialSeal: parsed.socialSeal,
    embedClaimCodeInFragment: parsed.claimCode,
  });
  assertFragmentSafeUrl(encoded.webUrl);
  return encoded.webUrl;
}

export interface UploadBurnOnPlayVoiceParams {
  /** Audio payload (`<= 60,016` bytes raw/ADPCM or pre-packed `60,032`-byte `CSV1` frame). */
  audioBytes: Uint8Array;
  durationMs?: number;
  /** Slip asset used to hard-enforce the `$1.00+` USD equivalent floor BEFORE encrypting or uploading. */
  asset: AnyAssetSymbol | string;
  /** Slip atomic amount (`>= 1_000_000n` USDC, `>= 400_000_000_000_000n` ETH/NARA, `>= 1_000n` cbBTC). */
  slipAmount: bigint;
  minUsdMicro?: bigint;
  vault?: VaultTag;
  vaultAddress?: Address | string;
  slipId: string | bigint | number;
  mode?: 'open' | 'code';
  claimPrivateKey?: Hex | string;
  fragmentVoiceKey?: string;
  claimCode?: string;
  codeSalt?: string;
  /** Signer of `refundBeneficiary[slipId]` (typically `creator` before first Keep) for `/api/voice/voucher`. */
  beneficiarySigner: UniversalTypedDataSigner;
  /** Optional `#startapp=slip_...` URL to upgrade with `_vn1` + `&vk=<fragmentVoiceKey>` in `#` fragment. */
  slipUrl?: string;
  voiceServerUrl?: string;
  originHeader?: string;
  ttlSec?: number;
  turnstileToken?: string;
  /** Optional pinned VOPRF epoch public key hex (fetched from `/api/voice/public-key` when omitted). */
  expectedPkHex?: string;
  fetchFn?: typeof fetch;
  nowSec?: number;
}

export interface UploadBurnOnPlayVoiceResult {
  voiceKeyIdHex: string;
  epochId: number;
  fragmentVoiceKey?: string;
  /** Updated `#` fragment URL carrying `_vn1` and `&vk=<fragmentVoiceKey>` (when `slipUrl` was passed). */
  slipUrlWithVoice?: string;
}

/**
 * Encrypts a voice note, acquires an unlinkable RFC 9497 P-256 VOPRF upload voucher (verifying
 * the server's Chaum-Pedersen DLEQ proof against its epoch public key), uploads the fixed
 * `60,166`-byte `CSVE` binary frame, and returns the updated `#..._vn1...&vk=<key>` slip URL.
 */
export async function uploadBurnOnPlayVoice(
  params: UploadBurnOnPlayVoiceParams,
): Promise<UploadBurnOnPlayVoiceResult> {
  // 1. Hard-enforce >= $1.00 USD floor BEFORE touching keys, crypto, or network!
  assertVoiceEconomicFloor(
    params.asset,
    params.slipAmount,
    params.minUsdMicro ?? VOICE_MIN_USD_MICRO,
  );

  const { baseUrl } = validateVoiceServerUrl(params.voiceServerUrl);
  const fetchImpl = params.fetchFn ?? globalThis.fetch;
  const vaultAddr = params.vaultAddress
    ? getAddress(params.vaultAddress)
    : VAULTS[params.vault ?? ISSUE_VAULT].address;
  const mode = params.mode ?? 'open';
  const fragmentVoiceKey =
    mode === 'open' ? params.fragmentVoiceKey ?? generateFragmentVoiceKey() : undefined;

  let identity: DerivedVoiceIdentity | null = null;
  let csv1Plaintext: Uint8Array | null = null;
  let encryptedPayload: Uint8Array | null = null;
  let csveEnvelope: Uint8Array | null = null;
  let voucherNonceBytes: Uint8Array | null = null;
  let voprfInput: Uint8Array | null = null;

  try {
    identity = await deriveVoiceIdentity({
      vaultAddress: vaultAddr,
      slipId: params.slipId,
      mode,
      claimPrivateKey: params.claimPrivateKey,
      fragmentVoiceKey,
      claimCode: params.claimCode,
      codeSalt: params.codeSalt,
    });

    csv1Plaintext = packVoiceCsv1Plaintext(params.audioBytes, { durationMs: params.durationMs });
    encryptedPayload = await encryptVoicePlaintext(
      csv1Plaintext,
      identity.voiceAudioKeyBytes,
      identity.voiceKeyIdBytes,
    );
    csv1Plaintext.fill(0);

    // Fetch public epoch key unless caller pinned one
    let pinnedPkHex = params.expectedPkHex;
    let pinnedPrevEpochId: number | undefined;
    let pinnedPrevPkHex: string | undefined;
    if (!pinnedPkHex) {
      const pkResp = await fetchImpl(`${baseUrl}/api/voice/public-key`, {
        method: 'GET',
        redirect: 'error',
      });
      const pkData = (await pkResp.json()) as {
        ok?: boolean;
        epochId?: number;
        pkHex?: string;
        previousEpochId?: number;
        previousPkHex?: string;
        error?: string;
      };
      if (!pkResp.ok || !pkData.ok || !pkData.pkHex) {
        throw new Error(pkData.error || 'Voice service is paused');
      }
      pinnedPkHex = pkData.pkHex;
      pinnedPrevEpochId = pkData.previousEpochId;
      pinnedPrevPkHex = pkData.previousPkHex;
    }

    const prepared = await prepareBlindedVoucherRequest({
      beneficiarySigner: params.beneficiarySigner,
      vaultAddress: vaultAddr,
      slipId: params.slipId,
      voiceKeyIdBytes: identity.voiceKeyIdBytes,
      nowSec: params.nowSec,
    });
    voucherNonceBytes = prepared.voucherNonceBytes;
    voprfInput = prepared.voprfInput;

    const reqHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
      Origin: params.originHeader || CANONICAL_SHARE_ORIGIN,
    };
    const voucherResp = await fetchImpl(`${baseUrl}/api/voice/voucher`, {
      method: 'POST',
      headers: reqHeaders,
      body: JSON.stringify({
        ...prepared.requestBody,
        ...(params.turnstileToken ? { turnstileToken: params.turnstileToken } : {}),
      }),
      redirect: 'error',
    });
    const voucherData = (await voucherResp.json()) as {
      ok?: boolean;
      epochId?: number;
      evaluatedHex?: string;
      proofHex?: string;
      pkHex?: string;
      error?: string;
    };
    if (
      !voucherResp.ok ||
      !voucherData.ok ||
      typeof voucherData.epochId !== 'number' ||
      !voucherData.evaluatedHex ||
      !voucherData.proofHex
    ) {
      throw new Error(voucherData.error || 'Voice note could not be accepted');
    }

    const expectedKeyForEpoch =
      pinnedPrevEpochId !== undefined && voucherData.epochId === pinnedPrevEpochId && pinnedPrevPkHex
        ? pinnedPrevPkHex
        : pinnedPkHex;

    csveEnvelope = finalizeVoucherAndPackEnvelope({
      voprfInput,
      blindScalarHex: prepared.blindScalarHex,
      expectedPkHex: expectedKeyForEpoch,
      epochId: voucherData.epochId,
      evaluatedHex: voucherData.evaluatedHex,
      proofHex: voucherData.proofHex,
      voiceKeyIdBytes: identity.voiceKeyIdBytes,
      voucherNonceBytes,
      encryptedPayloadBytes: encryptedPayload,
      ttlSec: params.ttlSec,
    });

    const uploadBody = toWebCryptoBytes(csveEnvelope);
    const uploadResp = await fetchImpl(`${baseUrl}/api/voice/upload`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        Origin: params.originHeader || CANONICAL_SHARE_ORIGIN,
      },
      body: uploadBody,
      redirect: 'error',
    });
    uploadBody.fill(0);
    const uploadData = (await uploadResp.json().catch(() => ({}))) as {
      ok?: boolean;
      error?: string;
    };
    if (!uploadResp.ok || !uploadData.ok) {
      throw new Error(uploadData.error || 'Voice note could not be accepted');
    }

    const slipUrlWithVoice = params.slipUrl
      ? attachVoiceToSlipUrl(params.slipUrl, fragmentVoiceKey)
      : undefined;

    return {
      voiceKeyIdHex: identity.voiceKeyIdHex,
      epochId: voucherData.epochId,
      ...(fragmentVoiceKey ? { fragmentVoiceKey } : {}),
      ...(slipUrlWithVoice ? { slipUrlWithVoice } : {}),
    };
  } finally {
    zeroVoiceIdentity(identity);
    zeroizeVoiceBuffers(csv1Plaintext, encryptedPayload, csveEnvelope, voucherNonceBytes, voprfInput);
  }
}

export interface PlayAndBurnVoiceParams {
  /** Either pass a `#startapp=slip_..._vn1...&vk=<key>` URL or explicit slip credentials below. */
  slipUrl?: string;
  vault?: VaultTag;
  vaultAddress?: Address | string;
  slipId?: string | bigint | number;
  mode?: 'open' | 'code';
  claimPrivateKey?: Hex | string;
  fragmentVoiceKey?: string;
  claimCode?: string;
  codeSalt?: string;
  voiceServerUrl?: string;
  originHeader?: string;
  /** Defaults to `true` — immediately sends signed `ACK` after decrypting to burn the shard slot. */
  acknowledgeBurn?: boolean;
  fetchFn?: typeof fetch;
  nowSec?: number;
}

export interface PlayAndBurnVoiceResult {
  audioBytes: Uint8Array;
  durationMs: number;
  codecId: number;
  voiceKeyIdHex: string;
  burned: boolean;
  zeroize: () => void;
}

function resolveVoiceParamsFromInput(params: PlayAndBurnVoiceParams) {
  if (params.slipUrl) {
    assertFragmentSafeUrl(params.slipUrl);
    const parsed = parseSlipUrl(params.slipUrl);
    if (!parsed) throw new Error('Invalid CryptoSLIP URL');
    const resolvedVaultAddr = params.vaultAddress
      ? getAddress(params.vaultAddress)
      : VAULTS[params.vault ?? parsed.vault].address;
    return {
      vaultAddress: resolvedVaultAddr,
      slipId: params.slipId ?? parsed.id,
      mode: params.mode ?? parsed.mode,
      claimPrivateKey: params.claimPrivateKey ?? parsed.claimKey,
      fragmentVoiceKey: params.fragmentVoiceKey ?? parsed.voiceKey,
      claimCode: params.claimCode ?? parsed.claimCode,
      codeSalt: params.codeSalt ?? parsed.codeSalt,
    };
  }
  const vaultAddr = params.vaultAddress
    ? getAddress(params.vaultAddress)
    : params.vault
      ? VAULTS[params.vault].address
      : VAULTS[ISSUE_VAULT].address;
  if (params.slipId === undefined) {
    throw new Error('playAndBurnVoice requires either slipUrl or slipId');
  }
  return {
    vaultAddress: vaultAddr,
    slipId: params.slipId,
    mode: params.mode ?? 'open',
    claimPrivateKey: params.claimPrivateKey,
    fragmentVoiceKey: params.fragmentVoiceKey,
    claimCode: params.claimCode,
    codeSalt: params.codeSalt,
  };
}

/**
 * Fetches, authenticates, decrypts, and burns a one-time voice note from `cryptoslip-voice`,
 * scrubbing all intermediate keys, ciphertexts, and padded frames immediately.
 */
export async function playAndBurnVoice(
  params: PlayAndBurnVoiceParams,
): Promise<PlayAndBurnVoiceResult> {
  const { baseUrl, host } = validateVoiceServerUrl(params.voiceServerUrl);
  const fetchImpl = params.fetchFn ?? globalThis.fetch;
  const resolved = resolveVoiceParamsFromInput(params);

  let identity: DerivedVoiceIdentity | null = null;
  let cipherBytes: Uint8Array | null = null;
  let plainBytes: Uint8Array | null = null;

  try {
    identity = await deriveVoiceIdentity({
      vaultAddress: resolved.vaultAddress,
      slipId: resolved.slipId,
      mode: resolved.mode,
      claimPrivateKey: resolved.claimPrivateKey,
      fragmentVoiceKey: resolved.fragmentVoiceKey,
      claimCode: resolved.claimCode,
      codeSalt: resolved.codeSalt,
    });

    const playNonce = randomVoiceNonceHex16Bytes();
    const signedPlay = await signVoiceAction({
      action: 'PLAY',
      host,
      identity,
      nonceHex: playNonce,
      timestampSec: params.nowSec,
    });

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Origin: params.originHeader || CANONICAL_SHARE_ORIGIN,
    };
    const playResp = await fetchImpl(`${baseUrl}/api/voice/play`, {
      method: 'POST',
      headers,
      body: JSON.stringify(signedPlay),
      redirect: 'error',
    });
    if (!playResp.ok) {
      throw new Error('Voice note is not available');
    }

    cipherBytes = new Uint8Array(await playResp.arrayBuffer());
    plainBytes = await decryptVoiceCiphertext(
      cipherBytes,
      identity.voiceAudioKeyBytes,
      identity.voiceKeyIdBytes,
    );
    const unpacked = unpackVoiceCsv1Plaintext(plainBytes);

    let burned = false;
    if (params.acknowledgeBurn !== false) {
      const signedAck = await signVoiceAction({
        action: 'ACK',
        host,
        identity,
        nonceHex: playNonce,
        timestampSec: params.nowSec,
      });
      const ackResp = await fetchImpl(`${baseUrl}/api/voice/ack`, {
        method: 'POST',
        headers,
        body: JSON.stringify(signedAck),
        redirect: 'error',
      }).catch(() => null);
      if (ackResp?.ok) {
        const ackJson = (await ackResp.json().catch(() => ({}))) as { burned?: boolean };
        burned = ackJson.burned === true;
      }
    }

    return {
      audioBytes: unpacked.audioBytes,
      durationMs: unpacked.durationMs,
      codecId: unpacked.codecId,
      voiceKeyIdHex: identity.voiceKeyIdHex,
      burned,
      zeroize: () => {
        unpacked.audioBytes.fill(0);
      },
    };
  } finally {
    zeroVoiceIdentity(identity);
    zeroizeVoiceBuffers(cipherBytes, plainBytes);
  }
}

export async function checkBurnOnPlayVoiceStatus(
  params: Omit<PlayAndBurnVoiceParams, 'acknowledgeBurn'>,
): Promise<'available' | 'gone' | 'error'> {
  const { baseUrl, host } = validateVoiceServerUrl(params.voiceServerUrl);
  const fetchImpl = params.fetchFn ?? globalThis.fetch;
  const resolved = resolveVoiceParamsFromInput(params);
  let identity: DerivedVoiceIdentity | null = null;
  try {
    identity = await deriveVoiceIdentity(resolved);
    const signed = await signVoiceAction({
      action: 'STATUS',
      host,
      identity,
      timestampSec: params.nowSec,
    });
    const resp = await fetchImpl(`${baseUrl}/api/voice/status`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: params.originHeader || CANONICAL_SHARE_ORIGIN,
      },
      body: JSON.stringify(signed),
      redirect: 'error',
    });
    if (!resp.ok) return 'error';
    const data = (await resp.json()) as { ok?: boolean; available?: boolean };
    if (data.ok !== true) return 'error';
    return data.available === true ? 'available' : 'gone';
  } catch {
    return 'error';
  } finally {
    zeroVoiceIdentity(identity);
  }
}

export async function burnVoiceNoteNow(
  params: Omit<PlayAndBurnVoiceParams, 'acknowledgeBurn'>,
): Promise<boolean> {
  const { baseUrl, host } = validateVoiceServerUrl(params.voiceServerUrl);
  const fetchImpl = params.fetchFn ?? globalThis.fetch;
  const resolved = resolveVoiceParamsFromInput(params);
  let identity: DerivedVoiceIdentity | null = null;
  try {
    identity = await deriveVoiceIdentity(resolved);
    const signed = await signVoiceAction({
      action: 'BURN',
      host,
      identity,
      timestampSec: params.nowSec,
    });
    const resp = await fetchImpl(`${baseUrl}/api/voice/burn`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: params.originHeader || CANONICAL_SHARE_ORIGIN,
      },
      body: JSON.stringify(signed),
      redirect: 'error',
    });
    if (!resp.ok) return false;
    const data = (await resp.json()) as { ok?: boolean; burned?: boolean };
    return Boolean(data.ok && data.burned);
  } catch {
    return false;
  } finally {
    zeroVoiceIdentity(identity);
  }
}

export { vaultTagForAddress };
