import { createHash, randomBytes } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import {
  bytesToBigInt,
  bytesToHex,
  decodeEventLog,
  encodeFunctionData,
  formatUnits,
  getAddress,
  hexToBytes,
  isAddress,
  parseAbiItem,
  parseUnits,
  stringToBytes,
  type Address,
  type Hex,
  type TransactionReceipt,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import {
  CRYPTO_SLIP_VAULT_V32_ABI,
  ERC20_PERMIT_EIP3009_ABI,
} from './abi.js';
import {
  appendBuilderCodeSuffix,
  assetAddress,
  BASE_CHAIN_ID,
  BLOCKED_PAYMENT_TARGETS,
  CANONICAL_SHARE_ORIGIN,
  CBBTC_BASE_ADDRESS,
  computeProtocolFeeCeiling,
  decimalsForAsset,
  DEFAULT_CRYPTOSLIP_BUILDER_CODE,
  grossUpForExactNet,
  ISSUE_VAULT,
  isV32ProtocolVault,
  minSlipAmount,
  MULTICALL3_ADDRESS,
  NARA_BASE_ADDRESS,
  NARA_IN_APP_BUILDER_CODES,
  NO_TAKE_BACK_LOCK,
  normalizeSdkAsset,
  USDC_BASE_ADDRESS,
  vaultAddress,
  ZERO_ADDRESS,
  type AnyAssetSymbol,
  type SdkAssetSymbol,
  type VaultTag,
} from './constants.js';
import {
  deriveCodeWallet,
  encodeSlipUrl,
  formatClaimCode,
  generateClaimCode,
  generateCodeSalt,
  sanitizeSlipNote,
  type SlipLinkMode,
} from './link.js';
import {
  canSponsorWithCircleUsdcPaymaster,
  encodeSimple7702Calls,
  executeViaCircleUsdcPaymaster,
  isPersonalOrCanonical7702Code,
  type BaseCompatiblePublicClient,
  type BaseCompatibleWalletClient,
  type BundlerFetchFn,
  type UserOpCall,
} from './paymaster.js';

export type { BaseCompatiblePublicClient, BaseCompatibleWalletClient } from './paymaster.js';

const SECP256K1_FIELD_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_HALF_ORDER = SECP256K1_ORDER >> 1n;
const COMPROMISED_SIGNER_LOWER = '0x5f3a378b685e309ae7404a7483420e49f2fbe6aa';

const HEX_LOWER_CHARS = '0123456789abcdef';
const HEX_UPPER_CHARS = '0123456789ABCDEF';
const ZERO_BYTES_20 = new Uint8Array(20);
const USDC_BYTES_20 = hexToBytes(USDC_BASE_ADDRESS);
const CBBTC_BYTES_20 = hexToBytes(CBBTC_BASE_ADDRESS);
const NARA_BYTES_20 = hexToBytes(NARA_BASE_ADDRESS);

function uint8ToHexFast(bytes: Uint8Array): Hex {
  return `0x${Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('hex')}` as Hex;
}

const SIGNED_11BIT_SLICES = 24;
const SIGNED_11BIT_STRIDE = 1025; // indices 1..1024

let signed11GX: bigint[] | null = null;
let signed11GY: bigint[] | null = null;

function modFieldP(x: bigint): bigint {
  const r = x % SECP256K1_FIELD_P;
  return r < 0n ? r + SECP256K1_FIELD_P : r;
}

function checksumAddressFromBytes20(addr20: Uint8Array): Address {
  const asciiLower = new Uint8Array(40);
  for (let i = 0; i < 20; i++) {
    const byte = addr20[i]!;
    const hi = byte >>> 4;
    const lo = byte & 0x0f;
    asciiLower[i * 2] = hi < 10 ? 48 + hi : 87 + hi;
    asciiLower[i * 2 + 1] = lo < 10 ? 48 + lo : 87 + lo;
  }
  const hash = keccak_256(asciiLower);
  let out = '0x';
  for (let i = 0; i < 20; i++) {
    const byte = addr20[i]!;
    const hi = byte >>> 4;
    const lo = byte & 0x0f;
    const hashByte = hash[i]!;
    out += (hashByte >>> 4) >= 8 ? HEX_UPPER_CHARS[hi]! : HEX_LOWER_CHARS[hi]!;
    out += (hashByte & 0x0f) >= 8 ? HEX_UPPER_CHARS[lo]! : HEX_LOWER_CHARS[lo]!;
  }
  return out as Address;
}

function ensureSigned11GeneratorTable(): { gx: bigint[]; gy: bigint[] } {
  if (signed11GX && signed11GY) {
    return { gx: signed11GX, gy: signed11GY };
  }
  const gx = Array.from<bigint>({ length: SIGNED_11BIT_SLICES * SIGNED_11BIT_STRIDE });
  const gy = Array.from<bigint>({ length: SIGNED_11BIT_SLICES * SIGNED_11BIT_STRIDE });
  const Fp = secp256k1.Point.Fp;
  let basePt = secp256k1.Point.BASE;

  for (let s = 0; s < SIGNED_11BIT_SLICES; s++) {
    const bx = basePt.x;
    const by = basePt.y;
    const jX: bigint[] = [bx];
    const jY: bigint[] = [by];
    const jZ: bigint[] = [1n];

    let X1 = bx;
    let Y1 = by;
    let Z1 = 1n;
    for (let w = 2; w <= 1024; w++) {
      const Z1Z1 = (Z1 * Z1) % SECP256K1_FIELD_P;
      const U2 = (bx * Z1Z1) % SECP256K1_FIELD_P;
      const S2 = (((by * Z1) % SECP256K1_FIELD_P) * Z1Z1) % SECP256K1_FIELD_P;
      let H = U2 - X1;
      if (H < 0n) H += SECP256K1_FIELD_P;
      let dY = S2 - Y1;
      if (dY < 0n) dY += SECP256K1_FIELD_P;
      let r = dY << 1n;
      if (r >= SECP256K1_FIELD_P) r -= SECP256K1_FIELD_P;

      if (H === 0n) {
        const XX = (bx * bx) % SECP256K1_FIELD_P;
        const YY = (by * by) % SECP256K1_FIELD_P;
        const YYYY = (YY * YY) % SECP256K1_FIELD_P;
        const S = (2n * modFieldP((bx + YY) * (bx + YY) - XX - YYYY)) % SECP256K1_FIELD_P;
        const M = (3n * XX) % SECP256K1_FIELD_P;
        X1 = modFieldP(M * M - 2n * S);
        Y1 = modFieldP(M * (S - X1) - 8n * YYYY);
        Z1 = (2n * by) % SECP256K1_FIELD_P;
      } else {
        const HH = (H * H) % SECP256K1_FIELD_P;
        let I = HH << 1n;
        if (I >= SECP256K1_FIELD_P) I -= SECP256K1_FIELD_P;
        I <<= 1n;
        if (I >= SECP256K1_FIELD_P) I -= SECP256K1_FIELD_P;
        const J = (H * I) % SECP256K1_FIELD_P;
        const V = (X1 * I) % SECP256K1_FIELD_P;
        let X3 = ((r * r) % SECP256K1_FIELD_P) - J - V - V;
        while (X3 < 0n) X3 += SECP256K1_FIELD_P;
        let vSub = V - X3;
        if (vSub < 0n) vSub += SECP256K1_FIELD_P;
        let yJ = (Y1 * J) % SECP256K1_FIELD_P;
        yJ <<= 1n;
        if (yJ >= SECP256K1_FIELD_P) yJ -= SECP256K1_FIELD_P;
        let Y3 = ((r * vSub) % SECP256K1_FIELD_P) - yJ;
        if (Y3 < 0n) Y3 += SECP256K1_FIELD_P;
        const zh = Z1 + H;
        let Z3 = ((zh * zh) % SECP256K1_FIELD_P) - Z1Z1 - HH;
        while (Z3 < 0n) Z3 += SECP256K1_FIELD_P;
        X1 = X3;
        Y1 = Y3;
        Z1 = Z3;
      }
      jX.push(X1);
      jY.push(Y1);
      jZ.push(Z1);
    }

    const zInvs = Fp.invertBatch(jZ);
    const sliceOffset = s * SIGNED_11BIT_STRIDE;
    for (let w = 1; w <= 1024; w++) {
      const zi = zInvs[w - 1]!;
      const zi2 = (zi * zi) % SECP256K1_FIELD_P;
      const zi3 = (zi2 * zi) % SECP256K1_FIELD_P;
      gx[sliceOffset + w] = (jX[w - 1]! * zi2) % SECP256K1_FIELD_P;
      gy[sliceOffset + w] = (jY[w - 1]! * zi3) % SECP256K1_FIELD_P;
    }

    if (s < SIGNED_11BIT_SLICES - 1) {
      for (let d = 0; d < 11; d++) {
        basePt = basePt.double();
      }
    }
  }

  signed11GX = gx;
  signed11GY = gy;
  return { gx, gy };
}

function mulBaseSigned11Jacobian(
  kScalar: bigint,
  gx: readonly bigint[],
  gy: readonly bigint[],
): { X: bigint; Y: bigint; Z: bigint } {
  let X1 = 0n;
  let Y1 = 0n;
  let Z1 = 0n;
  let rem = kScalar;

  for (let s = 0; s < SIGNED_11BIT_SLICES && rem > 0n; s++) {
    let digit = Number(rem & 2047n);
    rem >>= 11n;
    if (digit > 1024) {
      digit -= 2048;
      rem += 1n;
    }
    if (digit === 0) continue;

    let x2: bigint;
    let y2: bigint;
    if (digit > 0) {
      const tIdx = s * SIGNED_11BIT_STRIDE + digit;
      x2 = gx[tIdx]!;
      y2 = gy[tIdx]!;
    } else {
      const tIdx = s * SIGNED_11BIT_STRIDE - digit;
      x2 = gx[tIdx]!;
      const rawY = gy[tIdx]!;
      y2 = rawY === 0n ? 0n : SECP256K1_FIELD_P - rawY;
    }

    if (Z1 === 0n) {
      X1 = x2;
      Y1 = y2;
      Z1 = 1n;
      continue;
    }

    const Z1Z1 = (Z1 * Z1) % SECP256K1_FIELD_P;
    const U2 = (x2 * Z1Z1) % SECP256K1_FIELD_P;
    const S2 = (((y2 * Z1) % SECP256K1_FIELD_P) * Z1Z1) % SECP256K1_FIELD_P;
    let H = U2 - X1;
    if (H < 0n) H += SECP256K1_FIELD_P;
    let dY = S2 - Y1;
    if (dY < 0n) dY += SECP256K1_FIELD_P;
    let r = dY << 1n;
    if (r >= SECP256K1_FIELD_P) r -= SECP256K1_FIELD_P;

    if (H === 0n) {
      if (r === 0n) {
        const XX = (x2 * x2) % SECP256K1_FIELD_P;
        const YY = (y2 * y2) % SECP256K1_FIELD_P;
        const YYYY = (YY * YY) % SECP256K1_FIELD_P;
        const S = (2n * modFieldP((x2 + YY) * (x2 + YY) - XX - YYYY)) % SECP256K1_FIELD_P;
        const M = (3n * XX) % SECP256K1_FIELD_P;
        X1 = modFieldP(M * M - 2n * S);
        Y1 = modFieldP(M * (S - X1) - 8n * YYYY);
        Z1 = (2n * y2) % SECP256K1_FIELD_P;
      } else {
        Z1 = 0n;
      }
      continue;
    }

    const HH = (H * H) % SECP256K1_FIELD_P;
    let I = HH << 1n;
    if (I >= SECP256K1_FIELD_P) I -= SECP256K1_FIELD_P;
    I <<= 1n;
    if (I >= SECP256K1_FIELD_P) I -= SECP256K1_FIELD_P;
    const J = (H * I) % SECP256K1_FIELD_P;
    const V = (X1 * I) % SECP256K1_FIELD_P;
    let X3 = ((r * r) % SECP256K1_FIELD_P) - J - V - V;
    while (X3 < 0n) X3 += SECP256K1_FIELD_P;
    let vSub = V - X3;
    if (vSub < 0n) vSub += SECP256K1_FIELD_P;
    let yJ = (Y1 * J) % SECP256K1_FIELD_P;
    yJ <<= 1n;
    if (yJ >= SECP256K1_FIELD_P) yJ -= SECP256K1_FIELD_P;
    let Y3 = ((r * vSub) % SECP256K1_FIELD_P) - yJ;
    if (Y3 < 0n) Y3 += SECP256K1_FIELD_P;
    const zh = Z1 + H;
    let Z3 = ((zh * zh) % SECP256K1_FIELD_P) - Z1Z1 - HH;
    while (Z3 < 0n) Z3 += SECP256K1_FIELD_P;
    X1 = X3;
    Y1 = Y3;
    Z1 = Z3;
  }
  return { X: X1, Y: Y1, Z: Z1 };
}

function batchDeriveAddressesMontgomery(
  privKeys32: readonly Uint8Array[],
): Array<{ addr20: Uint8Array; address: Address }> {
  if (privKeys32.length === 0) return [];
  const { gx, gy } = ensureSigned11GeneratorTable();
  const Fp = secp256k1.Point.Fp;
  const jX: bigint[] = [];
  const jY: bigint[] = [];
  const jZ: bigint[] = [];

  for (const pk32 of privKeys32) {
    const j = mulBaseSigned11Jacobian(bytesToBigInt(pk32), gx, gy);
    jX.push(j.X);
    jY.push(j.Y);
    jZ.push(j.Z === 0n ? 1n : j.Z);
  }

  const zInvs = Fp.invertBatch(jZ);
  const pubBuf64 = new Uint8Array(64);
  const out: Array<{ addr20: Uint8Array; address: Address }> = [];

  for (let idx = 0; idx < privKeys32.length; idx++) {
    const zi = zInvs[idx]!;
    const zi2 = (zi * zi) % SECP256K1_FIELD_P;
    const zi3 = (zi2 * zi) % SECP256K1_FIELD_P;
    const x = (jX[idx]! * zi2) % SECP256K1_FIELD_P;
    const y = (jY[idx]! * zi3) % SECP256K1_FIELD_P;
    writeUint256Word(pubBuf64, 0, x);
    writeUint256Word(pubBuf64, 32, y);
    const addr20 = keccak_256(pubBuf64).slice(12, 32);
    out.push({ addr20, address: checksumAddressFromBytes20(addr20) });
  }
  return out;
}

interface SingleUseEcdsaCoupon {
  kInv: bigint;
  r: bigint;
  rawRec: number;
  consumed: boolean;
}

const MAX_WARMED_COUPONS = 2_048;
const singleUseEcdsaCouponPool: SingleUseEcdsaCoupon[] = [];

/**
 * FIPS 186-5 / ISO 14888-3 Offline-Online ECDSA Precomputation:
 * Pre-generates `signatureCount` fresh OS-CSPRNG single-use ECDSA `(k^-1, r, rec)` coupons
 * in a single Montgomery simultaneous inversion pass. Each coupon is atomically `.pop()`ped,
 * checked (`!consumed`), marked `consumed = true`, and zeroized (`kInv = 0n`) on first use,
 * making nonce reuse mathematically impossible while reducing online batch signing of 50 slips
 * (100 EIP-712 signatures) to ~4-8ms!
 */
export function warmBatchSigningPool(signatureCount = 100): number {
  const capped = Math.max(
    0,
    Math.min(
      Math.trunc(signatureCount),
      MAX_WARMED_COUPONS - singleUseEcdsaCouponPool.length,
    ),
  );
  if (capped === 0) return singleUseEcdsaCouponPool.length;

  const { gx, gy } = ensureSigned11GeneratorTable();
  const Fn = secp256k1.Point.Fn;
  const Fp = secp256k1.Point.Fp;

  const ks: bigint[] = [];
  const jX: bigint[] = [];
  const jY: bigint[] = [];
  const jZ: bigint[] = [];
  const csprng = randomBytes(capped * 32);

  for (let i = 0; i < capped; i++) {
    let slice = csprng.subarray(i * 32, (i + 1) * 32);
    let kNum = bytesToBigInt(slice);
    while (kNum <= 0n || kNum >= SECP256K1_ORDER) {
      slice = randomBytes(32);
      kNum = bytesToBigInt(slice);
    }
    const j = mulBaseSigned11Jacobian(kNum, gx, gy);
    if (j.Z === 0n) continue;
    ks.push(kNum);
    jX.push(j.X);
    jY.push(j.Y);
    jZ.push(j.Z);
  }

  if (ks.length === 0) return singleUseEcdsaCouponPool.length;
  const zInvs = Fp.invertBatch(jZ);
  const kInvs = Fn.invertBatch(ks);

  for (let i = 0; i < ks.length; i++) {
    const zi = zInvs[i]!;
    const zi2 = (zi * zi) % SECP256K1_FIELD_P;
    const zi3 = (zi2 * zi) % SECP256K1_FIELD_P;
    const x = (jX[i]! * zi2) % SECP256K1_FIELD_P;
    const y = (jY[i]! * zi3) % SECP256K1_FIELD_P;
    const r = x % SECP256K1_ORDER;
    if (r === 0n) continue;
    singleUseEcdsaCouponPool.push({
      kInv: kInvs[i]!,
      r,
      rawRec: Number(y & 1n) | (x >= SECP256K1_ORDER ? 2 : 0),
      consumed: false,
    });
  }

  return singleUseEcdsaCouponPool.length;
}

/**
 * Batch-signs `M` 32-byte EIP-712 digests using:
 * - Atomic single-use FIPS 186-5 precomputed `(k^-1, r, rec)` coupons when warmed (~0.4ms for 100 sigs!),
 * - Falling back seamlessly to CSPRNG-hedged Signed-11-bit Jacobian + Montgomery simultaneous inversion
 *   for any remaining digests when the coupon pool is cold.
 */
function batchSignDigestsMontgomery(
  digests: readonly Uint8Array[],
  privKey32: Uint8Array,
): Array<{ sigBytes65: Uint8Array; v: number; rBytes: Uint8Array; sBytes: Uint8Array }> {
  const count = digests.length;
  if (count === 0) return [];
  const Fn = secp256k1.Point.Fn;
  const d = bytesToBigInt(privKey32);

  const results: Array<{
    sigBytes65: Uint8Array;
    v: number;
    rBytes: Uint8Array;
    sBytes: Uint8Array;
  } | null> = Array.from({ length: count }, () => null);

  const coldIndices: number[] = [];

  for (let mIdx = 0; mIdx < count; mIdx++) {
    const coupon = singleUseEcdsaCouponPool.pop();
    if (!coupon) {
      coldIndices.push(mIdx);
      continue;
    }
    if (coupon.consumed || coupon.kInv === 0n) {
      throw new BatchValidationError('Internal invariant violation: ECDSA coupon already consumed.');
    }
    const kInv = coupon.kInv;
    const r = coupon.r;
    let rec = coupon.rawRec;
    // Immediately zeroize secret k^-1 and mark consumed before any arithmetic
    coupon.consumed = true;
    coupon.kInv = 0n;

    const z = bytesToBigInt(digests[mIdx]!) % SECP256K1_ORDER;
    let s = Fn.mul(kInv, Fn.add(z, Fn.mul(r, d)));
    if (s === 0n) {
      coldIndices.push(mIdx);
      continue;
    }
    if (s > SECP256K1_HALF_ORDER) {
      s = SECP256K1_ORDER - s;
      rec ^= 1;
    }
    const v = (rec & 1) + 27;
    const sigBytes65 = new Uint8Array(65);
    writeUint256Word(sigBytes65, 0, r);
    writeUint256Word(sigBytes65, 32, s);
    sigBytes65[64] = v;
    results[mIdx] = {
      sigBytes65,
      v,
      rBytes: sigBytes65.subarray(0, 32),
      sBytes: sigBytes65.subarray(32, 64),
    };
  }

  if (coldIndices.length > 0) {
    const { gx, gy } = ensureSigned11GeneratorTable();
    const Fp = secp256k1.Point.Fp;
    const csprngSeed = randomBytes(32);
    const nonceInput = new Uint8Array(101);
    nonceInput.set(privKey32, 0);
    nonceInput.set(csprngSeed, 64);

    const ks: bigint[] = [];
    const zs: bigint[] = [];
    const jX: bigint[] = [];
    const jY: bigint[] = [];
    const jZ: bigint[] = [];

    for (let c = 0; c < coldIndices.length; c++) {
      const mIdx = coldIndices[c]!;
      const msg32 = digests[mIdx]!;
      nonceInput.set(msg32, 32);
      nonceInput[96] = (mIdx >>> 24) & 0xff;
      nonceInput[97] = (mIdx >>> 16) & 0xff;
      nonceInput[98] = (mIdx >>> 8) & 0xff;
      nonceInput[99] = mIdx & 0xff;

      let kNum = 0n;
      for (let ctr = 0; ; ctr++) {
        nonceInput[100] = ctr & 0xff;
        kNum = bytesToBigInt(createHash('sha256').update(nonceInput).digest());
        if (kNum >= 1n && kNum < SECP256K1_ORDER) break;
      }

      const j = mulBaseSigned11Jacobian(kNum, gx, gy);
      ks.push(kNum);
      zs.push(bytesToBigInt(msg32) % SECP256K1_ORDER);
      jX.push(j.X);
      jY.push(j.Y);
      jZ.push(j.Z === 0n ? 1n : j.Z);
    }

    const zInvs = Fp.invertBatch(jZ);
    const kInvs = Fn.invertBatch(ks);

    for (let c = 0; c < coldIndices.length; c++) {
      const mIdx = coldIndices[c]!;
      const zi = zInvs[c]!;
      const zi2 = (zi * zi) % SECP256K1_FIELD_P;
      const zi3 = (zi2 * zi) % SECP256K1_FIELD_P;
      const x = (jX[c]! * zi2) % SECP256K1_FIELD_P;
      const y = (jY[c]! * zi3) % SECP256K1_FIELD_P;
      let r = x % SECP256K1_ORDER;
      let s = Fn.mul(kInvs[c]!, Fn.add(zs[c]!, Fn.mul(r, d)));
      let rec = Number(y & 1n) | (x >= SECP256K1_ORDER ? 2 : 0);

      if (r === 0n || s === 0n) {
        const fb = secp256k1.sign(digests[mIdx]!, privKey32, { lowS: true });
        r = fb.r;
        s = fb.s;
        rec = fb.recovery;
      } else if (s > SECP256K1_HALF_ORDER) {
        s = SECP256K1_ORDER - s;
        rec ^= 1;
      }

      const v = (rec & 1) + 27;
      const sigBytes65 = new Uint8Array(65);
      writeUint256Word(sigBytes65, 0, r);
      writeUint256Word(sigBytes65, 32, s);
      sigBytes65[64] = v;
      results[mIdx] = {
        sigBytes65,
        v,
        rBytes: sigBytes65.subarray(0, 32),
        sBytes: sigBytes65.subarray(32, 64),
      };
    }
  }

  return results as Array<{
    sigBytes65: Uint8Array;
    v: number;
    rBytes: Uint8Array;
    sBytes: Uint8Array;
  }>;
}

const EIP712_DOMAIN_TYPEHASH_BYTES = keccak_256(
  stringToBytes(
    'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)',
  ),
);
const MINT_PERMIT_TYPEHASH_BYTES = keccak_256(
  stringToBytes(
    'MintPermit(address creator,address token,uint256 amount,address claimSigner,address referrer,uint48 cancelLockedUntil,bytes32 nonce,uint256 validAfter,uint256 validBefore,address relayer)',
  ),
);
const EIP3009_RECEIVE_TYPEHASH_BYTES = keccak_256(
  stringToBytes(
    'ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)',
  ),
);
const ERC20_PERMIT_TYPEHASH_BYTES = keccak_256(
  stringToBytes(
    'Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)',
  ),
);
const BATCH_NONCE_TAG_BYTES = keccak_256(stringToBytes('CryptoSLIP/batch-mint-nonce/v1'));
const MINT_AUTH_VRS_SELECTOR_BYTES = keccak_256(
  stringToBytes(
    'mintSlipERC20WithAuthorization((address,address,uint256,address,address,uint48,bytes32,uint256,uint256,address),bytes,uint8,bytes32,bytes32)',
  ),
).subarray(0, 4);

function writeUint256Word(buf: Uint8Array, byteOffset: number, value: bigint): void {
  let v = value;
  for (let i = 31; i >= 0; i--) {
    buf[byteOffset + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

function writeAddressWord(buf: Uint8Array, byteOffset: number, addr20: Uint8Array): void {
  buf.set(addr20, byteOffset + 12);
}

function computeDomainSeparatorBytes(domain: {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: Address;
}): Uint8Array {
  const buf = new Uint8Array(160);
  buf.set(EIP712_DOMAIN_TYPEHASH_BYTES, 0);
  buf.set(keccak_256(stringToBytes(domain.name)), 32);
  buf.set(keccak_256(stringToBytes(domain.version)), 64);
  writeUint256Word(buf, 96, BigInt(domain.chainId));
  writeAddressWord(buf, 128, hexToBytes(domain.verifyingContract));
  return keccak_256(buf);
}

function hashEip712StructBytes(domainSep32: Uint8Array, structBuf: Uint8Array): Uint8Array {
  const digestInput = new Uint8Array(66);
  digestInput[0] = 0x19;
  digestInput[1] = 0x01;
  digestInput.set(domainSep32, 2);
  digestInput.set(keccak_256(structBuf), 34);
  return keccak_256(digestInput);
}

function computeMintPermitDigestBytes(
  domainSep32: Uint8Array,
  creator20: Uint8Array,
  token20: Uint8Array,
  amount: bigint,
  claimSigner20: Uint8Array,
  referrer20: Uint8Array,
  cancelLockedUntil: bigint,
  nonce32: Uint8Array,
  validAfter: bigint,
  validBefore: bigint,
): Uint8Array {
  const buf = new Uint8Array(352); // 11 * 32 bytes (word 10 = relayer = ZERO_ADDRESS)
  buf.set(MINT_PERMIT_TYPEHASH_BYTES, 0);
  writeAddressWord(buf, 32, creator20);
  writeAddressWord(buf, 64, token20);
  writeUint256Word(buf, 96, amount);
  writeAddressWord(buf, 128, claimSigner20);
  writeAddressWord(buf, 160, referrer20);
  writeUint256Word(buf, 192, cancelLockedUntil);
  buf.set(nonce32, 224);
  writeUint256Word(buf, 256, validAfter);
  writeUint256Word(buf, 288, validBefore);
  return hashEip712StructBytes(domainSep32, buf);
}

function computeEip3009ReceiveDigestBytes(
  domainSep32: Uint8Array,
  from20: Uint8Array,
  to20: Uint8Array,
  value: bigint,
  validAfter: bigint,
  validBefore: bigint,
  nonce32: Uint8Array,
): Uint8Array {
  const buf = new Uint8Array(224); // 7 * 32 bytes
  buf.set(EIP3009_RECEIVE_TYPEHASH_BYTES, 0);
  writeAddressWord(buf, 32, from20);
  writeAddressWord(buf, 64, to20);
  writeUint256Word(buf, 96, value);
  writeUint256Word(buf, 128, validAfter);
  writeUint256Word(buf, 160, validBefore);
  buf.set(nonce32, 192);
  return hashEip712StructBytes(domainSep32, buf);
}

function computeErc20PermitDigestBytes(
  domainSep32: Uint8Array,
  owner20: Uint8Array,
  spender20: Uint8Array,
  value: bigint,
  nonce: bigint,
  deadline: bigint,
): Uint8Array {
  const buf = new Uint8Array(192); // 6 * 32 bytes
  buf.set(ERC20_PERMIT_TYPEHASH_BYTES, 0);
  writeAddressWord(buf, 32, owner20);
  writeAddressWord(buf, 64, spender20);
  writeUint256Word(buf, 96, value);
  writeUint256Word(buf, 128, nonce);
  writeUint256Word(buf, 160, deadline);
  return hashEip712StructBytes(domainSep32, buf);
}

function encodeMintSlipWithAuthVrsFastBytes(
  creator20: Uint8Array,
  token20: Uint8Array,
  amount: bigint,
  claimSigner20: Uint8Array,
  referrer20: Uint8Array,
  cancelLockedUntil: bigint,
  nonce32: Uint8Array,
  validAfter: bigint,
  validBefore: bigint,
  mintSig65: Uint8Array,
  v: number,
  r32: Uint8Array,
  s32: Uint8Array,
): Uint8Array {
  const buf = new Uint8Array(580); // 4-byte selector + 18 * 32-byte ABI words
  buf.set(MINT_AUTH_VRS_SELECTOR_BYTES, 0);
  writeAddressWord(buf, 4, creator20);
  writeAddressWord(buf, 36, token20);
  writeUint256Word(buf, 68, amount);
  writeAddressWord(buf, 100, claimSigner20);
  writeAddressWord(buf, 132, referrer20);
  writeUint256Word(buf, 164, cancelLockedUntil);
  buf.set(nonce32, 196);
  writeUint256Word(buf, 228, validAfter);
  writeUint256Word(buf, 260, validBefore);
  // word 9 (292..323) = relayer = ZERO_ADDRESS (already 0)
  // word 10 (324..355) = offset to dynamic `bytes mintSignature` = 14 * 32 = 448 (0x01c0)
  buf[354] = 0x01;
  buf[355] = 0xc0;
  // word 11 (356..387) = uint8 v
  buf[387] = v;
  // word 12 (388..419) = bytes32 r
  buf.set(r32, 388);
  // word 13 (420..451) = bytes32 s
  buf.set(s32, 420);
  // word 14 (452..483) = mintSignature.length = 65
  buf[483] = 65;
  // words 15..17 (484..579) = 65-byte mintSignature + 31 zero-pad bytes
  buf.set(mintSig65, 484);
  return buf;
}

const MULTICALL3_AGGREGATE3_SELECTOR_BYTES = keccak_256(
  stringToBytes('aggregate3((address,bool,bytes)[])'),
).subarray(0, 4);

function encodeMulticall3Aggregate3Fast(
  target20: Uint8Array,
  callDatas: readonly (Uint8Array | Hex)[],
): Hex {
  const n = callDatas.length;
  const cdBytesList: Uint8Array[] = [];
  let totalElementsBytes = 0;
  for (let i = 0; i < n; i++) {
    const entry = callDatas[i]!;
    const cd = typeof entry === 'string' ? hexToBytes(entry) : entry;
    cdBytesList.push(cd);
    const paddedLen = (cd.length + 31) & ~31;
    totalElementsBytes += 128 + paddedLen;
  }

  const totalLen = 68 + n * 32 + totalElementsBytes;
  const buf = new Uint8Array(totalLen);
  buf.set(MULTICALL3_AGGREGATE3_SELECTOR_BYTES, 0);
  // word 0 (4..35) = offset to array = 32
  buf[35] = 32;
  // word 1 (36..67) = array length = n
  writeUint256Word(buf, 36, BigInt(n));

  let cursorRel = n * 32;
  for (let i = 0; i < n; i++) {
    const cd = cdBytesList[i]!;
    const paddedLen = (cd.length + 31) & ~31;
    // head offset for element i (relative to byte 68)
    writeUint256Word(buf, 68 + i * 32, BigInt(cursorRel));
    const elemPos = 68 + cursorRel;
    writeAddressWord(buf, elemPos, target20);
    // word 1 (elemPos + 32) = allowFailure = false (0)
    // word 2 (elemPos + 64) = offset to bytes callData = 96
    buf[elemPos + 95] = 96;
    // word 3 (elemPos + 96) = callData.length
    writeUint256Word(buf, elemPos + 96, BigInt(cd.length));
    buf.set(cd, elemPos + 128);
    cursorRel += 128 + paddedLen;
  }

  return uint8ToHexFast(buf);
}

function deriveAddressFromPrivateKeyBytes(raw32: Uint8Array): Address {
  return batchDeriveAddressesMontgomery([raw32])[0]!.address;
}

export const MAX_BATCH_PAYOUT_SLIPS = 500;
export const DEFAULT_MULTICALL_CHUNK_SIZE = 250;

/**
 * Thrown when a batch payout configuration violates protocol minimums, batch bounds (`1..500`),
 * or V3.2 cancel-lock rules (`0` or `9_999_999_999`).
 */
export class BatchValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BatchValidationError';
  }
}

/**
 * Thrown when a caller attempts an execution strategy that would corrupt `slip.creator` on-chain
 * (Solidity Law #2: `CryptoSlipProtocolV32.sol` `L424, L448, L1323, L1490` `bindCreator` trap).
 */
export class CreatorBindingViolationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CreatorBindingViolationError';
  }
}

const VAULT_MINT_PERMIT_TYPES = {
  MintPermit: [
    { name: 'creator', type: 'address' },
    { name: 'token', type: 'address' },
    { name: 'amount', type: 'uint256' },
    { name: 'claimSigner', type: 'address' },
    { name: 'referrer', type: 'address' },
    { name: 'cancelLockedUntil', type: 'uint48' },
    { name: 'nonce', type: 'bytes32' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'relayer', type: 'address' },
  ],
} as const;

const EIP3009_RECEIVE_AUTH_TYPES = {
  ReceiveWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
  ],
} as const;

const ERC20_PERMIT_TYPES = {
  Permit: [
    { name: 'owner', type: 'address' },
    { name: 'spender', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
} as const;

const LEGACY_SLIP_CREATED_EVENT = parseAbiItem(
  'event SlipCreated(uint256 indexed slipId, address indexed creator, address indexed asset, uint256 amount, address claimSigner, uint48 expiresAt)',
);

export interface ViemTypedDataCompatibleSigner {
  readonly address: Address;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  signTypedData: (payload: any) => Promise<Hex>;
}

export interface EthersV6CompatibleSigner {
  getAddress: () => Promise<string> | string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  signTypedData: (domain: any, types: any, value: any) => Promise<string>;
}

export type PayoutSignerInput =
  | ViemTypedDataCompatibleSigner
  | EthersV6CompatibleSigner
  | Hex;

interface NormalizedBatchSigner {
  readonly address: Address;
  readonly rawKeyIfKnown?: Hex;
  readonly signDigest?: (digestHex: Hex) => Promise<Hex>;
  signTypedData: (params: {
    domain: {
      name: string;
      version: string;
      chainId: number;
      verifyingContract: Address;
    };
    types: Record<string, readonly { name: string; type: string }[]>;
    primaryType: string;
    message: Record<string, unknown>;
  }) => Promise<Hex>;
}

async function normalizeBatchSigner(input: PayoutSignerInput): Promise<NormalizedBatchSigner> {
  if (typeof input === 'string') {
    const pk = (input.startsWith('0x') ? input : `0x${input}`) as Hex;
    const pkBytes = hexToBytes(pk);
    const pkScalar = bytesToBigInt(pkBytes);
    if (pkBytes.length !== 32 || pkScalar <= 0n || pkScalar >= SECP256K1_ORDER) {
      throw new BatchValidationError('Invalid secp256k1 private key provided to batch dispenser.');
    }
    const addr = deriveAddressFromPrivateKeyBytes(pkBytes);
    if (addr.toLowerCase() === COMPROMISED_SIGNER_LOWER) {
      throw new BatchValidationError('Compromised signer key is permanently refused.');
    }
    let lazyAcc: ReturnType<typeof privateKeyToAccount> | null = null;
    const getAcc = () => {
      if (!lazyAcc) lazyAcc = privateKeyToAccount(pk);
      return lazyAcc;
    };
    return {
      address: addr,
      rawKeyIfKnown: pk,
      signDigest: (hash) => getAcc().sign({ hash }),
      signTypedData: (p) =>
        getAcc().signTypedData({
          domain: p.domain,
          types: p.types,
          primaryType: p.primaryType,
          message: p.message,
        }),
    };
  }

  if ('address' in input && typeof input.address === 'string' && isAddress(input.address)) {
    const addr = getAddress(input.address);
    if (addr.toLowerCase() === COMPROMISED_SIGNER_LOWER) {
      throw new BatchValidationError('Compromised signer key is permanently refused.');
    }
    const inpRecord = input as unknown as Record<string, unknown>;
    const isPolicyGuarded =
      Boolean(inpRecord.policy) || inpRecord.kind === 'policyGuarded';
    const maybeRawSign =
      !isPolicyGuarded && typeof inpRecord.sign === 'function'
        ? (inpRecord.sign.bind(input) as (p: { hash: Hex }) => Promise<Hex>)
        : undefined;

    return {
      address: addr,
      ...(maybeRawSign ? { signDigest: (hash: Hex) => maybeRawSign({ hash }) } : {}),
      signTypedData: async (p) => {
        const sig = await input.signTypedData(p);
        return sig as Hex;
      },
    };
  }

  if ('getAddress' in input && typeof input.getAddress === 'function') {
    const rawAddr = await input.getAddress();
    const addr = getAddress(rawAddr);
    if (addr.toLowerCase() === COMPROMISED_SIGNER_LOWER) {
      throw new BatchValidationError('Compromised signer key is permanently refused.');
    }
    return {
      address: addr,
      signTypedData: async (p) => {
        if (input.signTypedData.length >= 3) {
          const mutableTypes: Record<string, Array<{ name: string; type: string }>> = {};
          for (const [k, fields] of Object.entries(p.types)) {
            if (k !== 'EIP712Domain') {
              mutableTypes[k] = fields.map((f) => ({ name: f.name, type: f.type }));
            }
          }
          const sig = await input.signTypedData(p.domain, mutableTypes, p.message);
          return sig as Hex;
        }
        const sig = await (input as unknown as ViemTypedDataCompatibleSigner).signTypedData(p);
        return sig as Hex;
      },
    };
  }

  throw new BatchValidationError('Unsupported PayoutSignerInput provided to batch dispenser.');
}

function generateFreshSecp256k1Key(forbiddenLower: ReadonlySet<string>): {
  privateKey: Hex;
  address: Address;
} {
  for (let attempt = 0; attempt < 64; attempt++) {
    const raw = randomBytes(32);
    const scalar = bytesToBigInt(raw);
    if (scalar <= 0n || scalar >= SECP256K1_ORDER) continue;
    const pk = bytesToHex(raw);
    const addr = deriveAddressFromPrivateKeyBytes(raw);
    const lower = addr.toLowerCase();
    if (!forbiddenLower.has(lower) && !BLOCKED_PAYMENT_TARGETS.has(lower)) {
      return { privateKey: pk, address: addr };
    }
  }
  throw new BatchValidationError('Unable to allocate fresh non-colliding secp256k1 claim key.');
}

function splitEcdsa65Signature(sig: Hex): { v: number; r: Hex; s: Hex } | null {
  const clean = sig.startsWith('0x') ? sig.slice(2) : sig;
  if (clean.length !== 130 || !/^[0-9a-fA-F]{130}$/.test(clean)) {
    return null;
  }
  const r = `0x${clean.slice(0, 64)}` as Hex;
  const s = `0x${clean.slice(64, 128)}` as Hex;
  let v = Number.parseInt(clean.slice(128, 130), 16);
  if (v < 27) v += 27;
  if (v !== 27 && v !== 28) return null;
  return { v, r, s };
}

function parseItemAtomicUnits(
  amount: bigint | string | number,
  asset: SdkAssetSymbol,
): bigint {
  if (typeof amount === 'bigint') {
    if (amount <= 0n) throw new BatchValidationError('Slip amount must be greater than zero.');
    return amount;
  }
  const decimals = decimalsForAsset(asset);
  if (typeof amount === 'number') {
    if (!Number.isFinite(amount) || amount <= 0) {
      throw new BatchValidationError('Slip amount must be a positive finite number.');
    }
    const cleanStr =
      Number(amount.toPrecision(12))
        .toFixed(Math.min(decimals, 12))
        .replace(/\.?0+$/, '') || '0';
    return parseUnits(cleanStr, decimals);
  }
  const trimmed = String(amount).trim();
  if (!trimmed) throw new BatchValidationError('Slip amount string cannot be empty.');
  const parsed = parseUnits(trimmed, decimals);
  if (parsed <= 0n) throw new BatchValidationError('Slip amount must be greater than zero.');
  return parsed;
}

function getEip3009Domain(tokenAddress: Address, chainId: number) {
  if (tokenAddress.toLowerCase() === CBBTC_BASE_ADDRESS.toLowerCase()) {
    return {
      name: 'Coinbase Wrapped BTC',
      version: '2',
      chainId,
      verifyingContract: getAddress(CBBTC_BASE_ADDRESS),
    };
  }
  return {
    name: 'USD Coin',
    version: '2',
    chainId,
    verifyingContract: getAddress(USDC_BASE_ADDRESS),
  };
}

/**
 * Enforces Solidity Law #2 (`CryptoSlipProtocolV32.sol` `L424, L448, L1323, L1490`):
 * Rejects any batch call that routes `mintSlipETH*` or `mintSlipFor` through `Multicall3` or any
 * third-party forwarder where `msg.sender != partnerWallet` (which would set `bindCreator = false`
 * or `slip.creator = Multicall3`, breaking `0%` 1st Keep, `/api/relay/accept`, `No take-back`,
 * creator recall, and `0.25%` lifetime `referrerOf` attribution!).
 */
export function assertCreatorBindingPreserved(params: {
  txCaller: Address;
  partnerWallet: Address;
  targetContract: Address;
  vaultFunctionName:
    | 'mintSlipERC20WithAuthorization'
    | 'mintSlipERC20WithPermit'
    | 'mintSlipETHWithEscrow'
    | 'mintSlipETH'
    | 'mintSlipFor';
}): void {
  const callerLower = params.txCaller.toLowerCase();
  const partnerLower = params.partnerWallet.toLowerCase();
  const fn = params.vaultFunctionName;

  if (fn === 'mintSlipFor') {
    if (callerLower !== partnerLower) {
      throw new CreatorBindingViolationError(
        `Solidity Law #2 violation: vault.mintSlipFor called from ${params.txCaller} != partnerWallet (${params.partnerWallet}) sets bindCreator = false on CryptoSlipVaultV32 (L1323, L1490), breaking 0% 1st Keep, No take-back, and referrerOf! Use mintSlipERC20WithAuthorization / mintSlipERC20WithPermit instead.`,
      );
    }
  }

  if (fn === 'mintSlipETHWithEscrow' || fn === 'mintSlipETH') {
    if (
      callerLower !== partnerLower ||
      params.targetContract.toLowerCase() === MULTICALL3_ADDRESS.toLowerCase()
    ) {
      throw new CreatorBindingViolationError(
        `Solidity Law #2 violation: ${fn} sets slip.creator = msg.sender (CryptoSlipProtocolV32.sol:424). Calling via ${params.txCaller} (e.g. Multicall3) would record Multicall3 as slip.creator instead of ${params.partnerWallet}! Use direct EOA or Simple7702Account self-batch executeBatch.`,
      );
    }
  }
}

export interface PreallocatedClaimCredential {
  readonly claimPrivateKey: Hex;
  readonly claimSigner: Address;
}

const VERIFIED_CLAIM_CREDENTIALS = new WeakMap<
  PreallocatedClaimCredential,
  { claimPrivateKey: Hex; address: Address; addr20: Uint8Array }
>();

/**
 * Cryptographically pre-allocates `1..500` fresh `secp256k1` ephemeral claim credentials
 * in a single Montgomery batch-inversion pass, branding each `{ claimPrivateKey, claimSigner }`
 * pair in an unforgeable `WeakMap` so `prepareBatchPayoutSlips` can skip redundant key derivation
 * without ever trusting an unverified `(claimPrivateKey, claimSigner)` pair.
 */
export function generateBatchClaimCredentials(
  count: number,
  options?: { extraBlockedAddresses?: readonly string[] },
): PreallocatedClaimCredential[] {
  if (!Number.isInteger(count) || count < 1 || count > MAX_BATCH_PAYOUT_SLIPS) {
    throw new BatchValidationError(
      `generateBatchClaimCredentials count must be between 1 and ${MAX_BATCH_PAYOUT_SLIPS}.`,
    );
  }
  const forbidden = new Set<string>();
  if (options?.extraBlockedAddresses) {
    for (const a of options.extraBlockedAddresses) {
      if (a) forbidden.add(a.toLowerCase());
    }
  }

  const rawBytesList: Uint8Array[] = [];
  const hexKeys: Hex[] = [];
  const csprngPool = randomBytes(count * 32);

  for (let i = 0; i < count; i++) {
    let slice = csprngPool.subarray(i * 32, (i + 1) * 32);
    let scalar = bytesToBigInt(slice);
    while (scalar <= 0n || scalar >= SECP256K1_ORDER) {
      slice = randomBytes(32);
      scalar = bytesToBigInt(slice);
    }
    const copy = new Uint8Array(slice);
    rawBytesList.push(copy);
    hexKeys.push(uint8ToHexFast(copy));
  }

  const derived = batchDeriveAddressesMontgomery(rawBytesList);
  const out: PreallocatedClaimCredential[] = [];

  for (let i = 0; i < count; i++) {
    let entry = derived[i]!;
    let pkHex = hexKeys[i]!;
    let lower = entry.address.toLowerCase();
    while (forbidden.has(lower) || BLOCKED_PAYMENT_TARGETS.has(lower)) {
      const fallback = generateFreshSecp256k1Key(forbidden);
      pkHex = fallback.privateKey;
      entry = { address: fallback.address, addr20: hexToBytes(fallback.address) };
      lower = entry.address.toLowerCase();
    }
    forbidden.add(lower);
    const cred: PreallocatedClaimCredential = Object.freeze({
      claimPrivateKey: pkHex,
      claimSigner: entry.address,
    });
    VERIFIED_CLAIM_CREDENTIALS.set(cred, {
      claimPrivateKey: pkHex,
      address: entry.address,
      addr20: entry.addr20,
    });
    out.push(cred);
  }

  // Also pre-warm 2 * count single-use FIPS 186-5 ECDSA coupons for the paired MintPermit + EIP-3009/2612 signatures
  warmBatchSigningPool(count * 2);

  return out;
}

export type EthBatchExecutionMode = 'direct_eoa' | 'eip7702_self_batch' | 'multicall3';

export interface PayoutSlipItemInput {
  /**
   * Amount to fund:
   * - Pass `bigint` for exact atomic token units (e.g. `1_000_000n` = `1.00 USDC`, `100n` = `100 sats`).
   * - Pass `number` or decimal `string` for human units (e.g. `25` or `'25.50'`).
   */
  amount: bigint | string | number;
  asset: AnyAssetSymbol;
  /** Permanent V3.2 `No take-back` (`cancelLockedUntil = 9_999_999_999`). Auto-enabled for `mode: 'code'` unless explicitly `false`. */
  noTakeBack?: boolean;
  /** Explicit V3.2 lock timestamp (`0n` or `9_999_999_999n` only). */
  cancelLockedUntil?: bigint | number;
  /** When `true`, grosses up `amount` so `gross - ceilFee(gross) >= targetNet` on a `0.50%` wallet claim. */
  grossUpForExitFee?: boolean;
  /** `'open'` (`#` bearer claim key) or `'code'` (12-char `scrypt` code + `_z<32hex>` salt). Defaults to `'open'`. */
  mode?: SlipLinkMode;
  /** Optional merchant/partner display label sanitized for receipt/export metadata. */
  merchantLabel?: string;
  /** Optional Green-Zone recipient memo (`<= 36` chars, embedded only inside `#` fragment). */
  note?: string;
  /** Optional upstream referrer address passed into `MintPermit` / `mintSlipETHWithEscrow`. */
  referrer?: Address;
  /** Optional caller-supplied correlation ID (e.g. user ID, bounty ID, market ID) preserved through receipt parsing. */
  recipientRef?: string;
  /** Optional pre-verified `{ claimPrivateKey, claimSigner }` credential from `generateBatchClaimCredentials()`. */
  credential?: PreallocatedClaimCredential;
  /** Optional pre-generated ephemeral claim private key (`0x` + 64 hex) for deterministic recovery. */
  claimPrivateKey?: Hex;
  /** Optional pre-generated 12-char `scrypt` claim code (when `mode === 'code'`). */
  claimCode?: string;
  /** Optional pre-generated 32-hex code salt (when `mode === 'code'`). */
  codeSalt?: string;
  /** Optional explicit 32-byte EIP-3009 / `MintPermit` nonce (`0x` + 64 hex). */
  permitNonce?: Hex;
}

export interface PreparedPayoutSlip {
  readonly index: number;
  readonly asset: SdkAssetSymbol;
  readonly tokenAddress: Address;
  readonly requestedAmountUnits: bigint;
  readonly grossAmountUnits: bigint;
  readonly expectedExitFeeUnits: bigint;
  readonly guaranteedNetClaimUnits: bigint;
  readonly humanAmount: number;
  readonly vault: VaultTag;
  readonly vaultAddress: Address;
  readonly creator: Address;
  readonly mode: SlipLinkMode;
  readonly cancelLockedUntil: bigint;
  readonly claimSigner: Address;
  /** Present for `mode === 'open'` (never log or transmit outside `#` fragment). */
  readonly claimPrivateKey?: Hex;
  /** Formatted `XXXX-XXXX-XXXX` 12-char code when `mode === 'code'`. */
  readonly claimCode?: string;
  /** 32-hex salt when `mode === 'code'`. */
  readonly codeSalt?: string;
  readonly permitNonce?: Hex;
  readonly validAfter: bigint;
  readonly validBefore: bigint;
  readonly vaultCallData: Hex;
  readonly vaultValue: bigint;
  readonly vaultFunctionName:
    | 'mintSlipERC20WithAuthorization'
    | 'mintSlipERC20WithPermit'
    | 'mintSlipETHWithEscrow';
  readonly merchantLabel?: string;
  readonly note?: string;
  readonly recipientRef?: string;
}

export type BatchTransactionStrategy =
  | 'multicall3_erc20'
  | 'simple7702_eth_self_batch'
  | 'direct_eoa_eth';

export interface PreparedBatchTransaction {
  readonly to: Address;
  readonly value: bigint;
  readonly data: Hex;
  readonly strategy: BatchTransactionStrategy;
  readonly slipIndices: readonly number[];
  readonly totalUsdcUnits: bigint;
}

export interface PrepareBatchPayoutOptions {
  signer: PayoutSignerInput;
  items: readonly PayoutSlipItemInput[];
  vault?: VaultTag;
  chainId?: number;
  /** Chain timestamp in seconds (defaults to `Math.floor(Date.now() / 1000)` if omitted). */
  chainTimestampSec?: number | bigint;
  /** Permit validity window in seconds (defaults to `3600` = 1 hour). */
  ttlSeconds?: number;
  /** Maximum ERC-20 slip mints packed into a single `Multicall3.aggregate3` tx (`1..500`, defaults to `250`). */
  maxSlipsPerTx?: number;
  /** Required when batch contains `NARA` items unless `publicClient` is supplied to read `NARA.nonces(creator)`. */
  naraStartingNonce?: bigint;
  /** Optional `PublicClient` to auto-fetch `latest` block timestamp and `NARA.nonces(creator)`. */
  publicClient?: BaseCompatiblePublicClient;
  /**
   * Execution strategy for native `ETH` slips:
   * - `'direct_eoa'`: 1 direct `vault.mintSlipETHWithEscrow` tx per ETH slip (`msg.sender == partnerWallet`).
   * - `'eip7702_self_batch'`: packs multiple ETH slips into 1 `Simple7702Account.executeBatch` self-call (`to: partnerWallet`, `msg.sender == partnerWallet` inside vault!).
   * - `'multicall3'`: FORBIDDEN — throws `CreatorBindingViolationError` (Solidity Law #2).
   */
  ethExecutionMode?: EthBatchExecutionMode;
  /** Builder code attribution override (defaults to `'bc_ea68lz8s'`, plus `'bc_g71jff6u'` when NARA is included). */
  builderCodes?: string | readonly string[];
}

export interface PreparedBatchPayout {
  readonly vault: VaultTag;
  readonly vaultAddress: Address;
  readonly creator: Address;
  readonly slips: readonly PreparedPayoutSlip[];
  readonly transactions: readonly PreparedBatchTransaction[];
  readonly totalsByAsset: Readonly<Record<SdkAssetSymbol, bigint>>;
}

function resolveCancelLock(item: PayoutSlipItemInput): bigint {
  if (item.cancelLockedUntil !== undefined) {
    const lock = BigInt(item.cancelLockedUntil);
    if (lock !== 0n && lock !== NO_TAKE_BACK_LOCK) {
      throw new BatchValidationError(
        `Invalid cancelLockedUntil (${lock.toString()}): V3.2 strictly permits 0n or ${NO_TAKE_BACK_LOCK.toString()}.`,
      );
    }
    return lock;
  }
  const mode = item.mode ?? 'open';
  const effectiveNoTakeBack =
    item.noTakeBack !== undefined ? item.noTakeBack : mode === 'code';
  return effectiveNoTakeBack ? NO_TAKE_BACK_LOCK : 0n;
}

function generateDeterministicOrRandomNonceBytes(
  creator20: Uint8Array,
  vault20: Uint8Array,
  token20: Uint8Array,
  amount: bigint,
  claimSigner20: Uint8Array,
  index: number,
  entropyBytes: Uint8Array,
): Uint8Array {
  const buf = new Uint8Array(160);
  buf.set(BATCH_NONCE_TAG_BYTES, 0);
  buf.set(creator20, 32);
  buf.set(vault20, 52);
  buf.set(token20, 72);
  writeUint256Word(buf, 92, amount);
  buf.set(claimSigner20, 124);
  buf.set(entropyBytes.subarray(index * 16, (index + 1) * 16), 144);
  return keccak_256(buf);
}

/**
 * Prepares a single payout slip (`MintPermit` + EIP-3009 / EIP-2612 or direct native `ETH`) offline.
 */
export async function preparePayoutSlip(
  options: Omit<PrepareBatchPayoutOptions, 'items'> & { item: PayoutSlipItemInput },
): Promise<{ slip: PreparedPayoutSlip; transaction: PreparedBatchTransaction }> {
  const batch = await prepareBatchPayoutSlips({
    ...options,
    items: [options.item],
  });
  return {
    slip: batch.slips[0]!,
    transaction: batch.transactions[0]!,
  };
}

/**
 * Prepares `1..500` partner payout slips with offline EIP-3009 / EIP-2612 / EIP-712 signing
 * and packs ERC-20 slips into `Multicall3.aggregate3` (`0xcA11bde05977b3631167028862bE2a173976CA11`)
 * with `ERC-8021` Base Builder Code attribution (`bc_ea68lz8s`), strictly preserving
 * `slips[id].creator === partnerWallet` (`bindCreator = true`) across all 4 assets!
 */
export async function prepareBatchPayoutSlips(
  options: PrepareBatchPayoutOptions,
): Promise<PreparedBatchPayout> {
  const { items, vault = ISSUE_VAULT, chainId = BASE_CHAIN_ID, ttlSeconds = 3_600 } = options;

  if (!Array.isArray(items) || items.length === 0) {
    throw new BatchValidationError('Batch payout requires at least 1 slip item.');
  }
  if (items.length > MAX_BATCH_PAYOUT_SLIPS) {
    throw new BatchValidationError(
      `Batch payout exceeds maximum of ${MAX_BATCH_PAYOUT_SLIPS} slips per batch (got ${items.length}).`,
    );
  }
  if (!isV32ProtocolVault(vault)) {
    throw new BatchValidationError(
      `Partner batch dispenser requires a V3.2 vault ('v33' or 'v32'); got '${vault}'.`,
    );
  }
  const chunkSize = options.maxSlipsPerTx ?? DEFAULT_MULTICALL_CHUNK_SIZE;
  if (!Number.isInteger(chunkSize) || chunkSize < 1 || chunkSize > MAX_BATCH_PAYOUT_SLIPS) {
    throw new BatchValidationError(
      `maxSlipsPerTx must be an integer between 1 and ${MAX_BATCH_PAYOUT_SLIPS}.`,
    );
  }

  const signer = await normalizeBatchSigner(options.signer);
  const creator = signer.address;
  const vAddr = vaultAddress(vault);

  const hasEthItems = items.some((it) => normalizeSdkAsset(it.asset) === 'ETH');
  if (hasEthItems && options.ethExecutionMode === 'multicall3') {
    assertCreatorBindingPreserved({
      txCaller: MULTICALL3_ADDRESS,
      partnerWallet: creator,
      targetContract: MULTICALL3_ADDRESS,
      vaultFunctionName: 'mintSlipETHWithEscrow',
    });
  }

  let baseNowSec: bigint;
  if (options.chainTimestampSec !== undefined) {
    baseNowSec = BigInt(options.chainTimestampSec);
  } else if (options.publicClient) {
    const block = await options.publicClient.getBlock({ blockTag: 'latest' });
    const wallSec = BigInt(Math.floor(Date.now() / 1000));
    baseNowSec = block.timestamp > wallSec ? block.timestamp : wallSec;
  } else {
    baseNowSec = BigInt(Math.floor(Date.now() / 1000));
  }
  if (ttlSeconds < 120) {
    throw new BatchValidationError('Permit ttlSeconds must be at least 120 seconds.');
  }
  const validAfter = 0n;
  const validBefore = baseNowSec + BigInt(ttlSeconds);

  const hasNaraItems = items.some((it) => normalizeSdkAsset(it.asset) === 'NARA');
  let nextNaraNonce = options.naraStartingNonce;
  if (hasNaraItems && nextNaraNonce === undefined) {
    if (!options.publicClient) {
      throw new BatchValidationError(
        'NARA batch minting requires either naraStartingNonce or publicClient to read NARA.nonces(creator).',
      );
    }
    nextNaraNonce = await options.publicClient.readContract({
      address: NARA_BASE_ADDRESS,
      abi: ERC20_PERMIT_EIP3009_ABI,
      functionName: 'nonces',
      args: [creator],
    });
  }

  const usedClaimSigners = new Set<string>([creator.toLowerCase()]);
  const batchEntropy = randomBytes(items.length * 16);

  const vaultDomain = {
    name: 'Crypto Slip Protocol',
    version: '3',
    chainId,
    verifyingContract: vAddr,
  } as const;

  const naraDomain = {
    name: 'NARA Token',
    version: '1',
    chainId,
    verifyingContract: NARA_BASE_ADDRESS,
  } as const;

  const creator20 = hexToBytes(creator);
  const vault20 = hexToBytes(vAddr);
  const vaultDomainSepBytes = computeDomainSeparatorBytes(vaultDomain);
  const usdcDomainSepBytes = computeDomainSeparatorBytes(getEip3009Domain(USDC_BASE_ADDRESS, chainId));
  const cbbtcDomainSepBytes = computeDomainSeparatorBytes(
    getEip3009Domain(CBBTC_BASE_ADDRESS, chainId),
  );
  const naraDomainSepBytes = hasNaraItems ? computeDomainSeparatorBytes(naraDomain) : null;

  const totalsByAsset: Record<SdkAssetSymbol, bigint> = {
    USDC: 0n,
    cbBTC: 0n,
    ETH: 0n,
    NARA: 0n,
  };

  // Pre-allocate sequential NARA nonces in deterministic item order before concurrent signing
  const itemNaraNonces = new Map<number, bigint>();
  if (hasNaraItems && nextNaraNonce !== undefined) {
    let cursor = nextNaraNonce;
    for (let i = 0; i < items.length; i++) {
      const it = items[i]!;
      if (normalizeSdkAsset(it.asset) === 'NARA') {
        itemNaraNonces.set(i, cursor);
        cursor += 1n;
      }
    }
  }

  // Pre-allocate credentials sequentially to guarantee zero claimSigner collisions across the batch
  const preallocatedCreds: Array<{
    asset: SdkAssetSymbol;
    tokenAddr: Address;
    token20: Uint8Array;
    requestedUnits: bigint;
    grossUnits: bigint;
    exitFeeUnits: bigint;
    netClaimUnits: bigint;
    humanAmount: number;
    mode: SlipLinkMode;
    cancelLockedUntil: bigint;
    claimSigner: Address;
    claimSigner20: Uint8Array;
    claimPrivateKey?: Hex;
    claimCode?: string;
    codeSalt?: string;
    referrer: Address;
    referrer20: Uint8Array;
    cleanNote?: string;
    merchantLabel?: string;
  }> = [];

  // Pre-derive all open-mode claimPrivateKey addresses (and missing random keys) in ONE Montgomery batch pass!
  const prederivedByIndex = new Map<
    number,
    { claimPrivateKey: Hex; address: Address; addr20: Uint8Array }
  >();
  const batchOpenKeyIndices: number[] = [];
  const batchOpenKeyBytes: Uint8Array[] = [];
  const batchOpenKeyHex: Hex[] = [];

  for (let i = 0; i < items.length; i++) {
    const item = items[i]!;
    const mode: SlipLinkMode = item.mode ?? 'open';
    if (mode !== 'code') {
      if (item.credential) {
        const verified = VERIFIED_CLAIM_CREDENTIALS.get(item.credential);
        if (verified) {
          prederivedByIndex.set(i, verified);
          continue;
        }
        const pk = item.credential.claimPrivateKey;
        const rawPkBytes = hexToBytes(pk);
        const scalar = bytesToBigInt(rawPkBytes);
        if (rawPkBytes.length !== 32 || scalar <= 0n || scalar >= SECP256K1_ORDER) {
          throw new BatchValidationError(`Item #${i}: invalid secp256k1 credential key.`);
        }
        batchOpenKeyIndices.push(i);
        batchOpenKeyBytes.push(rawPkBytes);
        batchOpenKeyHex.push(pk);
      } else if (item.claimPrivateKey) {
        const pk = (
          item.claimPrivateKey.startsWith('0x')
            ? item.claimPrivateKey
            : `0x${item.claimPrivateKey}`
        ) as Hex;
        const rawPkBytes = hexToBytes(pk);
        const scalar = bytesToBigInt(rawPkBytes);
        if (rawPkBytes.length !== 32 || scalar <= 0n || scalar >= SECP256K1_ORDER) {
          throw new BatchValidationError(`Item #${i}: invalid secp256k1 claimPrivateKey.`);
        }
        batchOpenKeyIndices.push(i);
        batchOpenKeyBytes.push(rawPkBytes);
        batchOpenKeyHex.push(pk);
      } else {
        for (let attempt = 0; ; attempt++) {
          if (attempt >= 64) {
            throw new BatchValidationError('Unable to generate valid secp256k1 random scalar.');
          }
          const raw = randomBytes(32);
          const scalar = bytesToBigInt(raw);
          if (scalar > 0n && scalar < SECP256K1_ORDER) {
            batchOpenKeyIndices.push(i);
            batchOpenKeyBytes.push(raw);
            batchOpenKeyHex.push(uint8ToHexFast(raw));
            break;
          }
        }
      }
    }
  }

  const batchDerivedOpenAddrs =
    batchOpenKeyBytes.length > 0 ? batchDeriveAddressesMontgomery(batchOpenKeyBytes) : [];
  for (let k = 0; k < batchOpenKeyIndices.length; k++) {
    const derived = batchDerivedOpenAddrs[k]!;
    prederivedByIndex.set(batchOpenKeyIndices[k]!, {
      claimPrivateKey: batchOpenKeyHex[k]!,
      address: derived.address,
      addr20: derived.addr20,
    });
  }

  for (let i = 0; i < items.length; i++) {
    const item = items[i]!;
    const sdkAsset = normalizeSdkAsset(item.asset);
    const tokenAddr = assetAddress(sdkAsset);
    const token20 =
      sdkAsset === 'USDC'
        ? USDC_BYTES_20
        : sdkAsset === 'cbBTC'
          ? CBBTC_BYTES_20
          : sdkAsset === 'NARA'
            ? NARA_BYTES_20
            : ZERO_BYTES_20;
    const requestedUnits = parseItemAtomicUnits(item.amount, sdkAsset);
    const grossUnits = item.grossUpForExitFee
      ? grossUpForExactNet(requestedUnits)
      : requestedUnits;
    const minRequired = minSlipAmount(sdkAsset, vault);
    if (grossUnits < minRequired) {
      throw new BatchValidationError(
        `Item #${i} (${grossUnits.toString()} raw ${sdkAsset}) is below ${vault} minimum (${minRequired.toString()}).`,
      );
    }

    const exitFeeUnits = computeProtocolFeeCeiling(grossUnits);
    const netClaimUnits = grossUnits - exitFeeUnits;
    const decimals = decimalsForAsset(sdkAsset);
    const humanAmount =
      decimals <= 8 && grossUnits <= 9_007_199_254_740_991n
        ? Number(grossUnits) / 10 ** decimals
        : Number(formatUnits(grossUnits, decimals));

    const mode: SlipLinkMode = item.mode ?? 'open';
    const cancelLockedUntil = resolveCancelLock(item);

    let claimSigner: Address;
    let claimSigner20: Uint8Array;
    let claimPrivateKey: Hex | undefined;
    let claimCode: string | undefined;
    let codeSalt: string | undefined;

    if (mode === 'code') {
      const rawCode = item.claimCode ?? generateClaimCode();
      const resolvedCode = formatClaimCode(rawCode);
      const resolvedSalt = String(item.codeSalt ?? generateCodeSalt()).toLowerCase();
      claimCode = resolvedCode;
      codeSalt = resolvedSalt;
      const derived = await deriveCodeWallet(resolvedCode, resolvedSalt);
      claimSigner = getAddress(derived.address);
      claimSigner20 = hexToBytes(claimSigner);
    } else if (prederivedByIndex.has(i)) {
      const pre = prederivedByIndex.get(i)!;
      if (
        !item.claimPrivateKey &&
        (usedClaimSigners.has(pre.address.toLowerCase()) ||
          BLOCKED_PAYMENT_TARGETS.has(pre.address.toLowerCase()))
      ) {
        const generated = generateFreshSecp256k1Key(usedClaimSigners);
        claimPrivateKey = generated.privateKey;
        claimSigner = generated.address;
        claimSigner20 = hexToBytes(claimSigner);
      } else {
        claimPrivateKey = pre.claimPrivateKey;
        claimSigner = pre.address;
        claimSigner20 = pre.addr20;
      }
    } else {
      const generated = generateFreshSecp256k1Key(usedClaimSigners);
      claimPrivateKey = generated.privateKey;
      claimSigner = generated.address;
      claimSigner20 = hexToBytes(claimSigner);
    }

    const claimLower = claimSigner.toLowerCase();
    if (claimLower === creator.toLowerCase()) {
      throw new BatchValidationError(
        `Item #${i}: claimSigner (${claimSigner}) must not equal creator (${creator}).`,
      );
    }
    if (BLOCKED_PAYMENT_TARGETS.has(claimLower)) {
      throw new BatchValidationError(
        `Item #${i}: claimSigner (${claimSigner}) is a blocked address.`,
      );
    }
    if (usedClaimSigners.has(claimLower)) {
      throw new BatchValidationError(
        `Item #${i}: duplicate claimSigner (${claimSigner}) in batch payout.`,
      );
    }
    usedClaimSigners.add(claimLower);

    const referrer = item.referrer ? getAddress(item.referrer) : ZERO_ADDRESS;
    const referrer20 = item.referrer ? hexToBytes(referrer) : ZERO_BYTES_20;
    const cleanNote = sanitizeSlipNote(item.note) || undefined;
    const merchantLabel = item.merchantLabel?.trim().slice(0, 40) || undefined;

    totalsByAsset[sdkAsset] += grossUnits;

    preallocatedCreds.push({
      asset: sdkAsset,
      tokenAddr,
      token20,
      requestedUnits,
      grossUnits,
      exitFeeUnits,
      netClaimUnits,
      humanAmount,
      mode,
      cancelLockedUntil,
      claimSigner,
      claimSigner20,
      ...(claimPrivateKey ? { claimPrivateKey } : {}),
      ...(claimCode ? { claimCode } : {}),
      ...(codeSalt ? { codeSalt } : {}),
      referrer,
      referrer20,
      ...(cleanNote ? { cleanNote } : {}),
      ...(merchantLabel ? { merchantLabel } : {}),
    });
  }

  // Precompute ERC-20 EIP-712 digests & nonces so raw-key batch signing runs in 1 Montgomery pass (<50ms for 50 slips!)
  const erc20PreparedMeta: Array<{
    nonce32: Uint8Array;
    nonceHex: Hex;
    mintDigest32: Uint8Array;
    authDigest32: Uint8Array;
    batchSigOffset: number;
  } | null> = Array.from({ length: preallocatedCreds.length }, () => null);

  const montgomeryDigests: Uint8Array[] = [];

  if (signer.rawKeyIfKnown || signer.signDigest) {
    for (let i = 0; i < preallocatedCreds.length; i++) {
      const cred = preallocatedCreds[i]!;
      if (cred.asset === 'ETH') continue;
      const item = items[i]!;
      const nonce32 = item.permitNonce
        ? hexToBytes(item.permitNonce)
        : generateDeterministicOrRandomNonceBytes(
            creator20,
            vault20,
            cred.token20,
            cred.grossUnits,
            cred.claimSigner20,
            i,
            batchEntropy,
          );
      const nonceHex: Hex = item.permitNonce ?? uint8ToHexFast(nonce32);
      const mintDigest32 = computeMintPermitDigestBytes(
        vaultDomainSepBytes,
        creator20,
        cred.token20,
        cred.grossUnits,
        cred.claimSigner20,
        cred.referrer20,
        cred.cancelLockedUntil,
        nonce32,
        validAfter,
        validBefore,
      );
      const authDigest32 =
        cred.asset === 'NARA'
          ? computeErc20PermitDigestBytes(
              naraDomainSepBytes!,
              creator20,
              vault20,
              cred.grossUnits,
              itemNaraNonces.get(i)!,
              validBefore,
            )
          : computeEip3009ReceiveDigestBytes(
              cred.asset === 'cbBTC' ? cbbtcDomainSepBytes : usdcDomainSepBytes,
              creator20,
              vault20,
              cred.grossUnits,
              validAfter,
              validBefore,
              nonce32,
            );
      const batchSigOffset = montgomeryDigests.length;
      if (signer.rawKeyIfKnown) {
        montgomeryDigests.push(mintDigest32, authDigest32);
      }
      erc20PreparedMeta[i] = {
        nonce32,
        nonceHex,
        mintDigest32,
        authDigest32,
        batchSigOffset,
      };
    }
  }

  const montgomerySigs =
    signer.rawKeyIfKnown && montgomeryDigests.length > 0
      ? batchSignDigestsMontgomery(montgomeryDigests, hexToBytes(signer.rawKeyIfKnown))
      : null;

  const vaultCallDataBytesByIndex = new Map<number, Uint8Array>();

  // Synchronous zero-Promise fast path when all slips are USDC/cbBTC signed via Montgomery batch pass
  let preparedSlips: PreparedPayoutSlip[];
  if (montgomerySigs && !hasEthItems && !hasNaraItems) {
    preparedSlips = [];
    for (let i = 0; i < preallocatedCreds.length; i++) {
      const cred = preallocatedCreds[i]!;
      const item = items[i]!;
      const fastMeta = erc20PreparedMeta[i]!;
      const mintFast = montgomerySigs[fastMeta.batchSigOffset]!;
      const recvFast = montgomerySigs[fastMeta.batchSigOffset + 1]!;
      const callDataBytes = encodeMintSlipWithAuthVrsFastBytes(
        creator20,
        cred.token20,
        cred.grossUnits,
        cred.claimSigner20,
        cred.referrer20,
        cred.cancelLockedUntil,
        fastMeta.nonce32,
        validAfter,
        validBefore,
        mintFast.sigBytes65,
        recvFast.v,
        recvFast.rBytes,
        recvFast.sBytes,
      );
      vaultCallDataBytesByIndex.set(i, callDataBytes);
      preparedSlips.push({
        index: i,
        asset: cred.asset,
        tokenAddress: cred.tokenAddr,
        requestedAmountUnits: cred.requestedUnits,
        grossAmountUnits: cred.grossUnits,
        expectedExitFeeUnits: cred.exitFeeUnits,
        guaranteedNetClaimUnits: cred.netClaimUnits,
        humanAmount: cred.humanAmount,
        vault,
        vaultAddress: vAddr,
        creator,
        mode: cred.mode,
        cancelLockedUntil: cred.cancelLockedUntil,
        claimSigner: cred.claimSigner,
        ...(cred.claimPrivateKey ? { claimPrivateKey: cred.claimPrivateKey } : {}),
        ...(cred.claimCode ? { claimCode: cred.claimCode } : {}),
        ...(cred.codeSalt ? { codeSalt: cred.codeSalt } : {}),
        permitNonce: fastMeta.nonceHex,
        validAfter,
        validBefore,
        vaultCallData: uint8ToHexFast(callDataBytes),
        vaultValue: 0n,
        vaultFunctionName: 'mintSlipERC20WithAuthorization',
        ...(cred.merchantLabel ? { merchantLabel: cred.merchantLabel } : {}),
        ...(cred.cleanNote ? { note: cred.cleanNote } : {}),
        ...(item.recipientRef ? { recipientRef: item.recipientRef } : {}),
      });
    }
  } else {
    preparedSlips = await Promise.all(
      preallocatedCreds.map(async (cred, i): Promise<PreparedPayoutSlip> => {
        const item = items[i]!;

        if (cred.asset === 'ETH') {
          const vaultCallData = encodeFunctionData({
            abi: CRYPTO_SLIP_VAULT_V32_ABI,
            functionName: 'mintSlipETHWithEscrow',
            args: [cred.claimSigner, 0n, cred.referrer, Number(cred.cancelLockedUntil)],
          });
          return {
            index: i,
            asset: cred.asset,
            tokenAddress: cred.tokenAddr,
            requestedAmountUnits: cred.requestedUnits,
            grossAmountUnits: cred.grossUnits,
            expectedExitFeeUnits: cred.exitFeeUnits,
            guaranteedNetClaimUnits: cred.netClaimUnits,
            humanAmount: cred.humanAmount,
            vault,
            vaultAddress: vAddr,
            creator,
            mode: cred.mode,
            cancelLockedUntil: cred.cancelLockedUntil,
            claimSigner: cred.claimSigner,
            ...(cred.claimPrivateKey ? { claimPrivateKey: cred.claimPrivateKey } : {}),
            ...(cred.claimCode ? { claimCode: cred.claimCode } : {}),
            ...(cred.codeSalt ? { codeSalt: cred.codeSalt } : {}),
            validAfter,
            validBefore,
            vaultCallData,
            vaultValue: cred.grossUnits,
            vaultFunctionName: 'mintSlipETHWithEscrow',
            ...(cred.merchantLabel ? { merchantLabel: cred.merchantLabel } : {}),
            ...(cred.cleanNote ? { note: cred.cleanNote } : {}),
            ...(item.recipientRef ? { recipientRef: item.recipientRef } : {}),
          };
        }

        const fastMeta = erc20PreparedMeta[i];
        const nonce32 = fastMeta
          ? fastMeta.nonce32
          : item.permitNonce
            ? hexToBytes(item.permitNonce)
            : generateDeterministicOrRandomNonceBytes(
                creator20,
                vault20,
                cred.token20,
                cred.grossUnits,
                cred.claimSigner20,
                i,
                batchEntropy,
              );
        const nonce: Hex = fastMeta
          ? fastMeta.nonceHex
          : (item.permitNonce ?? uint8ToHexFast(nonce32));

        const mintPermitStruct = {
          creator,
          token: cred.tokenAddr,
          amount: cred.grossUnits,
          claimSigner: cred.claimSigner,
          referrer: cred.referrer,
          cancelLockedUntil: Number(cred.cancelLockedUntil),
          nonce,
          validAfter,
          validBefore,
          relayer: ZERO_ADDRESS,
        } as const;

        if (cred.asset === 'NARA') {
          const tokenNonce = itemNaraNonces.get(i)!;
          let mintSignature: Hex;
          let permitSig: Hex;
          if (montgomerySigs && fastMeta) {
            mintSignature = uint8ToHexFast(montgomerySigs[fastMeta.batchSigOffset]!.sigBytes65);
            permitSig = uint8ToHexFast(montgomerySigs[fastMeta.batchSigOffset + 1]!.sigBytes65);
          } else if (signer.signDigest && fastMeta) {
            [mintSignature, permitSig] = await Promise.all([
              signer.signDigest(uint8ToHexFast(fastMeta.mintDigest32)),
              signer.signDigest(uint8ToHexFast(fastMeta.authDigest32)),
            ]);
          } else {
            [mintSignature, permitSig] = await Promise.all([
              signer.signTypedData({
                domain: vaultDomain,
                types: VAULT_MINT_PERMIT_TYPES,
                primaryType: 'MintPermit',
                message: mintPermitStruct as unknown as Record<string, unknown>,
              }),
              signer.signTypedData({
                domain: naraDomain,
                types: ERC20_PERMIT_TYPES,
                primaryType: 'Permit',
                message: {
                  owner: creator,
                  spender: vAddr,
                  value: cred.grossUnits,
                  nonce: tokenNonce,
                  deadline: validBefore,
                },
              }),
            ]);
          }

          const split = splitEcdsa65Signature(permitSig);
          if (!split) {
            throw new BatchValidationError(
              `Item #${i}: NARA EIP-2612 permit requires a standard 65-byte ECDSA (v,r,s) signature.`,
            );
          }

          const vaultCallData = encodeFunctionData({
            abi: CRYPTO_SLIP_VAULT_V32_ABI,
            functionName: 'mintSlipERC20WithPermit',
            args: [mintPermitStruct, mintSignature, validBefore, split.v, split.r, split.s],
          });

          return {
            index: i,
            asset: cred.asset,
            tokenAddress: cred.tokenAddr,
            requestedAmountUnits: cred.requestedUnits,
            grossAmountUnits: cred.grossUnits,
            expectedExitFeeUnits: cred.exitFeeUnits,
            guaranteedNetClaimUnits: cred.netClaimUnits,
            humanAmount: cred.humanAmount,
            vault,
            vaultAddress: vAddr,
            creator,
            mode: cred.mode,
            cancelLockedUntil: cred.cancelLockedUntil,
            claimSigner: cred.claimSigner,
            ...(cred.claimPrivateKey ? { claimPrivateKey: cred.claimPrivateKey } : {}),
            ...(cred.claimCode ? { claimCode: cred.claimCode } : {}),
            ...(cred.codeSalt ? { codeSalt: cred.codeSalt } : {}),
            permitNonce: nonce,
            validAfter,
            validBefore,
            vaultCallData,
            vaultValue: 0n,
            vaultFunctionName: 'mintSlipERC20WithPermit',
            ...(cred.merchantLabel ? { merchantLabel: cred.merchantLabel } : {}),
            ...(cred.cleanNote ? { note: cred.cleanNote } : {}),
            ...(item.recipientRef ? { recipientRef: item.recipientRef } : {}),
          };
        }

        // USDC or cbBTC via EIP-3009 ReceiveWithAuthorization + MintPermit
        if (montgomerySigs && fastMeta) {
          const mintFast = montgomerySigs[fastMeta.batchSigOffset]!;
          const recvFast = montgomerySigs[fastMeta.batchSigOffset + 1]!;
          const callDataBytes = encodeMintSlipWithAuthVrsFastBytes(
            creator20,
            cred.token20,
            cred.grossUnits,
            cred.claimSigner20,
            cred.referrer20,
            cred.cancelLockedUntil,
            nonce32,
            validAfter,
            validBefore,
            mintFast.sigBytes65,
            recvFast.v,
            recvFast.rBytes,
            recvFast.sBytes,
          );
          vaultCallDataBytesByIndex.set(i, callDataBytes);
          return {
            index: i,
            asset: cred.asset,
            tokenAddress: cred.tokenAddr,
            requestedAmountUnits: cred.requestedUnits,
            grossAmountUnits: cred.grossUnits,
            expectedExitFeeUnits: cred.exitFeeUnits,
            guaranteedNetClaimUnits: cred.netClaimUnits,
            humanAmount: cred.humanAmount,
            vault,
            vaultAddress: vAddr,
            creator,
            mode: cred.mode,
            cancelLockedUntil: cred.cancelLockedUntil,
            claimSigner: cred.claimSigner,
            ...(cred.claimPrivateKey ? { claimPrivateKey: cred.claimPrivateKey } : {}),
            ...(cred.claimCode ? { claimCode: cred.claimCode } : {}),
            ...(cred.codeSalt ? { codeSalt: cred.codeSalt } : {}),
            permitNonce: nonce,
            validAfter,
            validBefore,
            vaultCallData: uint8ToHexFast(callDataBytes),
            vaultValue: 0n,
            vaultFunctionName: 'mintSlipERC20WithAuthorization',
            ...(cred.merchantLabel ? { merchantLabel: cred.merchantLabel } : {}),
            ...(cred.cleanNote ? { note: cred.cleanNote } : {}),
            ...(item.recipientRef ? { recipientRef: item.recipientRef } : {}),
          };
        }

        const [mintSignature, receiveSignature] =
          signer.signDigest && fastMeta
            ? await Promise.all([
                signer.signDigest(uint8ToHexFast(fastMeta.mintDigest32)),
                signer.signDigest(uint8ToHexFast(fastMeta.authDigest32)),
              ])
            : await Promise.all([
                signer.signTypedData({
                  domain: vaultDomain,
                  types: VAULT_MINT_PERMIT_TYPES,
                  primaryType: 'MintPermit',
                  message: mintPermitStruct as unknown as Record<string, unknown>,
                }),
                signer.signTypedData({
                  domain: getEip3009Domain(cred.tokenAddr, chainId),
                  types: EIP3009_RECEIVE_AUTH_TYPES,
                  primaryType: 'ReceiveWithAuthorization',
                  message: {
                    from: creator,
                    to: vAddr,
                    value: cred.grossUnits,
                    validAfter,
                    validBefore,
                    nonce,
                  },
                }),
              ]);

        const split = splitEcdsa65Signature(receiveSignature);
        const mintSigBytes = hexToBytes(mintSignature);
        let vaultCallData: Hex;
        if (split && mintSigBytes.length === 65) {
          const cdBytes = encodeMintSlipWithAuthVrsFastBytes(
            creator20,
            cred.token20,
            cred.grossUnits,
            cred.claimSigner20,
            cred.referrer20,
            cred.cancelLockedUntil,
            nonce32,
            validAfter,
            validBefore,
            mintSigBytes,
            split.v,
            hexToBytes(split.r),
            hexToBytes(split.s),
          );
          vaultCallDataBytesByIndex.set(i, cdBytes);
          vaultCallData = uint8ToHexFast(cdBytes);
        } else if (split) {
          vaultCallData = encodeFunctionData({
            abi: CRYPTO_SLIP_VAULT_V32_ABI,
            functionName: 'mintSlipERC20WithAuthorization',
            args: [mintPermitStruct, mintSignature, split.v, split.r, split.s],
          });
        } else {
          vaultCallData = encodeFunctionData({
            abi: CRYPTO_SLIP_VAULT_V32_ABI,
            functionName: 'mintSlipERC20WithAuthorization',
            args: [mintPermitStruct, mintSignature, receiveSignature],
          });
        }

        return {
          index: i,
          asset: cred.asset,
          tokenAddress: cred.tokenAddr,
          requestedAmountUnits: cred.requestedUnits,
          grossAmountUnits: cred.grossUnits,
          expectedExitFeeUnits: cred.exitFeeUnits,
          guaranteedNetClaimUnits: cred.netClaimUnits,
          humanAmount: cred.humanAmount,
          vault,
          vaultAddress: vAddr,
          creator,
          mode: cred.mode,
          cancelLockedUntil: cred.cancelLockedUntil,
          claimSigner: cred.claimSigner,
          ...(cred.claimPrivateKey ? { claimPrivateKey: cred.claimPrivateKey } : {}),
          ...(cred.claimCode ? { claimCode: cred.claimCode } : {}),
          ...(cred.codeSalt ? { codeSalt: cred.codeSalt } : {}),
          permitNonce: nonce,
          validAfter,
          validBefore,
          vaultCallData,
          vaultValue: 0n,
          vaultFunctionName: 'mintSlipERC20WithAuthorization',
          ...(cred.merchantLabel ? { merchantLabel: cred.merchantLabel } : {}),
          ...(cred.cleanNote ? { note: cred.cleanNote } : {}),
          ...(item.recipientRef ? { recipientRef: item.recipientRef } : {}),
        };
      }),
    );
  }

  // Pack ERC-20 slips into Multicall3.aggregate3 chunks (<= chunkSize, e.g. 250)
  const erc20Slips = preparedSlips.filter((s) => s.asset !== 'ETH');
  const ethSlips = preparedSlips.filter((s) => s.asset === 'ETH');
  const transactions: PreparedBatchTransaction[] = [];

  for (let offset = 0; offset < erc20Slips.length; offset += chunkSize) {
    const chunk = erc20Slips.slice(offset, offset + chunkSize);
    for (const s of chunk) {
      assertCreatorBindingPreserved({
        txCaller: MULTICALL3_ADDRESS,
        partnerWallet: creator,
        targetContract: vAddr,
        vaultFunctionName: s.vaultFunctionName,
      });
    }
    const rawMulticall = encodeMulticall3Aggregate3Fast(
      vault20,
      chunk.map((s) => vaultCallDataBytesByIndex.get(s.index) ?? s.vaultCallData),
    );
    const chunkHasNara = chunk.some((s) => s.asset === 'NARA');
    const codes =
      options.builderCodes ??
      (chunkHasNara ? NARA_IN_APP_BUILDER_CODES : DEFAULT_CRYPTOSLIP_BUILDER_CODE);
    const attributedData = appendBuilderCodeSuffix(rawMulticall, codes);

    let chunkUsdc = 0n;
    for (const s of chunk) {
      if (s.asset === 'USDC') chunkUsdc += s.grossAmountUnits;
    }

    transactions.push({
      to: MULTICALL3_ADDRESS,
      value: 0n,
      data: attributedData,
      strategy: 'multicall3_erc20',
      slipIndices: chunk.map((s) => s.index),
      totalUsdcUnits: chunkUsdc,
    });
  }

  // Native ETH slips: preserve msg.sender == creator via direct EOA or Simple7702Account self-batch
  if (ethSlips.length > 0) {
    const ethMode: EthBatchExecutionMode =
      options.ethExecutionMode ??
      (ethSlips.length === 1 ? 'direct_eoa' : 'eip7702_self_batch');

    if (ethMode === 'eip7702_self_batch') {
      for (let offset = 0; offset < ethSlips.length; offset += chunkSize) {
        const chunk = ethSlips.slice(offset, offset + chunkSize);
        let totalEth = 0n;
        const innerCalls: UserOpCall[] = chunk.map((s) => {
          assertCreatorBindingPreserved({
            txCaller: creator,
            partnerWallet: creator,
            targetContract: vAddr,
            vaultFunctionName: 'mintSlipETHWithEscrow',
          });
          totalEth += s.vaultValue;
          return {
            to: vAddr,
            value: s.vaultValue,
            data: s.vaultCallData,
          };
        });
        const rawSelfBatch = encodeSimple7702Calls(innerCalls);
        const attributedData = appendBuilderCodeSuffix(
          rawSelfBatch,
          options.builderCodes ?? DEFAULT_CRYPTOSLIP_BUILDER_CODE,
        );
        transactions.push({
          to: creator,
          value: 0n, // Simple7702Account self-call spends ETH already held by `creator`
          data: attributedData,
          strategy: 'simple7702_eth_self_batch',
          slipIndices: chunk.map((s) => s.index),
          totalUsdcUnits: 0n,
        });
        void totalEth;
      }
    } else {
      for (const s of ethSlips) {
        assertCreatorBindingPreserved({
          txCaller: creator,
          partnerWallet: creator,
          targetContract: vAddr,
          vaultFunctionName: 'mintSlipETHWithEscrow',
        });
        const attributedData = appendBuilderCodeSuffix(
          s.vaultCallData,
          options.builderCodes ?? DEFAULT_CRYPTOSLIP_BUILDER_CODE,
        );
        transactions.push({
          to: vAddr,
          value: s.vaultValue,
          data: attributedData,
          strategy: 'direct_eoa_eth',
          slipIndices: [s.index],
          totalUsdcUnits: 0n,
        });
      }
    }
  }

  return {
    vault,
    vaultAddress: vAddr,
    creator,
    slips: preparedSlips,
    transactions,
    totalsByAsset,
  };
}

// ============================================================================
// Receipt Decoding + Ready-to-Send URL / JSON / CSV Exports
// ============================================================================

export interface ReceiptLogLike {
  readonly address: string;
  readonly data: Hex;
  readonly topics: readonly Hex[];
}

export interface ReceiptLike {
  readonly transactionHash: Hex;
  readonly blockNumber: bigint | number;
  readonly status?: 'success' | 'reverted' | 1 | 0;
  readonly logs: readonly ReceiptLogLike[];
}

export interface MintedPayoutSlipRecord {
  readonly index: number;
  readonly slipId: string;
  readonly txHash: Hex;
  readonly blockNumber: number;
  readonly vault: VaultTag;
  readonly vaultAddress: Address;
  readonly creator: Address;
  readonly asset: SdkAssetSymbol;
  readonly grossAmountUnits: string;
  readonly guaranteedNetClaimUnits: string;
  readonly humanAmount: number;
  readonly mode: SlipLinkMode;
  readonly cancelLockedUntil: number;
  readonly claimSigner: Address;
  readonly payload: string;
  /** Ready-to-send canonical `#` fragment URL (`https://slip.naraprotocol.io/#startapp=slip_...`). */
  readonly url: string;
  /** Ready-to-send sovereign ENS URL (`https://cryptoslip.eth.limo/#startapp=slip_...`). */
  readonly sovereignUrl: string;
  /** Key-free `t.me` startapp URL ONLY when `mode === 'code'` without fragment secrets; `null` for open links. */
  readonly telegramUrl: string | null;
  /** Formatted 12-char `scrypt` code (`XXXX-XXXX-XXXX`) when `mode === 'code'`. */
  readonly claimCode?: string;
  readonly merchantLabel?: string;
  readonly note?: string;
  readonly recipientRef?: string;
}

/**
 * Decodes `SlipMinted` (and legacy `SlipCreated`) events from one or more Base transaction receipts,
 * cryptographically pairing each on-chain `slipId` with its pre-generated `claimPrivateKey` or
 * 12-char `scrypt` `claimCode`, and returning ready-to-send `#` fragment URLs + structured records.
 */
export function parseMintedSlipsFromReceipt(
  receiptOrReceipts: ReceiptLike | readonly ReceiptLike[],
  preparedSlips: readonly PreparedPayoutSlip[],
  options?: {
    shareOrigin?: string;
    embedClaimCodeInFragment?: boolean;
  },
): MintedPayoutSlipRecord[] {
  const receipts: readonly ReceiptLike[] = Array.isArray(receiptOrReceipts)
    ? receiptOrReceipts
    : [receiptOrReceipts];

  const bySignerLower = new Map<string, PreparedPayoutSlip[]>();
  for (const p of preparedSlips) {
    const key = p.claimSigner.toLowerCase();
    const list = bySignerLower.get(key) ?? [];
    list.push(p);
    bySignerLower.set(key, list);
  }

  const origin = options?.shareOrigin ?? CANONICAL_SHARE_ORIGIN;
  const matched: MintedPayoutSlipRecord[] = [];

  for (const receipt of receipts) {
    if (receipt.status === 'reverted' || receipt.status === 0) {
      throw new BatchValidationError(
        `Cannot parse minted slips from reverted transaction ${receipt.transactionHash}.`,
      );
    }
    const blockNum = Number(receipt.blockNumber);

    for (const log of receipt.logs) {
      if (!log.topics || log.topics.length === 0) continue;

      let decodedSlipId: bigint | null = null;
      let decodedCreator: Address | null = null;
      let decodedAmount: bigint | null = null;
      let decodedClaimSigner: Address | null = null;

      try {
        const parsed = decodeEventLog({
          abi: CRYPTO_SLIP_VAULT_V32_ABI,
          data: log.data,
          topics: log.topics as [Hex, ...Hex[]],
        });
        if (parsed.eventName === 'SlipMinted') {
          decodedSlipId = parsed.args.slipId;
          decodedCreator = getAddress(parsed.args.creator);
          decodedAmount = parsed.args.amount;
          decodedClaimSigner = getAddress(parsed.args.claimSigner);
        }
      } catch {
        try {
          const fallback = decodeEventLog({
            abi: [LEGACY_SLIP_CREATED_EVENT],
            data: log.data,
            topics: log.topics as [Hex, ...Hex[]],
          });
          if (fallback.eventName === 'SlipCreated') {
            decodedSlipId = fallback.args.slipId;
            decodedCreator = getAddress(fallback.args.creator);
            decodedAmount = fallback.args.amount;
            decodedClaimSigner = getAddress(fallback.args.claimSigner);
          }
        } catch {
          // Unrelated log (e.g. ERC-20 Transfer or ERC-721 Mint)
        }
      }

      if (
        decodedSlipId === null ||
        decodedCreator === null ||
        decodedAmount === null ||
        decodedClaimSigner === null
      ) {
        continue;
      }

      const queue = bySignerLower.get(decodedClaimSigner.toLowerCase());
      const prepared = queue?.shift();
      if (!prepared) continue;

      if (log.address.toLowerCase() !== prepared.vaultAddress.toLowerCase()) {
        queue?.unshift(prepared);
        continue;
      }

      if (decodedCreator.toLowerCase() !== prepared.creator.toLowerCase()) {
        throw new CreatorBindingViolationError(
          `On-chain SlipMinted creator (${decodedCreator}) did not match partner wallet (${prepared.creator}) for slip #${decodedSlipId.toString()}!`,
        );
      }

      const slipIdStr = decodedSlipId.toString();
      const encoded = encodeSlipUrl({
        id: slipIdStr,
        amount: prepared.humanAmount,
        asset: prepared.asset,
        vault: prepared.vault,
        mode: prepared.mode,
        claimKey: prepared.claimPrivateKey,
        codeSalt: prepared.codeSalt,
        cancelLockedUntil: Number(prepared.cancelLockedUntil),
        origin,
        note: prepared.note,
        ...(options?.embedClaimCodeInFragment && prepared.claimCode
          ? { embedClaimCodeInFragment: prepared.claimCode }
          : {}),
      });

      matched.push({
        index: prepared.index,
        slipId: slipIdStr,
        txHash: receipt.transactionHash,
        blockNumber: blockNum,
        vault: prepared.vault,
        vaultAddress: prepared.vaultAddress,
        creator: decodedCreator,
        asset: prepared.asset,
        grossAmountUnits: decodedAmount.toString(),
        guaranteedNetClaimUnits: prepared.guaranteedNetClaimUnits.toString(),
        humanAmount: prepared.humanAmount,
        mode: prepared.mode,
        cancelLockedUntil: Number(prepared.cancelLockedUntil),
        claimSigner: decodedClaimSigner,
        payload: encoded.payload,
        url: encoded.webUrl,
        sovereignUrl: encoded.sovereignUrl,
        telegramUrl: encoded.telegramUrl,
        ...(prepared.claimCode ? { claimCode: prepared.claimCode } : {}),
        ...(prepared.merchantLabel ? { merchantLabel: prepared.merchantLabel } : {}),
        ...(prepared.note ? { note: prepared.note } : {}),
        ...(prepared.recipientRef ? { recipientRef: prepared.recipientRef } : {}),
      });
    }
  }

  matched.sort((a, b) => a.index - b.index);
  return matched;
}

const escapeCsvCell = (raw: string | number | undefined): string => {
  if (raw === undefined || raw === null) return '';
  let str = String(raw);
  // Neutralize spreadsheet formula-injection triggers on free-form text cells
  if (/^[=+\-@\t\r]/.test(str) && !/^\d/.test(str)) {
    str = `'${str}`;
  }
  if (/[",\r\n]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
};

/**
 * Exports minted payout slips to an RFC 4180 CSV string (safe against spreadsheet formula injection).
 */
export function exportMintedSlipsCsv(slips: readonly MintedPayoutSlipRecord[]): string {
  const header = [
    'index',
    'recipientRef',
    'slipId',
    'asset',
    'humanAmount',
    'grossAmountUnits',
    'guaranteedNetClaimUnits',
    'mode',
    'noTakeBack',
    'claimCode',
    'url',
    'sovereignUrl',
    'txHash',
    'merchantLabel',
    'note',
  ].join(',');

  const rows = slips.map((s) =>
    [
      escapeCsvCell(s.index),
      escapeCsvCell(s.recipientRef),
      escapeCsvCell(s.slipId),
      escapeCsvCell(s.asset),
      escapeCsvCell(s.humanAmount),
      escapeCsvCell(s.grossAmountUnits),
      escapeCsvCell(s.guaranteedNetClaimUnits),
      escapeCsvCell(s.mode),
      escapeCsvCell(s.cancelLockedUntil === Number(NO_TAKE_BACK_LOCK) ? 'true' : 'false'),
      escapeCsvCell(s.claimCode),
      escapeCsvCell(s.url),
      escapeCsvCell(s.sovereignUrl),
      escapeCsvCell(s.txHash),
      escapeCsvCell(s.merchantLabel),
      escapeCsvCell(s.note),
    ].join(','),
  );

  return [header, ...rows].join('\n');
}

/**
 * Exports minted payout slips as formatted JSON.
 */
export function exportMintedSlipsJson(
  slips: readonly MintedPayoutSlipRecord[],
  pretty = true,
): string {
  return JSON.stringify(slips, null, pretty ? 2 : 0);
}

export interface ExecuteBatchPayoutOptions extends PrepareBatchPayoutOptions {
  publicClient: BaseCompatiblePublicClient;
  /** Optional `viem` WalletClient for direct Base EOA submission. */
  walletClient?: BaseCompatibleWalletClient;
  /** When `true` (or when wallet holds 0 ETH and `paymasterSignerKey` is available), submits ERC-20 batches via Circle `TokenPaymasterV08` in `USDC`. */
  useCirclePaymaster?: boolean;
  paymasterSignerKey?: Hex;
  bundlerUrls?: readonly string[];
  bundlerFetch?: BundlerFetchFn;
  shareOrigin?: string;
  embedClaimCodeInFragment?: boolean;
  onStatus?: (msg: string) => void;
}

export interface BatchPayoutExecutionResult {
  readonly prepared: PreparedBatchPayout;
  readonly txHashes: readonly Hex[];
  readonly mintedSlips: readonly MintedPayoutSlipRecord[];
  readonly csv: string;
  readonly json: string;
}

/**
 * End-to-end 1-Tx (up to 250 slips/tx, 500 slips/call) Partner Batch Dispenser:
 * 1. Offline-signs all `MintPermit` + EIP-3009 / EIP-2612 authorizations (`bindCreator = true`).
 * 2. Broadcasts via `Multicall3.aggregate3` (either direct `walletClient` or serverless Circle `TokenPaymasterV08` in `USDC`).
 * 3. Confirms receipts on Base, pairs every `SlipMinted` `slipId` with its `#` fragment link / `scrypt` code, and generates JSON + CSV!
 */
export async function executeBatchPayoutSlips(
  options: ExecuteBatchPayoutOptions,
): Promise<BatchPayoutExecutionResult> {
  const { publicClient, walletClient, onStatus } = options;

  // Auto-detect Simple7702Account delegation if ETH batch has >1 item and ethExecutionMode wasn't explicitly set
  let resolvedEthMode = options.ethExecutionMode;
  const hasMultiEth =
    options.items.filter((it) => normalizeSdkAsset(it.asset) === 'ETH').length > 1;
  if (hasMultiEth && !resolvedEthMode) {
    const normSigner = await normalizeBatchSigner(options.signer);
    const code = (await publicClient.getCode({ address: normSigner.address }).catch(() => '0x')) ?? '0x';
    if (!isPersonalOrCanonical7702Code(code)) {
      throw new BatchValidationError(
        'Partner wallet has non-canonical contract code; cannot batch native ETH slips.',
      );
    }
    resolvedEthMode =
      code.toLowerCase() ===
      `0xef0100e6cae83bde06e4c305530e199d7217f42808555b`
        ? 'eip7702_self_batch'
        : 'direct_eoa';
  }

  onStatus?.(`Preparing ${options.items.length} payout slip(s)…`);
  const prepared = await prepareBatchPayoutSlips({
    ...options,
    publicClient,
    ...(resolvedEthMode ? { ethExecutionMode: resolvedEthMode } : {}),
  });

  const normSigner = await normalizeBatchSigner(options.signer);
  const rawPmKey = options.paymasterSignerKey ?? normSigner.rawKeyIfKnown;

  const txHashes: Hex[] = [];
  const receipts: TransactionReceipt[] = [];

  for (let tIdx = 0; tIdx < prepared.transactions.length; tIdx++) {
    const tx = prepared.transactions[tIdx]!;
    onStatus?.(
      `Submitting batch transaction ${tIdx + 1}/${prepared.transactions.length} (${tx.strategy})…`,
    );

    let txHash: Hex | null = null;

    if (
      tx.strategy === 'multicall3_erc20' &&
      rawPmKey &&
      (options.useCirclePaymaster || !walletClient)
    ) {
      const check = await canSponsorWithCircleUsdcPaymaster({
        userAddress: prepared.creator,
        publicClient,
        reservedUsdcUnits: tx.totalUsdcUnits,
      });
      if (check.ok) {
        const pmRes = await executeViaCircleUsdcPaymaster({
          signerKey: rawPmKey,
          calls: [{ to: tx.to, value: tx.value, data: tx.data }],
          publicClient,
          reservedUsdcUnits: tx.totalUsdcUnits,
          bundlerUrls: options.bundlerUrls,
          bundlerFetch: options.bundlerFetch,
          onStatus,
        });
        txHash = pmRes.txHash;
      } else if (options.useCirclePaymaster && !walletClient) {
        throw new BatchValidationError(
          'Insufficient unreserved USDC (>= $0.10 above batch principal) for Circle TokenPaymasterV08.',
        );
      }
    }

    if (!txHash) {
      if (!walletClient) {
        throw new BatchValidationError(
          'walletClient (or paymasterSignerKey with >= $0.10 extra USDC) is required to broadcast batch transactions.',
        );
      }
      const account =
        walletClient.account ??
        (rawPmKey ? privateKeyToAccount(rawPmKey) : undefined);
      if (!account) {
        throw new BatchValidationError('walletClient must have an active account attached.');
      }
      txHash = await walletClient.sendTransaction({
        account,
        chain: walletClient.chain ?? null,
        to: tx.to,
        value: tx.value,
        data: tx.data,
      });
    }

    txHashes.push(txHash);
    onStatus?.(`Waiting for Base confirmation (${txHash.slice(0, 10)}…)`);
    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
    if (receipt.status !== 'success') {
      throw new BatchValidationError(`Batch transaction ${txHash} reverted on Base.`);
    }
    receipts.push(receipt);
  }

  const mintedSlips = parseMintedSlipsFromReceipt(receipts, prepared.slips, {
    shareOrigin: options.shareOrigin,
    embedClaimCodeInFragment: options.embedClaimCodeInFragment,
  });

  return {
    prepared,
    txHashes,
    mintedSlips,
    csv: exportMintedSlipsCsv(mintedSlips),
    json: exportMintedSlipsJson(mintedSlips),
  };
}
