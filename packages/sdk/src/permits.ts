import { randomBytes } from 'node:crypto';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import {
  bytesToBigInt,
  bytesToHex,
  concatHex,
  encodeAbiParameters,
  encodePacked,
  getAddress,
  hashTypedData,
  hexToBytes,
  keccak256,
  parseAbiParameters,
  stringToHex,
  type Address,
  type Hex,
  type LocalAccount,
  type WalletClient,
} from 'viem';
import { privateKeyToAccount, privateKeyToAddress } from 'viem/accounts';
import {
  BASE_CHAIN_ID,
  CBBTC_BASE_ADDRESS,
  ISSUE_VAULT,
  NARA_BASE_ADDRESS,
  NO_TAKE_BACK_LOCK,
  USDC_BASE_ADDRESS,
  VAULTS,
  ZERO_ADDRESS,
  tradeRouterForVault,
  vaultAddress,
  vaultTagForAddress,
  type VaultTag,
} from './constants.js';

const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const KEPT_RECOVERY_PURPOSE = 'CryptoSLIP/kept-slip-recovery/v1';
const CREATED_RECOVERY_PURPOSE = 'CryptoSLIP/created-slip-recovery/v1';
const SPLIT_CHANGE_RECOVERY_PURPOSE = 'CryptoSLIP/split-change-recovery/v1';
export const MAX_KEPT_SLIP_HOPS = 5;

const INSPECT_CUSTOM = Symbol.for('nodejs.util.inspect.custom');

// ============================================================================
// Universal `SlipSigner` Interface & Safe Multi-Library Signer Adapters
// ============================================================================

export interface EIP712DomainConfig {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: Address;
}

export interface TypedDataField {
  readonly name: string;
  readonly type: string;
}

export interface SlipTypedDataPayload {
  domain: EIP712DomainConfig;
  types: Record<string, readonly TypedDataField[]>;
  primaryType: string;
  message: Record<string, unknown>;
}

/**
 * Structural duck-type for `ethers` v6 `AbstractSigner` / `Wallet` so callers using `ethers`
 * work out-of-the-box without requiring `ethers` when using `viem`.
 */
export interface EthersV6SignerLike {
  getAddress(): Promise<string>;
  signTypedData(
    domain: Record<string, unknown>,
    types: Record<string, Array<{ name: string; type: string }>>,
    value: Record<string, unknown>,
  ): Promise<string>;
  signMessage(message: string | Uint8Array): Promise<string>;
}

export interface SlipSigner {
  readonly address: Address;
  readonly kind: 'privateKey' | 'viemAccount' | 'viemWalletClient' | 'ethersSigner' | 'policyGuarded';
  getAddress(): Promise<Address>;
  signTypedData(payload: SlipTypedDataPayload): Promise<Hex>;
  signMessage(message: string | { raw: Hex | Uint8Array }): Promise<Hex>;
  toString(): string;
  toJSON(): { address: Address; kind: string };
}

export type SlipSignerInput =
  | SlipSigner
  | LocalAccount
  | WalletClient
  | EthersV6SignerLike
  | Hex
  | Uint8Array;

function attachSafeRedaction<T extends SlipSigner>(signer: T): T {
  Object.defineProperty(signer, INSPECT_CUSTOM, {
    value: () => `SlipSigner(${signer.kind}:${signer.address})`,
    enumerable: false,
    configurable: true,
  });
  return signer;
}

/**
 * Wraps a raw 32-byte private key (`0x` + 64 hex or 32-byte `Uint8Array`) inside an opaque closure
 * that NEVER exposes or logs the private key on `console.log`, `JSON.stringify`, or stack inspection.
 */
export function createSlipSignerFromKey(privateKey: Hex | Uint8Array): SlipSigner {
  const keyHex: Hex =
    privateKey instanceof Uint8Array
      ? bytesToHex(privateKey)
      : (`0x${String(privateKey).replace(/^0x/i, '')}` as Hex);
  if (!/^0x[0-9a-fA-F]{64}$/.test(keyHex)) {
    throw new Error('Invalid secp256k1 private key length (expected 32 bytes)');
  }
  const scalar = BigInt(keyHex);
  if (scalar <= 0n || scalar >= SECP256K1_ORDER) {
    throw new Error('Private key scalar is outside valid secp256k1 range');
  }
  const account = privateKeyToAccount(keyHex);
  const address = account.address;

  const signer: SlipSigner = {
    address,
    kind: 'privateKey',
    async getAddress() {
      return address;
    },
    async signTypedData(payload) {
      return account.signTypedData({
        domain: payload.domain,
        types: payload.types as Record<string, readonly { name: string; type: string }[]>,
        primaryType: payload.primaryType,
        message: payload.message,
      });
    },
    async signMessage(message) {
      return account.signMessage({ message });
    },
    toString() {
      return `SlipSigner(privateKey:${address})`;
    },
    toJSON() {
      return { address, kind: 'privateKey' };
    },
  };
  return attachSafeRedaction(signer);
}

/** Wraps a `viem` `LocalAccount` (`PrivateKeyAccount`, HD account, custom account). */
export function fromViemAccount(account: LocalAccount): SlipSigner {
  const address = getAddress(account.address);
  if (typeof account.signTypedData !== 'function' || typeof account.signMessage !== 'function') {
    throw new Error('Provided viem account does not support signTypedData / signMessage');
  }
  const signer: SlipSigner = {
    address,
    kind: 'viemAccount',
    async getAddress() {
      return address;
    },
    async signTypedData(payload) {
      return account.signTypedData({
        domain: payload.domain,
        types: payload.types as Record<string, readonly { name: string; type: string }[]>,
        primaryType: payload.primaryType,
        message: payload.message,
      });
    },
    async signMessage(message) {
      return account.signMessage({ message });
    },
    toString() {
      return `SlipSigner(viemAccount:${address})`;
    },
    toJSON() {
      return { address, kind: 'viemAccount' };
    },
  };
  return attachSafeRedaction(signer);
}

/** Wraps a `viem` `WalletClient` with an attached `account`. */
export function fromViemWalletClient(walletClient: WalletClient): SlipSigner {
  const account = walletClient.account;
  if (!account) {
    throw new Error('WalletClient must have an attached account to sign CryptoSLIP permits');
  }
  const address = getAddress(account.address);
  const signer: SlipSigner = {
    address,
    kind: 'viemWalletClient',
    async getAddress() {
      return address;
    },
    async signTypedData(payload) {
      return walletClient.signTypedData({
        account,
        domain: payload.domain,
        types: payload.types as Record<string, readonly { name: string; type: string }[]>,
        primaryType: payload.primaryType,
        message: payload.message,
      });
    },
    async signMessage(message) {
      return walletClient.signMessage({ account, message });
    },
    toString() {
      return `SlipSigner(viemWalletClient:${address})`;
    },
    toJSON() {
      return { address, kind: 'viemWalletClient' };
    },
  };
  return attachSafeRedaction(signer);
}

/** Adapts an `ethers` v6 `AbstractSigner` / `Wallet` into a universal `SlipSigner`. */
export async function fromEthersSigner(ethersSigner: EthersV6SignerLike): Promise<SlipSigner> {
  const rawAddr = await ethersSigner.getAddress();
  const address = getAddress(rawAddr);
  const signer: SlipSigner = {
    address,
    kind: 'ethersSigner',
    async getAddress() {
      return address;
    },
    async signTypedData(payload) {
      const mutableTypes: Record<string, Array<{ name: string; type: string }>> = {};
      for (const [typeName, fields] of Object.entries(payload.types)) {
        if (typeName === 'EIP712Domain') continue;
        mutableTypes[typeName] = fields.map((f) => ({ name: f.name, type: f.type }));
      }
      const sig = await ethersSigner.signTypedData(
        {
          name: payload.domain.name,
          version: payload.domain.version,
          chainId: payload.domain.chainId,
          verifyingContract: payload.domain.verifyingContract,
        },
        mutableTypes,
        payload.message,
      );
      return sig as Hex;
    },
    async signMessage(message) {
      if (typeof message === 'string') {
        return (await ethersSigner.signMessage(message)) as Hex;
      }
      const bytes =
        message.raw instanceof Uint8Array ? message.raw : hexToBytes(message.raw);
      return (await ethersSigner.signMessage(bytes)) as Hex;
    },
    toString() {
      return `SlipSigner(ethersSigner:${address})`;
    },
    toJSON() {
      return { address, kind: 'ethersSigner' };
    },
  };
  return attachSafeRedaction(signer);
}

function isSlipSigner(x: unknown): x is SlipSigner {
  return (
    typeof x === 'object' &&
    x !== null &&
    'kind' in x &&
    'address' in x &&
    typeof (x as SlipSigner).getAddress === 'function' &&
    typeof (x as SlipSigner).signTypedData === 'function'
  );
}

function isViemLocalAccount(x: unknown): x is LocalAccount {
  return (
    typeof x === 'object' &&
    x !== null &&
    'address' in x &&
    'type' in x &&
    typeof (x as LocalAccount).signTypedData === 'function' &&
    !('kind' in x)
  );
}

function isViemWalletClient(x: unknown): x is WalletClient {
  return (
    typeof x === 'object' &&
    x !== null &&
    'account' in x &&
    'chain' in x &&
    typeof (x as WalletClient).signTypedData === 'function'
  );
}

/**
 * Resolves any supported signer (`SlipSigner`, `viem` `LocalAccount` / `WalletClient`,
 * `ethers` v6 `AbstractSigner`, or 32-byte key) into a safe `SlipSigner`.
 */
export async function toSlipSigner(input: SlipSignerInput): Promise<SlipSigner> {
  if (input instanceof Uint8Array || typeof input === 'string') {
    return createSlipSignerFromKey(input);
  }
  if (isSlipSigner(input)) return input;
  if (isViemWalletClient(input)) return fromViemWalletClient(input);
  if (isViemLocalAccount(input)) return fromViemAccount(input);
  if (
    typeof input === 'object' &&
    input !== null &&
    typeof (input as EthersV6SignerLike).getAddress === 'function' &&
    typeof (input as EthersV6SignerLike).signTypedData === 'function'
  ) {
    return fromEthersSigner(input as EthersV6SignerLike);
  }
  throw new Error('Unsupported signer passed to toSlipSigner');
}

// ============================================================================
// Law #3 Cancel-Lock Guard & L2 Clock-Skew Safe Deadlines
// ============================================================================

/**
 * Enforces Solidity Law #3 (`CryptoSlipProtocolV32.sol:1491-1495`):
 * `cancelLockedUntil` MUST be strictly `0n` (revocable) or `9_999_999_999n` (`No take-back`).
 */
export function assertValidCancelLock(lock: bigint | number | undefined | null): bigint {
  if (lock === undefined || lock === null) return 0n;
  if (typeof lock === 'number' && (!Number.isSafeInteger(lock) || lock < 0)) {
    throw new Error('Invalid cancelLockedUntil: expected 0 or 9_999_999_999');
  }
  const lockBig = BigInt(lock);
  if (lockBig !== 0n && lockBig !== NO_TAKE_BACK_LOCK) {
    throw new Error(
      `Solidity Law #3 violation: cancelLockedUntil must be strictly 0n or ${NO_TAKE_BACK_LOCK}n (got ${lockBig}n)`,
    );
  }
  return lockBig;
}

/**
 * Computes an L2 clock-skew safe EIP-712 / EIP-3009 / EIP-2612 deadline anchored strictly to
 * the Base L2 `headBlockTimestamp` (never trusting an uncalibrated client clock).
 */
export function computePermitDeadline(
  headBlockTimestamp: bigint | number,
  ttlSeconds: bigint | number = 7200n,
): bigint {
  const head =
    typeof headBlockTimestamp === 'bigint'
      ? headBlockTimestamp
      : Number.isSafeInteger(headBlockTimestamp)
        ? BigInt(headBlockTimestamp)
        : -1n;
  if (head <= 0n) {
    throw new Error('headBlockTimestamp must be a positive Base block timestamp (seconds)');
  }
  const ttl =
    typeof ttlSeconds === 'bigint'
      ? ttlSeconds
      : Number.isSafeInteger(ttlSeconds)
        ? BigInt(ttlSeconds)
        : -1n;
  if (ttl <= 0n) {
    throw new Error('ttlSeconds must be positive');
  }
  return head + ttl;
}

/**
 * Computes `{ validAfter: 0n, validBefore }` for `MintPermit` / EIP-3009 authorizations.
 * `validAfter` MUST be `0n` because `CryptoSlipVaultV32._executeGaslessMint` (`L1361`) checks
 * `if (block.timestamp <= a.validAfter) revert AuthorizationNotYetValid()`.
 */
export function computeMintValidityWindow(
  headBlockTimestamp: bigint | number,
  ttlSeconds: bigint | number = 7200n,
): { validAfter: 0n; validBefore: bigint } {
  return {
    validAfter: 0n,
    validBefore: computePermitDeadline(headBlockTimestamp, ttlSeconds),
  };
}

export function randomPermitNonce(): Hex {
  return bytesToHex(randomBytes(32));
}

// ============================================================================
// EIP-712 Domains & Domain Separator Calculators
// ============================================================================

const EIP712_DOMAIN_TYPEHASH = keccak256(
  stringToHex('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
);

export function computeEip712DomainSeparator(domain: EIP712DomainConfig): Hex {
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters('bytes32, bytes32, bytes32, uint256, address'),
      [
        EIP712_DOMAIN_TYPEHASH,
        keccak256(stringToHex(domain.name)),
        keccak256(stringToHex(domain.version)),
        BigInt(domain.chainId),
        getAddress(domain.verifyingContract),
      ],
    ),
  );
}

export function getVaultDomain(
  vaultOrContract: VaultTag | Address = ISSUE_VAULT,
  chainId: number = BASE_CHAIN_ID,
): EIP712DomainConfig {
  if (
    vaultOrContract === 'v33' ||
    vaultOrContract === 'v32' ||
    vaultOrContract === 'v3' ||
    vaultOrContract === 'v2'
  ) {
    const info = VAULTS[vaultOrContract];
    return {
      name: info.domainName,
      version: info.domainVersion,
      chainId,
      verifyingContract: info.address,
    };
  }
  const checksummed = getAddress(vaultOrContract);
  const tag = vaultTagForAddress(checksummed);
  return {
    name: 'Crypto Slip Protocol',
    version: tag ? VAULTS[tag].domainVersion : '3',
    chainId,
    verifyingContract: checksummed,
  };
}

export function computeVaultDomainSeparator(
  vaultOrContract: VaultTag | Address = ISSUE_VAULT,
  chainId: number = BASE_CHAIN_ID,
): Hex {
  return computeEip712DomainSeparator(getVaultDomain(vaultOrContract, chainId));
}

export function getTradeRouterDomain(
  vaultOrRouter: 'v33' | 'v32' | Address = 'v33',
  chainId: number = BASE_CHAIN_ID,
): EIP712DomainConfig {
  const verifyingContract =
    vaultOrRouter === 'v33' || vaultOrRouter === 'v32'
      ? tradeRouterForVault(vaultOrRouter)
      : getAddress(vaultOrRouter);
  return {
    name: 'Crypto Slip Trade Router',
    version: '3.2',
    chainId,
    verifyingContract,
  };
}

export function computeTradeRouterDomainSeparator(
  vaultOrRouter: 'v33' | 'v32' | Address = 'v33',
  chainId: number = BASE_CHAIN_ID,
): Hex {
  return computeEip712DomainSeparator(getTradeRouterDomain(vaultOrRouter, chainId));
}

/** Canonical Base token EIP-712 domains (`client/src/lib/eip3009Helper.ts` exact parity). */
export const USDC_BASE_DOMAIN: EIP712DomainConfig = {
  name: 'USD Coin',
  version: '2',
  chainId: BASE_CHAIN_ID,
  verifyingContract: USDC_BASE_ADDRESS,
};

export const CBBTC_BASE_DOMAIN: EIP712DomainConfig = {
  name: 'Coinbase Wrapped BTC',
  version: '2',
  chainId: BASE_CHAIN_ID,
  verifyingContract: CBBTC_BASE_ADDRESS,
};

export const NARA_BASE_DOMAIN: EIP712DomainConfig = {
  name: 'NARA Token',
  version: '1',
  chainId: BASE_CHAIN_ID,
  verifyingContract: NARA_BASE_ADDRESS,
};

export function getEip3009DomainForToken(tokenOrAsset: string): EIP712DomainConfig {
  const clean = (tokenOrAsset || '').trim().toLowerCase();
  if (clean === 'cbbtc' || clean === 'btc' || clean === CBBTC_BASE_ADDRESS.toLowerCase()) {
    return CBBTC_BASE_DOMAIN;
  }
  if (clean === 'usdc' || clean === USDC_BASE_ADDRESS.toLowerCase()) {
    return USDC_BASE_DOMAIN;
  }
  throw new Error(`Token ${tokenOrAsset} does not use canonical Base EIP-3009 (USDC / cbBTC only)`);
}

export function getErc2612DomainForToken(tokenOrAsset: string): EIP712DomainConfig {
  const clean = (tokenOrAsset || '').trim().toLowerCase();
  if (clean === 'nara' || clean === NARA_BASE_ADDRESS.toLowerCase()) {
    return NARA_BASE_DOMAIN;
  }
  if (clean === 'usdc' || clean === USDC_BASE_ADDRESS.toLowerCase()) {
    return USDC_BASE_DOMAIN;
  }
  if (clean === 'cbbtc' || clean === 'btc' || clean === CBBTC_BASE_ADDRESS.toLowerCase()) {
    return CBBTC_BASE_DOMAIN;
  }
  throw new Error(`Unknown canonical Base EIP-2612 token: ${tokenOrAsset}`);
}

// ============================================================================
// EIP-712 Type Definitions (`CryptoSlipProtocolV32.sol` & `permitHelper.ts` Parity)
// ============================================================================

export const MINT_PERMIT_V32_TYPES = {
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

export const CASH_PERMIT_TYPES = {
  CashPermit: [
    { name: 'slipId', type: 'uint256' },
    { name: 'recipient', type: 'address' },
    { name: 'relayer', type: 'address' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
} as const;

export const ACCEPT_PERMIT_V32_TYPES = {
  AcceptPermit: [
    { name: 'slipId', type: 'uint256' },
    { name: 'newHolder', type: 'address' },
    { name: 'newClaimSigner', type: 'address' },
    { name: 'keepEscrowedInVault', type: 'bool' },
    { name: 'relayer', type: 'address' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
} as const;

export const SPLIT_PERMIT_TYPES = {
  SplitPermit: [
    { name: 'slipId', type: 'uint256' },
    { name: 'paymentAmount', type: 'uint256' },
    { name: 'merchant', type: 'address' },
    { name: 'changeReceiver', type: 'address' },
    { name: 'newChangeSigner', type: 'address' },
    { name: 'relayer', type: 'address' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
} as const;

export const REARRANGE_PERMIT_V32_TYPES = {
  RearrangePermit: [
    { name: 'slipId', type: 'uint256' },
    { name: 'slipIdsHash', type: 'bytes32' },
    { name: 'paymentAmount', type: 'uint256' },
    { name: 'merchant', type: 'address' },
    { name: 'changeReceiver', type: 'address' },
    { name: 'newChangeSigner', type: 'address' },
    { name: 'relayer', type: 'address' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
} as const;

export const REFUND_PERMIT_V32_TYPES = {
  RefundPermit: [
    { name: 'slipId', type: 'uint256' },
    { name: 'destination', type: 'address' },
    { name: 'relayer', type: 'address' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
} as const;

export const REFERRAL_CONSENT_V32_TYPES = {
  ReferralConsent: [
    { name: 'recipient', type: 'address' },
    { name: 'slipId', type: 'uint256' },
    { name: 'referrer', type: 'address' },
    { name: 'deadline', type: 'uint256' },
  ],
} as const;

export const SWAP_OFFER_V32_TYPES = {
  SwapOfferPermit: [
    { name: 'slipId', type: 'uint256' },
    { name: 'swapAmount', type: 'uint256' },
    { name: 'outAsset', type: 'address' },
    { name: 'minAmountOut', type: 'uint256' },
    { name: 'newOutputSigner', type: 'address' },
    { name: 'outputCancelLockedUntil', type: 'uint48' },
    { name: 'swapTarget', type: 'address' },
    { name: 'swapDataHash', type: 'bytes32' },
    { name: 'relayer', type: 'address' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
} as const;

export const SWAP_AND_PAY_V32_TYPES = {
  SwapAndPayPermit: [
    { name: 'slipId', type: 'uint256' },
    { name: 'swapAmount', type: 'uint256' },
    { name: 'merchant', type: 'address' },
    { name: 'outAsset', type: 'address' },
    { name: 'minAmountOut', type: 'uint256' },
    { name: 'swapTarget', type: 'address' },
    { name: 'swapDataHash', type: 'bytes32' },
    { name: 'relayer', type: 'address' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
} as const;

export const COMPOSITE_SWAP_OFFER_V32_TYPES = {
  CompositeSwapOfferPermit: [
    { name: 'slipId', type: 'uint256' },
    { name: 'swapAmount', type: 'uint256' },
    { name: 'midAsset', type: 'address' },
    { name: 'outAsset', type: 'address' },
    { name: 'leg2AmountIn', type: 'uint256' },
    { name: 'minAmountOut', type: 'uint256' },
    { name: 'newOutputSigner', type: 'address' },
    { name: 'outputCancelLockedUntil', type: 'uint48' },
    { name: 'swapTarget1', type: 'address' },
    { name: 'swapData1Hash', type: 'bytes32' },
    { name: 'swapTarget2', type: 'address' },
    { name: 'swapData2Hash', type: 'bytes32' },
    { name: 'relayer', type: 'address' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
} as const;

export const TRADE_OFFER_V32_TYPES = {
  TradeOfferPermit: [
    { name: 'mySlipId', type: 'uint256' },
    { name: 'counterpartySlipId', type: 'uint256' },
    { name: 'myNewClaimSigner', type: 'address' },
    { name: 'relayer', type: 'address' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
} as const;

export const RECEIVE_WITH_AUTHORIZATION_TYPES = {
  ReceiveWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
  ],
} as const;

export const TRANSFER_WITH_AUTHORIZATION_TYPES = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
  ],
} as const;

export const ERC20_PERMIT_TYPES = {
  Permit: [
    { name: 'owner', type: 'address' },
    { name: 'spender', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
} as const;

// ============================================================================
// Signature Split & `130-Byte` ReferralConsent Packing Helpers
// ============================================================================

export interface SplitEcdsaSignature {
  v: 27 | 28;
  r: Hex;
  s: Hex;
  signature: Hex;
}

export function splitSignatureVrs(rawSignature: Hex | string): SplitEcdsaSignature {
  const clean = (rawSignature || '').trim().replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]{130}$/.test(clean)) {
    throw new Error(`Expected 65-byte ECDSA signature (got ${clean.length / 2} bytes)`);
  }
  const r = `0x${clean.slice(0, 64).toLowerCase()}` as Hex;
  const s = `0x${clean.slice(64, 128).toLowerCase()}` as Hex;
  let vNum = Number.parseInt(clean.slice(128, 130), 16);
  if (vNum === 0 || vNum === 1) vNum += 27;
  if (vNum !== 27 && vNum !== 28) {
    throw new Error(`Invalid ECDSA recovery byte v=${vNum}`);
  }
  const vHex = vNum.toString(16).padStart(2, '0');
  const signature = `0x${clean.slice(0, 128).toLowerCase()}${vHex}` as Hex;
  return { v: vNum, r, s, signature };
}

/**
 * Packs a `65-byte` Vault permit signature (`CashPermit` or `AcceptPermit`) and a `65-byte`
 * `ReferralConsent` signature into the canonical `130-byte` (`sig[0:65] || sig[65:130]`) bundle
 * verified by `CryptoSlipVaultV32` (`L569, L981, L1445-1450`).
 */
export function packPermitWithReferralConsent(
  permitSignature: Hex | string,
  referralConsentSignature: Hex | string,
): Hex {
  const p = splitSignatureVrs(permitSignature).signature;
  const c = splitSignatureVrs(referralConsentSignature).signature;
  const packed = concatHex([p, c]);
  if (packed.length !== 2 + 260) {
    throw new Error('Internal error: packed permit + referral consent must be 130 bytes');
  }
  return packed;
}

export function unpackPermitWithReferralConsent(packedSignature: Hex | string): {
  permitSignature: Hex;
  referralConsentSignature: Hex;
} {
  const clean = (packedSignature || '').trim().replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]{260}$/.test(clean)) {
    throw new Error('Expected 130-byte packed permit + referral consent signature');
  }
  return {
    permitSignature: splitSignatureVrs(`0x${clean.slice(0, 130)}`).signature,
    referralConsentSignature: splitSignatureVrs(`0x${clean.slice(130, 260)}`).signature,
  };
}

// ============================================================================
// Typed-Data Builders & Signers for Vault & Router Permits
// ============================================================================

export interface MintPermitMessage {
  creator: Address;
  token: Address;
  amount: bigint;
  claimSigner: Address;
  referrer: Address;
  cancelLockedUntil: number;
  nonce: Hex;
  validAfter: bigint;
  validBefore: bigint;
  relayer: Address;
}

export interface BuildMintPermitInput {
  creator: Address;
  token: Address;
  amount: bigint;
  claimSigner: Address;
  referrer?: Address;
  cancelLockedUntil?: bigint | number;
  nonce?: Hex;
  validAfter?: bigint;
  validBefore: bigint;
  relayer?: Address;
  vault?: VaultTag | Address;
  chainId?: number;
}

export function buildMintPermitTypedData(input: BuildMintPermitInput): {
  domain: EIP712DomainConfig;
  types: typeof MINT_PERMIT_V32_TYPES;
  primaryType: 'MintPermit';
  message: MintPermitMessage;
  digest: Hex;
} {
  const lockBig = assertValidCancelLock(input.cancelLockedUntil);
  const creator = getAddress(input.creator);
  const claimSigner = getAddress(input.claimSigner);
  if (lockBig !== 0n && creator.toLowerCase() === claimSigner.toLowerCase()) {
    throw new Error(
      'CryptoSlipVaultV32 reverts CancelLockTooLong() when creator == claimSigner on a No take-back slip',
    );
  }
  const nonce = input.nonce ?? randomPermitNonce();
  if (!/^0x[0-9a-fA-F]{64}$/.test(nonce)) {
    throw new Error('MintPermit nonce must be 32-byte hex (bytes32)');
  }
  const validAfter = input.validAfter ?? 0n;
  if (input.validBefore <= validAfter) {
    throw new Error('MintPermit validBefore must be strictly greater than validAfter');
  }
  const domain = getVaultDomain(input.vault ?? ISSUE_VAULT, input.chainId ?? BASE_CHAIN_ID);
  const message: MintPermitMessage = {
    creator,
    token: getAddress(input.token),
    amount: input.amount,
    claimSigner,
    referrer: input.referrer ? getAddress(input.referrer) : ZERO_ADDRESS,
    cancelLockedUntil: Number(lockBig),
    nonce,
    validAfter,
    validBefore: input.validBefore,
    relayer: input.relayer ? getAddress(input.relayer) : ZERO_ADDRESS,
  };
  const digest = hashTypedData({
    domain,
    types: MINT_PERMIT_V32_TYPES,
    primaryType: 'MintPermit',
    message,
  });
  return { domain, types: MINT_PERMIT_V32_TYPES, primaryType: 'MintPermit', message, digest };
}

export async function signMintPermit(
  signerInput: SlipSignerInput,
  input: Omit<BuildMintPermitInput, 'creator'> & { creator?: Address },
): Promise<{ permit: MintPermitMessage; signature: Hex; digest: Hex; domain: EIP712DomainConfig }> {
  const signer = await toSlipSigner(signerInput);
  const creator = input.creator ? getAddress(input.creator) : await signer.getAddress();
  const td = buildMintPermitTypedData({ ...input, creator });
  const rawSig = await signer.signTypedData({
    domain: td.domain,
    types: td.types,
    primaryType: td.primaryType,
    message: td.message as unknown as Record<string, unknown>,
  });
  const signature = rawSig.length === 132 ? splitSignatureVrs(rawSig).signature : rawSig;
  return { permit: td.message, signature, digest: td.digest, domain: td.domain };
}

export interface BuildCashPermitInput {
  slipId: bigint | number;
  recipient: Address;
  nonce: bigint | number;
  deadline: bigint | number;
  relayer?: Address;
  vault?: VaultTag | Address;
  chainId?: number;
}

export function buildCashPermitTypedData(input: BuildCashPermitInput) {
  const domain = getVaultDomain(input.vault ?? ISSUE_VAULT, input.chainId ?? BASE_CHAIN_ID);
  const message = {
    slipId: BigInt(input.slipId),
    recipient: getAddress(input.recipient),
    relayer: input.relayer ? getAddress(input.relayer) : ZERO_ADDRESS,
    nonce: BigInt(input.nonce),
    deadline: BigInt(input.deadline),
  };
  const digest = hashTypedData({
    domain,
    types: CASH_PERMIT_TYPES,
    primaryType: 'CashPermit',
    message,
  });
  return { domain, types: CASH_PERMIT_TYPES, primaryType: 'CashPermit' as const, message, digest };
}

export async function signCashPermit(signerInput: SlipSignerInput, input: BuildCashPermitInput) {
  const signer = await toSlipSigner(signerInput);
  const td = buildCashPermitTypedData(input);
  const rawSig = await signer.signTypedData({
    domain: td.domain,
    types: td.types,
    primaryType: td.primaryType,
    message: td.message as unknown as Record<string, unknown>,
  });
  const signature = rawSig.length === 132 ? splitSignatureVrs(rawSig).signature : rawSig;
  return { permit: td.message, signature, digest: td.digest, domain: td.domain };
}

export interface BuildAcceptPermitInput {
  slipId: bigint | number;
  newHolder: Address;
  newClaimSigner: Address;
  keepEscrowedInVault?: boolean;
  nonce: bigint | number;
  deadline: bigint | number;
  relayer?: Address;
  vault?: VaultTag | Address;
  chainId?: number;
}

export function buildAcceptPermitTypedData(input: BuildAcceptPermitInput) {
  const domain = getVaultDomain(input.vault ?? ISSUE_VAULT, input.chainId ?? BASE_CHAIN_ID);
  const message = {
    slipId: BigInt(input.slipId),
    newHolder: getAddress(input.newHolder),
    newClaimSigner: getAddress(input.newClaimSigner),
    keepEscrowedInVault: input.keepEscrowedInVault ?? true,
    relayer: input.relayer ? getAddress(input.relayer) : ZERO_ADDRESS,
    nonce: BigInt(input.nonce),
    deadline: BigInt(input.deadline),
  };
  const digest = hashTypedData({
    domain,
    types: ACCEPT_PERMIT_V32_TYPES,
    primaryType: 'AcceptPermit',
    message,
  });
  return {
    domain,
    types: ACCEPT_PERMIT_V32_TYPES,
    primaryType: 'AcceptPermit' as const,
    message,
    digest,
  };
}

export async function signAcceptPermit(
  signerInput: SlipSignerInput,
  input: BuildAcceptPermitInput,
) {
  const signer = await toSlipSigner(signerInput);
  const td = buildAcceptPermitTypedData(input);
  const rawSig = await signer.signTypedData({
    domain: td.domain,
    types: td.types,
    primaryType: td.primaryType,
    message: td.message as unknown as Record<string, unknown>,
  });
  const signature = rawSig.length === 132 ? splitSignatureVrs(rawSig).signature : rawSig;
  return { permit: td.message, signature, digest: td.digest, domain: td.domain };
}

export interface BuildSplitPermitInput {
  slipId: bigint | number;
  paymentAmount: bigint;
  merchant: Address;
  changeReceiver?: Address;
  newChangeSigner?: Address;
  nonce: bigint | number;
  deadline: bigint | number;
  relayer?: Address;
  vault?: VaultTag | Address;
  chainId?: number;
}

export function buildSplitPermitTypedData(input: BuildSplitPermitInput) {
  const domain = getVaultDomain(input.vault ?? ISSUE_VAULT, input.chainId ?? BASE_CHAIN_ID);
  const message = {
    slipId: BigInt(input.slipId),
    paymentAmount: input.paymentAmount,
    merchant: getAddress(input.merchant),
    changeReceiver: input.changeReceiver ? getAddress(input.changeReceiver) : ZERO_ADDRESS,
    newChangeSigner: input.newChangeSigner ? getAddress(input.newChangeSigner) : ZERO_ADDRESS,
    relayer: input.relayer ? getAddress(input.relayer) : ZERO_ADDRESS,
    nonce: BigInt(input.nonce),
    deadline: BigInt(input.deadline),
  };
  const digest = hashTypedData({
    domain,
    types: SPLIT_PERMIT_TYPES,
    primaryType: 'SplitPermit',
    message,
  });
  return { domain, types: SPLIT_PERMIT_TYPES, primaryType: 'SplitPermit' as const, message, digest };
}

export async function signSplitPermit(signerInput: SlipSignerInput, input: BuildSplitPermitInput) {
  const signer = await toSlipSigner(signerInput);
  const td = buildSplitPermitTypedData(input);
  const rawSig = await signer.signTypedData({
    domain: td.domain,
    types: td.types,
    primaryType: td.primaryType,
    message: td.message as unknown as Record<string, unknown>,
  });
  const signature = rawSig.length === 132 ? splitSignatureVrs(rawSig).signature : rawSig;
  return { permit: td.message, signature, digest: td.digest, domain: td.domain };
}

/** Exact `keccak256(abi.encodePacked(slipIds))` matching `CryptoSlipProtocolV32.sol:843`. */
export function computeRearrangeSlipIdsHash(slipIds: readonly (bigint | number)[]): Hex {
  if (slipIds.length === 0 || slipIds.length > 10) {
    throw new Error('Rearrange batch must contain between 1 and 10 slipIds');
  }
  return keccak256(
    encodePacked(
      ['uint256[]'],
      [slipIds.map((id) => BigInt(id))],
    ),
  );
}

export interface BuildRearrangePermitInput {
  slipId: bigint | number;
  slipIds: readonly (bigint | number)[];
  paymentAmount: bigint;
  merchant: Address;
  changeReceiver?: Address;
  newChangeSigner?: Address;
  nonce: bigint | number;
  deadline: bigint | number;
  relayer?: Address;
  vault?: VaultTag | Address;
  chainId?: number;
}

export function buildRearrangePermitTypedData(input: BuildRearrangePermitInput) {
  const domain = getVaultDomain(input.vault ?? ISSUE_VAULT, input.chainId ?? BASE_CHAIN_ID);
  const slipIdsHash = computeRearrangeSlipIdsHash(input.slipIds);
  const message = {
    slipId: BigInt(input.slipId),
    slipIdsHash,
    paymentAmount: input.paymentAmount,
    merchant: getAddress(input.merchant),
    changeReceiver: input.changeReceiver ? getAddress(input.changeReceiver) : ZERO_ADDRESS,
    newChangeSigner: input.newChangeSigner ? getAddress(input.newChangeSigner) : ZERO_ADDRESS,
    relayer: input.relayer ? getAddress(input.relayer) : ZERO_ADDRESS,
    nonce: BigInt(input.nonce),
    deadline: BigInt(input.deadline),
  };
  const digest = hashTypedData({
    domain,
    types: REARRANGE_PERMIT_V32_TYPES,
    primaryType: 'RearrangePermit',
    message,
  });
  return {
    domain,
    types: REARRANGE_PERMIT_V32_TYPES,
    primaryType: 'RearrangePermit' as const,
    message,
    digest,
  };
}

export async function signRearrangePermit(
  signerInput: SlipSignerInput,
  input: BuildRearrangePermitInput,
) {
  const signer = await toSlipSigner(signerInput);
  const td = buildRearrangePermitTypedData(input);
  const rawSig = await signer.signTypedData({
    domain: td.domain,
    types: td.types,
    primaryType: td.primaryType,
    message: td.message as unknown as Record<string, unknown>,
  });
  const signature = rawSig.length === 132 ? splitSignatureVrs(rawSig).signature : rawSig;
  return { permit: td.message, signature, digest: td.digest, domain: td.domain };
}

export interface BuildRefundPermitInput {
  slipId: bigint | number;
  destination: Address;
  nonce: bigint | number;
  deadline: bigint | number;
  relayer?: Address;
  vault?: VaultTag | Address;
  chainId?: number;
}

export function buildRefundPermitTypedData(input: BuildRefundPermitInput) {
  const domain = getVaultDomain(input.vault ?? ISSUE_VAULT, input.chainId ?? BASE_CHAIN_ID);
  const message = {
    slipId: BigInt(input.slipId),
    destination: getAddress(input.destination),
    relayer: input.relayer ? getAddress(input.relayer) : ZERO_ADDRESS,
    nonce: BigInt(input.nonce),
    deadline: BigInt(input.deadline),
  };
  const digest = hashTypedData({
    domain,
    types: REFUND_PERMIT_V32_TYPES,
    primaryType: 'RefundPermit',
    message,
  });
  return {
    domain,
    types: REFUND_PERMIT_V32_TYPES,
    primaryType: 'RefundPermit' as const,
    message,
    digest,
  };
}

export async function signRefundPermit(
  signerInput: SlipSignerInput,
  input: BuildRefundPermitInput,
) {
  const signer = await toSlipSigner(signerInput);
  const td = buildRefundPermitTypedData(input);
  const rawSig = await signer.signTypedData({
    domain: td.domain,
    types: td.types,
    primaryType: td.primaryType,
    message: td.message as unknown as Record<string, unknown>,
  });
  const signature = rawSig.length === 132 ? splitSignatureVrs(rawSig).signature : rawSig;
  return { permit: td.message, signature, digest: td.digest, domain: td.domain };
}

export interface BuildReferralConsentInput {
  recipient: Address;
  slipId: bigint | number;
  referrer: Address;
  deadline: bigint | number;
  vault?: VaultTag | Address;
  chainId?: number;
}

export function buildReferralConsentTypedData(input: BuildReferralConsentInput) {
  const domain = getVaultDomain(input.vault ?? ISSUE_VAULT, input.chainId ?? BASE_CHAIN_ID);
  const message = {
    recipient: getAddress(input.recipient),
    slipId: BigInt(input.slipId),
    referrer: getAddress(input.referrer),
    deadline: BigInt(input.deadline),
  };
  const digest = hashTypedData({
    domain,
    types: REFERRAL_CONSENT_V32_TYPES,
    primaryType: 'ReferralConsent',
    message,
  });
  return {
    domain,
    types: REFERRAL_CONSENT_V32_TYPES,
    primaryType: 'ReferralConsent' as const,
    message,
    digest,
  };
}

export async function signReferralConsent(
  recipientSignerInput: SlipSignerInput,
  input: Omit<BuildReferralConsentInput, 'recipient'> & { recipient?: Address },
) {
  const signer = await toSlipSigner(recipientSignerInput);
  const recipient = input.recipient ? getAddress(input.recipient) : await signer.getAddress();
  const td = buildReferralConsentTypedData({ ...input, recipient });
  const rawSig = await signer.signTypedData({
    domain: td.domain,
    types: td.types,
    primaryType: td.primaryType,
    message: td.message as unknown as Record<string, unknown>,
  });
  const signature = rawSig.length === 132 ? splitSignatureVrs(rawSig).signature : rawSig;
  return { consent: td.message, signature, digest: td.digest, domain: td.domain };
}

// ---- TradeRouter Permits (`SwapOfferPermit`, `SwapAndPayPermit`, `CompositeSwapOfferPermit`, `TradeOfferPermit`) ----

export interface BuildSwapOfferPermitInput {
  slipId: bigint | number;
  swapAmount: bigint;
  outAsset: Address;
  minAmountOut: bigint;
  newOutputSigner: Address;
  outputCancelLockedUntil?: bigint | number;
  swapTarget: Address;
  swapData: Hex;
  nonce: bigint | number;
  deadline: bigint | number;
  relayer?: Address;
  router?: 'v33' | 'v32' | Address;
  chainId?: number;
}

export function buildSwapOfferPermitTypedData(input: BuildSwapOfferPermitInput) {
  const lockBig = assertValidCancelLock(input.outputCancelLockedUntil);
  const domain = getTradeRouterDomain(input.router ?? 'v33', input.chainId ?? BASE_CHAIN_ID);
  const message = {
    slipId: BigInt(input.slipId),
    swapAmount: input.swapAmount,
    outAsset: getAddress(input.outAsset),
    minAmountOut: input.minAmountOut,
    newOutputSigner: getAddress(input.newOutputSigner),
    outputCancelLockedUntil: Number(lockBig),
    swapTarget: getAddress(input.swapTarget),
    swapDataHash: keccak256(input.swapData),
    relayer: input.relayer ? getAddress(input.relayer) : ZERO_ADDRESS,
    nonce: BigInt(input.nonce),
    deadline: BigInt(input.deadline),
  };
  const digest = hashTypedData({
    domain,
    types: SWAP_OFFER_V32_TYPES,
    primaryType: 'SwapOfferPermit',
    message,
  });
  return {
    domain,
    types: SWAP_OFFER_V32_TYPES,
    primaryType: 'SwapOfferPermit' as const,
    message,
    digest,
  };
}

export async function signSwapOfferPermit(
  signerInput: SlipSignerInput,
  input: BuildSwapOfferPermitInput,
) {
  const signer = await toSlipSigner(signerInput);
  const td = buildSwapOfferPermitTypedData(input);
  const rawSig = await signer.signTypedData({
    domain: td.domain,
    types: td.types,
    primaryType: td.primaryType,
    message: td.message as unknown as Record<string, unknown>,
  });
  const signature = rawSig.length === 132 ? splitSignatureVrs(rawSig).signature : rawSig;
  return { permit: td.message, signature, digest: td.digest, domain: td.domain };
}

export const signSwapPermit = signSwapOfferPermit;

export interface BuildSwapAndPayPermitInput {
  slipId: bigint | number;
  swapAmount: bigint;
  merchant: Address;
  outAsset: Address;
  minAmountOut: bigint;
  swapTarget: Address;
  swapData: Hex;
  nonce: bigint | number;
  deadline: bigint | number;
  relayer?: Address;
  router?: 'v33' | 'v32' | Address;
  chainId?: number;
}

export function buildSwapAndPayPermitTypedData(input: BuildSwapAndPayPermitInput) {
  const domain = getTradeRouterDomain(input.router ?? 'v33', input.chainId ?? BASE_CHAIN_ID);
  const message = {
    slipId: BigInt(input.slipId),
    swapAmount: input.swapAmount,
    merchant: getAddress(input.merchant),
    outAsset: getAddress(input.outAsset),
    minAmountOut: input.minAmountOut,
    swapTarget: getAddress(input.swapTarget),
    swapDataHash: keccak256(input.swapData),
    relayer: input.relayer ? getAddress(input.relayer) : ZERO_ADDRESS,
    nonce: BigInt(input.nonce),
    deadline: BigInt(input.deadline),
  };
  const digest = hashTypedData({
    domain,
    types: SWAP_AND_PAY_V32_TYPES,
    primaryType: 'SwapAndPayPermit',
    message,
  });
  return {
    domain,
    types: SWAP_AND_PAY_V32_TYPES,
    primaryType: 'SwapAndPayPermit' as const,
    message,
    digest,
  };
}

export async function signSwapAndPayPermit(
  signerInput: SlipSignerInput,
  input: BuildSwapAndPayPermitInput,
) {
  const signer = await toSlipSigner(signerInput);
  const td = buildSwapAndPayPermitTypedData(input);
  const rawSig = await signer.signTypedData({
    domain: td.domain,
    types: td.types,
    primaryType: td.primaryType,
    message: td.message as unknown as Record<string, unknown>,
  });
  const signature = rawSig.length === 132 ? splitSignatureVrs(rawSig).signature : rawSig;
  return { permit: td.message, signature, digest: td.digest, domain: td.domain };
}

export interface BuildCompositeSwapOfferPermitInput {
  slipId: bigint | number;
  swapAmount: bigint;
  midAsset: Address;
  outAsset: Address;
  leg2AmountIn: bigint;
  minAmountOut: bigint;
  newOutputSigner: Address;
  outputCancelLockedUntil?: bigint | number;
  swapTarget1: Address;
  swapData1: Hex;
  swapTarget2: Address;
  swapData2: Hex;
  nonce: bigint | number;
  deadline: bigint | number;
  relayer?: Address;
  router?: 'v33' | 'v32' | Address;
  chainId?: number;
}

export function buildCompositeSwapOfferPermitTypedData(input: BuildCompositeSwapOfferPermitInput) {
  const lockBig = assertValidCancelLock(input.outputCancelLockedUntil);
  const domain = getTradeRouterDomain(input.router ?? 'v33', input.chainId ?? BASE_CHAIN_ID);
  const message = {
    slipId: BigInt(input.slipId),
    swapAmount: input.swapAmount,
    midAsset: getAddress(input.midAsset),
    outAsset: getAddress(input.outAsset),
    leg2AmountIn: input.leg2AmountIn,
    minAmountOut: input.minAmountOut,
    newOutputSigner: getAddress(input.newOutputSigner),
    outputCancelLockedUntil: Number(lockBig),
    swapTarget1: getAddress(input.swapTarget1),
    swapData1Hash: keccak256(input.swapData1),
    swapTarget2: getAddress(input.swapTarget2),
    swapData2Hash: keccak256(input.swapData2),
    relayer: input.relayer ? getAddress(input.relayer) : ZERO_ADDRESS,
    nonce: BigInt(input.nonce),
    deadline: BigInt(input.deadline),
  };
  const digest = hashTypedData({
    domain,
    types: COMPOSITE_SWAP_OFFER_V32_TYPES,
    primaryType: 'CompositeSwapOfferPermit',
    message,
  });
  return {
    domain,
    types: COMPOSITE_SWAP_OFFER_V32_TYPES,
    primaryType: 'CompositeSwapOfferPermit' as const,
    message,
    digest,
  };
}

export async function signCompositeSwapOfferPermit(
  signerInput: SlipSignerInput,
  input: BuildCompositeSwapOfferPermitInput,
) {
  const signer = await toSlipSigner(signerInput);
  const td = buildCompositeSwapOfferPermitTypedData(input);
  const rawSig = await signer.signTypedData({
    domain: td.domain,
    types: td.types,
    primaryType: td.primaryType,
    message: td.message as unknown as Record<string, unknown>,
  });
  const signature = rawSig.length === 132 ? splitSignatureVrs(rawSig).signature : rawSig;
  return { permit: td.message, signature, digest: td.digest, domain: td.domain };
}

export interface BuildTradeOfferPermitInput {
  mySlipId: bigint | number;
  counterpartySlipId: bigint | number;
  myNewClaimSigner: Address;
  nonce: bigint | number;
  deadline: bigint | number;
  relayer?: Address;
  router?: 'v33' | 'v32' | Address;
  chainId?: number;
}

export function buildTradeOfferPermitTypedData(input: BuildTradeOfferPermitInput) {
  if (BigInt(input.mySlipId) === BigInt(input.counterpartySlipId)) {
    throw new Error('TradeOfferPermit requires distinct mySlipId and counterpartySlipId');
  }
  const domain = getTradeRouterDomain(input.router ?? 'v33', input.chainId ?? BASE_CHAIN_ID);
  const message = {
    mySlipId: BigInt(input.mySlipId),
    counterpartySlipId: BigInt(input.counterpartySlipId),
    myNewClaimSigner: getAddress(input.myNewClaimSigner),
    relayer: input.relayer ? getAddress(input.relayer) : ZERO_ADDRESS,
    nonce: BigInt(input.nonce),
    deadline: BigInt(input.deadline),
  };
  const digest = hashTypedData({
    domain,
    types: TRADE_OFFER_V32_TYPES,
    primaryType: 'TradeOfferPermit',
    message,
  });
  return {
    domain,
    types: TRADE_OFFER_V32_TYPES,
    primaryType: 'TradeOfferPermit' as const,
    message,
    digest,
  };
}

export async function signTradeOfferPermit(
  signerInput: SlipSignerInput,
  input: BuildTradeOfferPermitInput,
) {
  const signer = await toSlipSigner(signerInput);
  const td = buildTradeOfferPermitTypedData(input);
  const rawSig = await signer.signTypedData({
    domain: td.domain,
    types: td.types,
    primaryType: td.primaryType,
    message: td.message as unknown as Record<string, unknown>,
  });
  const signature = rawSig.length === 132 ? splitSignatureVrs(rawSig).signature : rawSig;
  return { permit: td.message, signature, digest: td.digest, domain: td.domain };
}

// ============================================================================
// EIP-3009 (`ReceiveWithAuthorization` / `TransferWithAuthorization`) & EIP-2612 (`Permit`)
// ============================================================================

export interface SignedEip3009Authorization {
  from: Address;
  to: Address;
  value: bigint;
  validAfter: bigint;
  validBefore: bigint;
  nonce: Hex;
  v: 27 | 28;
  r: Hex;
  s: Hex;
  signature: Hex;
  digest: Hex;
  domain: EIP712DomainConfig;
}

export async function signReceiveWithAuthorization(
  signerInput: SlipSignerInput,
  input: {
    token: 'USDC' | 'cbBTC' | 'BTC' | Address;
    from?: Address;
    to?: Address;
    value: bigint;
    validAfter?: bigint;
    validBefore: bigint;
    nonce?: Hex;
    domainOverride?: EIP712DomainConfig;
  },
): Promise<SignedEip3009Authorization> {
  const signer = await toSlipSigner(signerInput);
  const from = input.from ? getAddress(input.from) : await signer.getAddress();
  const to = input.to ? getAddress(input.to) : vaultAddress(ISSUE_VAULT);
  const validAfter = input.validAfter ?? 0n;
  if (input.validBefore <= validAfter) {
    throw new Error('EIP-3009 validBefore must be strictly greater than validAfter');
  }
  const nonce = input.nonce ?? randomPermitNonce();
  const domain = input.domainOverride ?? getEip3009DomainForToken(input.token);
  const message = {
    from,
    to,
    value: input.value,
    validAfter,
    validBefore: input.validBefore,
    nonce,
  };
  const digest = hashTypedData({
    domain,
    types: RECEIVE_WITH_AUTHORIZATION_TYPES,
    primaryType: 'ReceiveWithAuthorization',
    message,
  });
  const rawSig = await signer.signTypedData({
    domain,
    types: RECEIVE_WITH_AUTHORIZATION_TYPES,
    primaryType: 'ReceiveWithAuthorization',
    message: message as unknown as Record<string, unknown>,
  });
  if (rawSig.length === 132) {
    const { v, r, s, signature } = splitSignatureVrs(rawSig);
    return { ...message, v, r, s, signature, digest, domain };
  }
  return {
    ...message,
    v: 27,
    r: ('0x' + '00'.repeat(32)) as Hex,
    s: ('0x' + '00'.repeat(32)) as Hex,
    signature: rawSig,
    digest,
    domain,
  };
}

export async function signTransferWithAuthorization(
  signerInput: SlipSignerInput,
  input: {
    token: 'USDC' | 'cbBTC' | 'BTC' | Address;
    from?: Address;
    to: Address;
    value: bigint;
    validAfter?: bigint;
    validBefore: bigint;
    nonce?: Hex;
    domainOverride?: EIP712DomainConfig;
  },
): Promise<SignedEip3009Authorization> {
  const signer = await toSlipSigner(signerInput);
  const from = input.from ? getAddress(input.from) : await signer.getAddress();
  const to = getAddress(input.to);
  const validAfter = input.validAfter ?? 0n;
  const nonce = input.nonce ?? randomPermitNonce();
  const domain = input.domainOverride ?? getEip3009DomainForToken(input.token);
  const message = {
    from,
    to,
    value: input.value,
    validAfter,
    validBefore: input.validBefore,
    nonce,
  };
  const digest = hashTypedData({
    domain,
    types: TRANSFER_WITH_AUTHORIZATION_TYPES,
    primaryType: 'TransferWithAuthorization',
    message,
  });
  const rawSig = await signer.signTypedData({
    domain,
    types: TRANSFER_WITH_AUTHORIZATION_TYPES,
    primaryType: 'TransferWithAuthorization',
    message: message as unknown as Record<string, unknown>,
  });
  const { v, r, s, signature } = splitSignatureVrs(rawSig);
  return { ...message, v, r, s, signature, digest, domain };
}

export interface SignedErc2612Permit {
  owner: Address;
  spender: Address;
  value: bigint;
  nonce: bigint;
  deadline: bigint;
  v: 27 | 28;
  r: Hex;
  s: Hex;
  signature: Hex;
  digest: Hex;
  domain: EIP712DomainConfig;
}

/**
 * Signs an EIP-2612 `Permit` for `NARA` (`name: "NARA Token", version: "1"`) or `USDC` (`version: "2"`).
 */
export async function signErc2612Permit(
  signerInput: SlipSignerInput,
  input: {
    token?: 'NARA' | 'USDC' | 'cbBTC' | Address;
    owner?: Address;
    spender?: Address;
    value: bigint;
    nonce: bigint | number;
    deadline: bigint | number;
    domainOverride?: EIP712DomainConfig;
  },
): Promise<SignedErc2612Permit> {
  const signer = await toSlipSigner(signerInput);
  const owner = input.owner ? getAddress(input.owner) : await signer.getAddress();
  const spender = input.spender ? getAddress(input.spender) : vaultAddress(ISSUE_VAULT);
  const domain = input.domainOverride ?? getErc2612DomainForToken(input.token ?? 'NARA');
  const message = {
    owner,
    spender,
    value: input.value,
    nonce: BigInt(input.nonce),
    deadline: BigInt(input.deadline),
  };
  const digest = hashTypedData({
    domain,
    types: ERC20_PERMIT_TYPES,
    primaryType: 'Permit',
    message,
  });
  const rawSig = await signer.signTypedData({
    domain,
    types: ERC20_PERMIT_TYPES,
    primaryType: 'Permit',
    message: message as unknown as Record<string, unknown>,
  });
  const { v, r, s, signature } = splitSignatureVrs(rawSig);
  return { ...message, v, r, s, signature, digest, domain };
}

export const signNaraPermit = signErc2612Permit;

/**
 * Signs a paired `(MintPermit, ReceiveWithAuthorization)` bundle for `vault.mintSlipERC20WithAuthorization`
 * sharing the exact same `nonce`, `validAfter = 0n`, `validBefore`, `creator`, and `amount`.
 */
export async function signPairedEip3009Mint(
  creatorSignerInput: SlipSignerInput,
  input: {
    token: 'USDC' | 'cbBTC' | 'BTC' | Address;
    amount: bigint;
    claimSigner: Address;
    referrer?: Address;
    cancelLockedUntil?: bigint | number;
    validBefore: bigint;
    nonce?: Hex;
    relayer?: Address;
    vault?: VaultTag | Address;
    chainId?: number;
  },
) {
  const signer = await toSlipSigner(creatorSignerInput);
  const creator = await signer.getAddress();
  const tokenDomain = getEip3009DomainForToken(input.token);
  const vaultDomain = getVaultDomain(input.vault ?? ISSUE_VAULT, input.chainId ?? BASE_CHAIN_ID);
  const nonce = input.nonce ?? randomPermitNonce();

  const [mintSigned, receiveSigned] = await Promise.all([
    signMintPermit(signer, {
      creator,
      token: tokenDomain.verifyingContract,
      amount: input.amount,
      claimSigner: input.claimSigner,
      referrer: input.referrer,
      cancelLockedUntil: input.cancelLockedUntil,
      nonce,
      validAfter: 0n,
      validBefore: input.validBefore,
      relayer: input.relayer,
      vault: vaultDomain.verifyingContract,
      chainId: vaultDomain.chainId,
    }),
    signReceiveWithAuthorization(signer, {
      token: tokenDomain.verifyingContract,
      from: creator,
      to: vaultDomain.verifyingContract,
      value: input.amount,
      validAfter: 0n,
      validBefore: input.validBefore,
      nonce,
      domainOverride: tokenDomain,
    }),
  ]);

  return {
    mintPermit: mintSigned.permit,
    mintSignature: mintSigned.signature,
    receiveAuthorization: receiveSigned,
    nonce,
  };
}

// ============================================================================
// Deterministic Ephemeral Key Derivation (`client/src/lib/keptSlipRecovery.ts` Byte Parity)
// ============================================================================

const SCOPED_KEY_PARAMS = parseAbiParameters('string, uint256, address, uint256, uint256');

function normalizePrivateKeyBytes(walletPrivateKey: Hex | string): Uint8Array {
  const clean = (walletPrivateKey || '').trim().replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]{64}$/.test(clean)) {
    throw new Error('Invalid wallet private key for deterministic slip recovery');
  }
  const scalar = BigInt(`0x${clean}`);
  if (scalar <= 0n || scalar >= SECP256K1_ORDER) {
    throw new Error('Wallet private key scalar out of secp256k1 range');
  }
  return hexToBytes(`0x${clean.toLowerCase()}` as Hex);
}

function deriveScopedSlipKey(
  purpose: string,
  walletPrivateKey: Hex | string,
  vault: VaultTag,
  indexStr: string,
  errLabel: string,
): Hex {
  const vaultAddr = getAddress(VAULTS[vault].address);
  const secretBytes = normalizePrivateKeyBytes(walletPrivateKey);
  try {
    if (!/^\d+$/.test(indexStr)) throw new Error(errLabel);
    const id = BigInt(indexStr);
    if (id <= 0n || id >= 1n << 256n) throw new Error(errLabel);

    for (let counter = 0; counter < 256; counter++) {
      const encoded = encodeAbiParameters(SCOPED_KEY_PARAMS, [
        purpose,
        BigInt(BASE_CHAIN_ID),
        vaultAddr,
        id,
        BigInt(counter),
      ]);
      const mac = hmac(sha256, secretBytes, hexToBytes(encoded));
      const scalar = bytesToBigInt(mac);
      if (scalar > 0n && scalar < SECP256K1_ORDER) {
        return bytesToHex(mac);
      }
    }
    throw new Error('Could not prepare recoverable slip key');
  } finally {
    secretBytes.fill(0);
  }
}

export function deriveKeptSlipKey(
  walletPrivateKey: Hex | string,
  vault: VaultTag,
  parentId: string | bigint | number,
): Hex {
  return deriveScopedSlipKey(
    KEPT_RECOVERY_PURPOSE,
    walletPrivateKey,
    vault,
    String(parentId),
    'Invalid original slip number.',
  );
}

/**
 * Deterministically derives the N-th hop key (`0..4`) for an in-place kept slip.
 * Byte-for-byte identical to `client/src/lib/keptSlipRecovery.ts:deriveKeptSlipHopKey`.
 */
export function deriveKeptSlipHopKey(
  walletPrivateKey: Hex | string,
  vault: VaultTag,
  parentId: string | bigint | number,
  hop: number,
): Hex {
  if (!Number.isInteger(hop) || hop < 0 || hop >= MAX_KEPT_SLIP_HOPS) {
    throw new Error('Invalid kept slip hop index.');
  }
  if (hop === 0) return deriveKeptSlipKey(walletPrivateKey, vault, parentId);
  return deriveScopedSlipKey(
    `${KEPT_RECOVERY_PURPOSE}/hop-${hop}`,
    walletPrivateKey,
    vault,
    String(parentId),
    'Invalid original slip number.',
  );
}

export function deriveSplitChangeSlipKey(
  walletPrivateKey: Hex | string,
  vault: VaultTag,
  parentId: string | bigint | number,
): Hex {
  return deriveScopedSlipKey(
    SPLIT_CHANGE_RECOVERY_PURPOSE,
    walletPrivateKey,
    vault,
    String(parentId),
    'Invalid original slip number.',
  );
}

export function deriveCreatedSlipKey(
  walletPrivateKey: Hex | string,
  vault: VaultTag,
  slotIndex: string | bigint | number,
): Hex {
  return deriveScopedSlipKey(
    CREATED_RECOVERY_PURPOSE,
    walletPrivateKey,
    vault,
    String(slotIndex),
    'Invalid created slip slot.',
  );
}

function normalizeIdentifierToAddressLower(value?: string): string {
  const trimmed = (value || '').trim();
  if (!trimmed) return '';
  if (/^(?:0x)?[0-9a-fA-F]{64}$/.test(trimmed)) {
    const pk = `0x${trimmed.replace(/^0x/i, '')}` as Hex;
    try {
      return privateKeyToAddress(pk).toLowerCase();
    } catch {
      return '';
    }
  }
  return trimmed.toLowerCase();
}

/**
 * Picks the next deterministic kept-slip key for `slipId` that does NOT collide with
 * `currentClaimSigner`, the wallet's own address, or any address/key in `forbiddenAddresses`.
 * Byte-for-byte identical to `client/src/lib/keptSlipRecovery.ts:deriveNextSlipHolderKey`.
 */
export function deriveNextSlipHolderKey(
  walletPrivateKey: Hex | string,
  vault: VaultTag,
  slipId: string | bigint | number,
  currentClaimSigner?: string,
  forbiddenAddresses: Iterable<string> = [],
): Hex {
  const cleanWalletPk = `0x${String(walletPrivateKey).trim().replace(/^0x/i, '').toLowerCase()}` as Hex;
  const walletAddress = privateKeyToAddress(cleanWalletPk);
  const currentLower = normalizeIdentifierToAddressLower(currentClaimSigner);
  const forbidden = new Set<string>([walletAddress.toLowerCase()]);
  if (currentLower) forbidden.add(currentLower);
  for (const item of forbiddenAddresses) {
    const norm = normalizeIdentifierToAddressLower(item);
    if (norm) forbidden.add(norm);
  }

  const slipIdStr = String(slipId);
  let startHop = 0;
  if (currentLower) {
    for (let h = 0; h < MAX_KEPT_SLIP_HOPS; h++) {
      const candidate = deriveKeptSlipHopKey(cleanWalletPk, vault, slipIdStr, h);
      if (privateKeyToAddress(candidate).toLowerCase() === currentLower) {
        startHop = h + 1;
        break;
      }
    }
  }

  for (let hop = startHop; hop < MAX_KEPT_SLIP_HOPS; hop++) {
    const candidate = deriveKeptSlipHopKey(cleanWalletPk, vault, slipIdStr, hop);
    if (!forbidden.has(privateKeyToAddress(candidate).toLowerCase())) {
      return candidate;
    }
  }

  const fallback = deriveSplitChangeSlipKey(cleanWalletPk, vault, slipIdStr);
  if (!forbidden.has(privateKeyToAddress(fallback).toLowerCase())) {
    return fallback;
  }

  throw new Error(
    'Maximum consecutive re-keeps reached for this slip. Claim it to your wallet or split into a new slip.',
  );
}
