import { randomBytes } from 'node:crypto';
import {
  bytesToBigInt,
  bytesToHex,
  decodeAbiParameters,
  decodeEventLog,
  decodeFunctionData,
  encodeFunctionData,
  getAddress,
  isAddress,
  parseAbi,
  parseAbiParameters,
  type Address,
  type Hex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { CRYPTO_SLIP_VAULT_V32_ABI } from './abi.js';
import {
  appendBuilderCodeSuffix,
  assetAddress,
  BLOCKED_PAYMENT_TARGETS,
  CBBTC_BASE_ADDRESS,
  computeProtocolFeeCeiling,
  DEFAULT_CRYPTOSLIP_BUILDER_CODE,
  ISSUE_VAULT,
  isV32ProtocolVault,
  MAX_COMBINE_SLIPS,
  minSlipAmount,
  MULTICALL3_ADDRESS,
  NARA_BASE_ADDRESS,
  NARA_LIQUIDITY_HOOK_V5_ADDRESS,
  normalizeSdkAsset,
  resolveAssetMetadata,
  SlipStatus,
  TREASURY_SAFE_ADDRESS,
  UNIVERSAL_ROUTER_ADDRESS,
  USDC_BASE_ADDRESS,
  vaultAddress,
  WETH_BASE_ADDRESS,
  ZERO_ADDRESS,
  type AnyAssetSymbol,
  type SdkAssetSymbol,
  type SlipStatusCode,
  type VaultTag,
} from './constants.js';
import {
  encodeSimple7702Calls,
  executeGaslessTransport,
  executeViaCircleUsdcPaymaster,
  type BaseCompatiblePublicClient,
  type BaseCompatibleWalletClient,
  type BundlerFetchFn,
  type GaslessTransportMode,
  type GaslessTransportTier,
  type RelayGatewayClient,
  type UserOpCall,
} from './paymaster.js';

export type { BaseCompatiblePublicClient, BaseCompatibleWalletClient } from './paymaster.js';
import {
  computePermitDeadline,
  deriveNextSlipHolderKey,
  deriveSplitChangeSlipKey,
  packPermitWithReferralConsent,
  signAcceptPermit,
  signCashPermit,
  signRearrangePermit,
  signReferralConsent,
  signSplitPermit,
  toSlipSigner,
  type SlipSignerInput,
} from './permits.js';

const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

// ============================================================================
// Typed Protocol & Frontier Defense Errors (`V-03`, `V-05`, Hard Invariant #1)
// ============================================================================

export class SlipOperationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SlipOperationError';
  }
}

/**
 * Thrown by `V-03` sub-minimum dust-cliff pre-check when `0n < slipAmount - paymentAmount < minSlipAmount(asset)`,
 * which would revert on-chain with `BelowMinimum()` (`CryptoSlipProtocolV32.sol:1269-1273, 1549`).
 */
export class DustCliffError extends Error {
  readonly slipAmount: bigint;
  readonly paymentAmount: bigint;
  readonly remainder: bigint;
  readonly minRequiredChange: bigint;
  readonly maxValidPartialPayment: bigint;
  readonly asset: SdkAssetSymbol;
  readonly vault: VaultTag;
  readonly suggestion: string;

  constructor(params: {
    slipAmount: bigint;
    paymentAmount: bigint;
    remainder: bigint;
    minRequiredChange: bigint;
    asset: SdkAssetSymbol;
    vault: VaultTag;
  }) {
    const maxPartial =
      params.slipAmount > params.minRequiredChange
        ? params.slipAmount - params.minRequiredChange
        : 0n;
    const suggestion =
      maxPartial >= params.minRequiredChange
        ? `Reduce paymentAmount to <= ${maxPartial.toString()} raw ${params.asset} (leaving >= ${params.minRequiredChange.toString()} change), spend the full ${params.slipAmount.toString()} slip, or set allowFullCashOnDust: true within tolerance.`
        : `Slip (${params.slipAmount.toString()} raw ${params.asset}) cannot leave valid change >= ${params.minRequiredChange.toString()}; spend the full slip or set allowFullCashOnDust: true.`;

    super(
      `V-03 Dust cliff blocked: splitting ${params.paymentAmount.toString()} from ${params.slipAmount.toString()} ${params.asset} leaves ${params.remainder.toString()} remainder, below ${params.vault} minimum (${params.minRequiredChange.toString()}). ${suggestion}`,
    );
    this.name = 'DustCliffError';
    this.slipAmount = params.slipAmount;
    this.paymentAmount = params.paymentAmount;
    this.remainder = params.remainder;
    this.minRequiredChange = params.minRequiredChange;
    this.maxValidPartialPayment = maxPartial;
    this.asset = params.asset;
    this.vault = params.vault;
    this.suggestion = suggestion;
  }
}

/**
 * Thrown when `UniversalRouter` swap calldata violates Hard Invariant #1 (`100% NARALiquidityHookV5`
 * `0x07d8F2Dfd121B10dE3176DeAb6A8C0eaa2646aCC` routing for all `NARA` swap legs).
 */
export class NonCanonicalNaraSwapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NonCanonicalNaraSwapError';
  }
}

// ============================================================================
// `V-03` Per-Slip FIFO Async Mutex Queue
// ============================================================================

/**
 * Per-`slipId` FIFO async mutex (`V-03` defense) preventing concurrent `splitAndPay`,
 * `keepSlip`, `claimSlip`, or `combineSlips` operations on the same slip from racing nonces
 * and reverting with `InvalidSlipStatus()` or `InvalidSignature()`.
 */
export class SlipMutex {
  private readonly tails = new Map<string, Promise<void>>();
  private readonly counts = new Map<string, number>();

  static keyFor(vaultOrAddress: VaultTag | Address, slipId: bigint | number | string): string {
    const vAddr =
      vaultOrAddress === 'v33' ||
      vaultOrAddress === 'v32' ||
      vaultOrAddress === 'v3' ||
      vaultOrAddress === 'v2'
        ? vaultAddress(vaultOrAddress).toLowerCase()
        : String(vaultOrAddress).toLowerCase();
    return `${vAddr}:${BigInt(slipId).toString()}`;
  }

  isLocked(key: string): boolean {
    return (this.counts.get(key) ?? 0) > 0;
  }

  pendingCount(key: string): number {
    return this.counts.get(key) ?? 0;
  }

  async runExclusive<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.tails.get(key) ?? Promise.resolve();
    this.counts.set(key, (this.counts.get(key) ?? 0) + 1);

    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const nextTail = prev.then(() => gate);
    this.tails.set(key, nextTail);

    await prev;
    try {
      return await fn();
    } finally {
      const remaining = (this.counts.get(key) ?? 1) - 1;
      if (remaining <= 0) {
        this.counts.delete(key);
        if (this.tails.get(key) === nextTail) {
          this.tails.delete(key);
        }
      } else {
        this.counts.set(key, remaining);
      }
      release();
    }
  }

  /**
   * Acquires locks across multiple slip keys in deterministic sorted order so concurrent
   * overlapping `combineSlips` batches can never deadlock.
   */
  async runExclusiveMulti<T>(keys: readonly string[], fn: () => Promise<T>): Promise<T> {
    const sortedUnique = [...new Set(keys)].sort();
    const acquireAt = async (idx: number): Promise<T> => {
      const key = sortedUnique[idx];
      if (!key) return fn();
      return this.runExclusive(key, () => acquireAt(idx + 1));
    };
    return acquireAt(0);
  }
}

export const defaultSlipMutex = new SlipMutex();

// ============================================================================
// On-Chain Slip Reader & Ephemeral Key Helpers
// ============================================================================

export interface OnChainSlipRecord {
  readonly vault: VaultTag;
  readonly vaultAddress: Address;
  readonly slipId: bigint;
  readonly asset: SdkAssetSymbol;
  readonly assetAddress: Address;
  readonly amount: bigint;
  readonly createdAt: number;
  readonly cancelLockedUntil: bigint;
  readonly creator: Address;
  readonly claimSigner: Address;
  readonly refundBeneficiary: Address;
  readonly refundFeeRequired: boolean;
  readonly nonce: bigint;
  readonly status: SlipStatusCode;
}

export async function readOnChainSlip(params: {
  publicClient: BaseCompatiblePublicClient;
  slipId: bigint | number | string;
  vault?: VaultTag;
}): Promise<OnChainSlipRecord> {
  const { publicClient, vault = ISSUE_VAULT } = params;
  const slipId = BigInt(params.slipId);
  if (slipId <= 0n) throw new SlipOperationError('slipId must be positive.');
  const vAddr = vaultAddress(vault);

  const [slipTuple, nonce, rawBeneficiary, refundFeeReq] = await Promise.all([
    publicClient.readContract({
      address: vAddr,
      abi: CRYPTO_SLIP_VAULT_V32_ABI,
      functionName: 'slips',
      args: [slipId],
    }),
    publicClient.readContract({
      address: vAddr,
      abi: CRYPTO_SLIP_VAULT_V32_ABI,
      functionName: 'nonces',
      args: [slipId],
    }),
    publicClient
      .readContract({
        address: vAddr,
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        functionName: 'refundBeneficiary',
        args: [slipId],
      })
      .catch(() => ZERO_ADDRESS),
    publicClient
      .readContract({
        address: vAddr,
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        functionName: 'refundFeeRequired',
        args: [slipId],
      })
      .catch(() => false),
  ]);

  const rawAssetAddr = getAddress(slipTuple[0]);
  const amount = slipTuple[1];
  const createdAt = Number(slipTuple[2]);
  const cancelLockedUntil = BigInt(slipTuple[3]);
  const creator = getAddress(slipTuple[4]);
  const claimSigner = getAddress(slipTuple[5]);
  const status = Number(slipTuple[6]) as SlipStatusCode;

  const assetMeta =
    status === SlipStatus.NONE && rawAssetAddr === ZERO_ADDRESS
      ? resolveAssetMetadata('ETH')
      : resolveAssetMetadata(rawAssetAddr);

  const beneficiary =
    rawBeneficiary && rawBeneficiary.toLowerCase() !== ZERO_ADDRESS
      ? getAddress(rawBeneficiary)
      : creator;

  return {
    vault,
    vaultAddress: vAddr,
    slipId,
    asset: assetMeta.symbol,
    assetAddress: rawAssetAddr,
    amount,
    createdAt,
    cancelLockedUntil,
    creator,
    claimSigner,
    refundBeneficiary: beneficiary,
    refundFeeRequired: Boolean(refundFeeReq),
    nonce,
    status,
  };
}

function generateFreshNonCollidingKey(forbiddenAddresses: Iterable<string>): {
  privateKey: Hex;
  address: Address;
} {
  const forbidden = new Set<string>(BLOCKED_PAYMENT_TARGETS);
  for (const item of forbiddenAddresses) {
    if (item) forbidden.add(item.toLowerCase());
  }
  for (let i = 0; i < 64; i++) {
    const raw = randomBytes(32);
    const scalar = bytesToBigInt(raw);
    if (scalar <= 0n || scalar >= SECP256K1_ORDER) continue;
    const privateKey = bytesToHex(raw);
    const address = getAddress(privateKeyToAccount(privateKey).address);
    if (!forbidden.has(address.toLowerCase())) {
      return { privateKey, address };
    }
  }
  throw new SlipOperationError('Failed to generate non-colliding secp256k1 ephemeral key.');
}

async function resolveChainHeadTimestamp(
  publicClient: BaseCompatiblePublicClient,
  overrideSec?: bigint | number,
): Promise<bigint> {
  if (overrideSec !== undefined) return BigInt(overrideSec);
  try {
    const blk = await publicClient.getBlock({ blockTag: 'latest' });
    const wall = BigInt(Math.floor(Date.now() / 1000));
    return blk.timestamp > wall ? blk.timestamp : wall;
  } catch {
    return BigInt(Math.floor(Date.now() / 1000));
  }
}

function estimateAssetUsdMicro(amount: bigint, asset: SdkAssetSymbol): bigint {
  if (amount <= 0n) return 0n;
  if (asset === 'USDC') return amount;
  if (asset === 'cbBTC') return (amount * 50_000_000_000n + 99_999_999n) / 100_000_000n;
  if (asset === 'ETH') return (amount * 2_500_000_000n + 10n ** 18n - 1n) / 10n ** 18n;
  return (amount * 1_000_000n + 10n ** 18n - 1n) / 10n ** 18n;
}

export interface SharedTransportExecutionOptions {
  mode?: GaslessTransportMode;
  telegramInitData?: string;
  partnerKey?: string;
  relayClient?: RelayGatewayClient;
  paymasterSignerKey?: Hex;
  bundlerUrls?: readonly string[];
  bundlerFetch?: BundlerFetchFn;
  walletClient?: BaseCompatibleWalletClient;
  directBroadcast?: (call: UserOpCall) => Promise<Hex>;
  allowHumanRelayInAgentMode?: boolean;
  onStatus?: (msg: string) => void;
}

// ============================================================================
// 1. `keepSlip()` — Shielded 1:1 Vault Keep (`acceptWithPermit`)
// ============================================================================

export interface KeepSlipOptions extends SharedTransportExecutionOptions {
  publicClient: BaseCompatiblePublicClient;
  slipId: bigint | number | string;
  claimSigner: SlipSignerInput;
  vault?: VaultTag;
  /** Optional master wallet key to deterministically derive `deriveNextSlipHolderKey`. */
  recoveryMasterKey?: Hex;
  /** Optional explicit fresh ephemeral private key (`0x` + 64 hex). */
  newClaimPrivateKey?: Hex;
  /** Optional user's main wallet address so the rotated ephemeral key is guaranteed distinct from it. */
  userMainWallet?: Address;
  /** Marks this rotation as `V-01` MCP boot rotation (`boot_keep` permitted on Edge Relay before agent holds USDC/ETH). */
  isBootKeep?: boolean;
  /** Defaults to `false` (`V-07`: `Claim` binds `userMainWallet`, while `Keep` binds `freshEphemeralAddress`). */
  bindReferrerOnKeep?: boolean;
  chainTimestampSec?: bigint | number;
  ttlSeconds?: number;
  mutex?: SlipMutex;
  /** Invoked with `{ slipId, newClaimPrivateKey, newClaimSigner }` BEFORE any network transmission. */
  onBeforeBroadcast?: (rotated: {
    slipId: bigint;
    vault: VaultTag;
    newClaimPrivateKey: Hex;
    newClaimSigner: Address;
  }) => Promise<void> | void;
}

export interface KeepSlipResult {
  readonly txHash: Hex;
  readonly slipId: bigint;
  readonly vault: VaultTag;
  readonly newClaimPrivateKey: Hex;
  readonly newClaimSigner: Address;
  readonly grossAmountUnits: bigint;
  readonly feeUnits: bigint;
  readonly netAmountUnits: bigint;
  readonly isFirstKeepZeroFee: boolean;
  readonly transportTier: GaslessTransportTier;
}

/**
 * Executes `acceptWithPermit(..., keepEscrowedInVault: true)`:
 * - `0%` fee on 1st Keep (`nonces == 0 && !refundFeeRequired`), `0.50%` ceiling fee on subsequent re-keeps.
 * - Rotates `claimSigner` in-place inside `CryptoSlipVaultV32` to a fresh ephemeral key guaranteed
 *   `!= [creator, previousClaimSigner, refundBeneficiary, userMainWallet]`.
 */
export async function keepSlip(options: KeepSlipOptions): Promise<KeepSlipResult> {
  const {
    publicClient,
    vault = ISSUE_VAULT,
    ttlSeconds = 3_600,
    mutex = defaultSlipMutex,
  } = options;
  if (!isV32ProtocolVault(vault)) {
    throw new SlipOperationError(`keepSlip requires a V3.2 vault ('v33' or 'v32'); got '${vault}'.`);
  }
  const slipId = BigInt(options.slipId);
  const lockKey = SlipMutex.keyFor(vault, slipId);

  return mutex.runExclusive(lockKey, async () => {
    const state = await readOnChainSlip({ publicClient, slipId, vault });
    if (state.status !== SlipStatus.ACTIVE) {
      throw new SlipOperationError(
        `Slip #${slipId.toString()} is not active (status=${state.status}).`,
      );
    }

    const currentSigner = await toSlipSigner(options.claimSigner);
    const currentSignerAddr = await currentSigner.getAddress();
    if (currentSignerAddr.toLowerCase() !== state.claimSigner.toLowerCase()) {
      throw new SlipOperationError(
        `Provided claimSigner (${currentSignerAddr}) does not match on-chain slip.claimSigner (${state.claimSigner}).`,
      );
    }

    const forbidden = [
      state.creator,
      state.claimSigner,
      state.refundBeneficiary,
      ...(options.userMainWallet ? [options.userMainWallet] : []),
    ];
    const forbiddenSet = new Set(forbidden.map((a) => a.toLowerCase()));

    let newClaimPrivateKey: Hex;
    let newClaimSigner: Address;

    if (options.newClaimPrivateKey) {
      const pk = (
        options.newClaimPrivateKey.startsWith('0x')
          ? options.newClaimPrivateKey
          : `0x${options.newClaimPrivateKey}`
      ) as Hex;
      const addr = getAddress(privateKeyToAccount(pk).address);
      if (forbiddenSet.has(addr.toLowerCase()) || BLOCKED_PAYMENT_TARGETS.has(addr.toLowerCase())) {
        throw new SlipOperationError(
          `newClaimPrivateKey address (${addr}) collides with creator, current signer, beneficiary, userMainWallet, or a blocked protocol target.`,
        );
      }
      newClaimPrivateKey = pk;
      newClaimSigner = addr;
    } else if (options.recoveryMasterKey) {
      newClaimPrivateKey = deriveNextSlipHolderKey(
        options.recoveryMasterKey,
        vault,
        slipId,
        state.claimSigner,
        forbidden,
      );
      newClaimSigner = getAddress(privateKeyToAccount(newClaimPrivateKey).address);
    } else {
      const fresh = generateFreshNonCollidingKey(forbidden);
      newClaimPrivateKey = fresh.privateKey;
      newClaimSigner = fresh.address;
    }

    const alreadyKeptOrSelfCreated =
      state.nonce > 0n ||
      state.refundFeeRequired ||
      state.creator.toLowerCase() === state.claimSigner.toLowerCase() ||
      state.refundBeneficiary.toLowerCase() !== state.creator.toLowerCase();

    const feeUnits = alreadyKeptOrSelfCreated ? computeProtocolFeeCeiling(state.amount) : 0n;
    const netAmountUnits = state.amount > feeUnits ? state.amount - feeUnits : 0n;
    const minUnits = minSlipAmount(state.asset, vault);
    if (netAmountUnits < minUnits) {
      throw new SlipOperationError(
        `Slip #${slipId.toString()} net balance after Keep (${netAmountUnits.toString()}) would fall below minimum (${minUnits.toString()}). Claim directly to wallet instead.`,
      );
    }

    const headTs = await resolveChainHeadTimestamp(publicClient, options.chainTimestampSec);
    const deadline = computePermitDeadline(headTs, ttlSeconds);

    const { signature: acceptSig } = await signAcceptPermit(currentSigner, {
      slipId,
      newHolder: newClaimSigner,
      newClaimSigner,
      keepEscrowedInVault: true,
      nonce: state.nonce,
      deadline,
      relayer: ZERO_ADDRESS,
      vault,
    });

    let finalSignature: Hex = acceptSig;
    let consentSig: Hex | undefined;
    if (
      options.bindReferrerOnKeep &&
      state.creator !== ZERO_ADDRESS &&
      state.creator.toLowerCase() !== state.claimSigner.toLowerCase() &&
      state.creator.toLowerCase() !== newClaimSigner.toLowerCase()
    ) {
      const consent = await signReferralConsent(newClaimPrivateKey, {
        recipient: newClaimSigner,
        slipId,
        referrer: state.creator,
        deadline,
        vault,
      });
      consentSig = consent.signature;
      finalSignature = packPermitWithReferralConsent(acceptSig, consentSig);
    }

    await options.onBeforeBroadcast?.({
      slipId,
      vault,
      newClaimPrivateKey,
      newClaimSigner,
    });

    const callData = encodeFunctionData({
      abi: CRYPTO_SLIP_VAULT_V32_ABI,
      functionName: 'acceptWithPermit',
      args: [slipId, newClaimSigner, newClaimSigner, true, ZERO_ADDRESS, deadline, finalSignature],
    });

    const relayBody: Record<string, unknown> = {
      mode: 'v32',
      vault: state.vaultAddress,
      slipId: slipId.toString(),
      newHolder: newClaimSigner,
      newClaimSigner,
      keepEscrowedInVault: true,
      relayer: ZERO_ADDRESS,
      deadline: deadline.toString(),
      signature: finalSignature,
      ...(consentSig ? { referralConsentSignature: consentSig } : {}),
    };

    const transportRes = await executeGaslessTransport({
      mode: options.mode,
      telegramInitData: options.telegramInitData,
      partnerKey: options.partnerKey,
      relayClient: options.relayClient,
      // Edge Relay only sponsors 1st Keep (`!alreadyKeptOrSelfCreated`)
      ...(alreadyKeptOrSelfCreated
        ? {}
        : { relayPath: '/api/relay/accept', relayBody }),
      operationKind: options.isBootKeep ? 'boot_keep' : 'keep',
      estimatedUsdMicro: estimateAssetUsdMicro(state.amount, state.asset),
      calls: [{ to: state.vaultAddress, data: callData }],
      publicClient,
      paymasterSignerKey: options.paymasterSignerKey,
      bundlerUrls: options.bundlerUrls,
      bundlerFetch: options.bundlerFetch,
      walletClient: options.walletClient,
      directBroadcast: options.directBroadcast,
      allowHumanRelayInAgentMode: options.allowHumanRelayInAgentMode,
      onStatus: options.onStatus,
    });

    return {
      txHash: transportRes.txHash,
      slipId,
      vault,
      newClaimPrivateKey,
      newClaimSigner,
      grossAmountUnits: state.amount,
      feeUnits,
      netAmountUnits,
      isFirstKeepZeroFee: !alreadyKeptOrSelfCreated,
      transportTier: transportRes.tier,
    };
  });
}

// ============================================================================
// 2. `claimSlip()` — Wallet Cashout + `130-Byte` ReferralConsent Binding
// ============================================================================

export interface ClaimSlipOptions extends SharedTransportExecutionOptions {
  publicClient: BaseCompatiblePublicClient;
  slipId: bigint | number | string;
  claimSigner: SlipSignerInput;
  recipient: Address;
  /**
   * Optional signer for `recipient` (`userMainWallet`). When provided, signs the 65-byte
   * `ReferralConsent` and packs a `130-byte` (`CashPermit || ReferralConsent`) signature
   * permanently binding `referrerOf[recipient] = slip.creator` on-chain (`0.25%` lifetime share)!
   */
  recipientSigner?: SlipSignerInput;
  vault?: VaultTag;
  chainTimestampSec?: bigint | number;
  ttlSeconds?: number;
  mutex?: SlipMutex;
}

export interface ClaimSlipResult {
  readonly txHash: Hex;
  readonly slipId: bigint;
  readonly vault: VaultTag;
  readonly recipient: Address;
  readonly asset: SdkAssetSymbol;
  readonly grossAmountUnits: bigint;
  readonly feeUnits: bigint;
  readonly netAmountUnits: bigint;
  readonly signature: Hex;
  readonly attachedReferralConsent: boolean;
  readonly transportTier: GaslessTransportTier;
}

/**
 * Executes `cashWithPermit` (`0.50%` ceiling fee), building the `130-byte`
 * `PermitSig || ReferralConsentSig` bundle when `recipientSigner` is provided so
 * `referrerOf[recipient] = slip.creator` binds permanently on Base.
 */
export async function claimSlip(options: ClaimSlipOptions): Promise<ClaimSlipResult> {
  const {
    publicClient,
    vault = ISSUE_VAULT,
    ttlSeconds = 3_600,
    mutex = defaultSlipMutex,
  } = options;
  if (!isAddress(options.recipient)) {
    throw new SlipOperationError('Invalid recipient wallet address.');
  }
  const recipient = getAddress(options.recipient);
  if (BLOCKED_PAYMENT_TARGETS.has(recipient.toLowerCase())) {
    throw new SlipOperationError(`Recipient ${recipient} is a blocked protocol or burn address.`);
  }

  const slipId = BigInt(options.slipId);
  const lockKey = SlipMutex.keyFor(vault, slipId);

  return mutex.runExclusive(lockKey, async () => {
    const state = await readOnChainSlip({ publicClient, slipId, vault });
    if (state.status !== SlipStatus.ACTIVE) {
      throw new SlipOperationError(
        `Slip #${slipId.toString()} is not active (status=${state.status}).`,
      );
    }

    const signer = await toSlipSigner(options.claimSigner);
    const signerAddr = await signer.getAddress();
    if (signerAddr.toLowerCase() !== state.claimSigner.toLowerCase()) {
      throw new SlipOperationError(
        `Provided claimSigner (${signerAddr}) does not match on-chain slip.claimSigner (${state.claimSigner}).`,
      );
    }

    const headTs = await resolveChainHeadTimestamp(publicClient, options.chainTimestampSec);
    if (
      state.cancelLockedUntil > headTs &&
      (recipient.toLowerCase() === state.creator.toLowerCase() ||
        recipient.toLowerCase() === state.refundBeneficiary.toLowerCase())
    ) {
      throw new SlipOperationError(
        'No take-back slip cannot be claimed back to the sender or refund beneficiary.',
      );
    }

    const deadline = computePermitDeadline(headTs, ttlSeconds);
    const { signature: cashSig } = await signCashPermit(signer, {
      slipId,
      recipient,
      nonce: state.nonce,
      deadline,
      relayer: ZERO_ADDRESS,
      vault,
    });

    let finalSig: Hex = cashSig;
    let consentSig: Hex | undefined;
    let attachedReferralConsent = false;

    const eligibleForRefBind =
      isV32ProtocolVault(vault) &&
      state.creator !== ZERO_ADDRESS &&
      state.creator.toLowerCase() !== state.claimSigner.toLowerCase() &&
      state.creator.toLowerCase() !== recipient.toLowerCase() &&
      state.creator.toLowerCase() !== TREASURY_SAFE_ADDRESS.toLowerCase() &&
      !state.refundFeeRequired &&
      state.amount >= minSlipAmount(state.asset, vault);

    if (options.recipientSigner && eligibleForRefBind) {
      const recSigner = await toSlipSigner(options.recipientSigner);
      const recAddr = await recSigner.getAddress();
      if (recAddr.toLowerCase() === recipient.toLowerCase()) {
        const consent = await signReferralConsent(recSigner, {
          recipient,
          slipId,
          referrer: state.creator,
          deadline,
          vault,
        });
        consentSig = consent.signature;
        finalSig = packPermitWithReferralConsent(cashSig, consentSig);
        attachedReferralConsent = true;
      }
    }

    const feeUnits = computeProtocolFeeCeiling(state.amount);
    const netAmountUnits = state.amount > feeUnits ? state.amount - feeUnits : 0n;

    const callData = encodeFunctionData({
      abi: CRYPTO_SLIP_VAULT_V32_ABI,
      functionName: 'cashWithPermit',
      args: [slipId, recipient, ZERO_ADDRESS, deadline, finalSig],
    });

    const relayBody: Record<string, unknown> = {
      vault: state.vaultAddress,
      slipId: slipId.toString(),
      recipient,
      relayer: ZERO_ADDRESS,
      deadline: deadline.toString(),
      signature: finalSig,
      ...(consentSig ? { referralConsentSignature: consentSig } : {}),
    };

    const transportRes = await executeGaslessTransport({
      mode: options.mode,
      telegramInitData: options.telegramInitData,
      partnerKey: options.partnerKey,
      relayClient: options.relayClient,
      relayPath: '/api/relay/cash',
      relayBody,
      operationKind: 'claim',
      estimatedUsdMicro: estimateAssetUsdMicro(state.amount, state.asset),
      calls: [{ to: state.vaultAddress, data: callData }],
      publicClient,
      paymasterSignerKey: options.paymasterSignerKey,
      bundlerUrls: options.bundlerUrls,
      bundlerFetch: options.bundlerFetch,
      walletClient: options.walletClient,
      directBroadcast: options.directBroadcast,
      allowHumanRelayInAgentMode: options.allowHumanRelayInAgentMode,
      onStatus: options.onStatus,
    });

    return {
      txHash: transportRes.txHash,
      slipId,
      vault,
      recipient,
      asset: state.asset,
      grossAmountUnits: state.amount,
      feeUnits,
      netAmountUnits,
      signature: finalSig,
      attachedReferralConsent,
      transportTier: transportRes.tier,
    };
  });
}

// ============================================================================
// 3. `splitAndPay()` — `V-03` Mutex + Sub-Minimum Dust-Cliff Pre-Check
// ============================================================================

export interface CheckSplitDustOptions {
  slipAmount: bigint;
  paymentAmount: bigint;
  asset: AnyAssetSymbol;
  vault?: VaultTag;
  /** When `true`, allows sweeping the full `slipAmount` to `merchant` if `0 < remainder <= maxDustToleranceUnits`. */
  allowFullCashOnDust?: boolean;
  /** Maximum dust remainder eligible for `allowFullCashOnDust` (defaults to `minSlipAmount(asset, vault)`). */
  maxDustToleranceUnits?: bigint;
}

export interface SplitDustResolution {
  readonly effectivePaymentAmount: bigint;
  readonly expectedChangeAmount: bigint;
  readonly routedFullCashOnDust: boolean;
}

/**
 * Deterministic `V-03` dust-cliff validator:
 * Rejects `0n < remainder < minSlipAmount(asset, vault)` with a typed `DustCliffError` BEFORE
 * signing or submitting, unless `allowFullCashOnDust` is explicitly enabled within tolerance.
 */
export function resolveSplitPaymentWithDustCheck(
  options: CheckSplitDustOptions,
): SplitDustResolution {
  const { slipAmount, paymentAmount, vault = ISSUE_VAULT } = options;
  const asset = normalizeSdkAsset(options.asset);
  const minUnits = minSlipAmount(asset, vault);

  if (paymentAmount <= 0n) {
    throw new SlipOperationError('paymentAmount must be strictly greater than zero.');
  }
  if (paymentAmount > slipAmount) {
    throw new SlipOperationError(
      `paymentAmount (${paymentAmount.toString()}) exceeds slip balance (${slipAmount.toString()}).`,
    );
  }
  if (paymentAmount < minUnits) {
    throw new SlipOperationError(
      `paymentAmount (${paymentAmount.toString()}) is below ${vault} minimum (${minUnits.toString()} raw ${asset}).`,
    );
  }

  const remainder = slipAmount - paymentAmount;
  if (remainder === 0n) {
    return {
      effectivePaymentAmount: slipAmount,
      expectedChangeAmount: 0n,
      routedFullCashOnDust: false,
    };
  }

  if (remainder < minUnits) {
    const maxDust = options.maxDustToleranceUnits ?? minUnits;
    if (options.allowFullCashOnDust && remainder <= maxDust) {
      return {
        effectivePaymentAmount: slipAmount,
        expectedChangeAmount: 0n,
        routedFullCashOnDust: true,
      };
    }
    throw new DustCliffError({
      slipAmount,
      paymentAmount,
      remainder,
      minRequiredChange: minUnits,
      asset,
      vault,
    });
  }

  return {
    effectivePaymentAmount: paymentAmount,
    expectedChangeAmount: remainder,
    routedFullCashOnDust: false,
  };
}

export interface SplitAndPayOptions extends SharedTransportExecutionOptions {
  publicClient: BaseCompatiblePublicClient;
  slipId: bigint | number | string;
  claimSigner: SlipSignerInput;
  paymentAmount: bigint;
  merchant: Address;
  vault?: VaultTag;
  recoveryMasterKey?: Hex;
  newChangePrivateKey?: Hex;
  userMainWallet?: Address;
  allowFullCashOnDust?: boolean;
  maxDustToleranceUnits?: bigint;
  chainTimestampSec?: bigint | number;
  ttlSeconds?: number;
  mutex?: SlipMutex;
  onBeforeBroadcast?: (changeInfo: {
    parentSlipId: bigint;
    newChangePrivateKey?: Hex;
    newChangeSigner: Address;
    expectedChangeAmount: bigint;
  }) => Promise<void> | void;
}

export interface SplitAndPayResult {
  readonly txHash: Hex;
  readonly parentSlipId: bigint;
  readonly changeSlipId: bigint | null;
  readonly newChangePrivateKey?: Hex;
  readonly newChangeSigner: Address;
  readonly merchant: Address;
  readonly asset: SdkAssetSymbol;
  readonly grossPaymentAmount: bigint;
  readonly feeUnits: bigint;
  readonly netMerchantAmount: bigint;
  readonly changeAmount: bigint;
  readonly routedFullCashOnDust: boolean;
  readonly transportTier: GaslessTransportTier;
}

/**
 * Executes `splitAndPayWithPermit` under per-`slipId` `SlipMutex` (`V-03`) with deterministic
 * sub-minimum dust-cliff pre-validation (`DustCliffError`).
 */
export async function splitAndPay(options: SplitAndPayOptions): Promise<SplitAndPayResult> {
  const {
    publicClient,
    vault = ISSUE_VAULT,
    ttlSeconds = 3_600,
    mutex = defaultSlipMutex,
  } = options;
  if (!isV32ProtocolVault(vault)) {
    throw new SlipOperationError(`splitAndPay requires a V3.2 vault ('v33' or 'v32').`);
  }
  if (!isAddress(options.merchant)) {
    throw new SlipOperationError('Invalid merchant address.');
  }
  const merchant = getAddress(options.merchant);
  if (BLOCKED_PAYMENT_TARGETS.has(merchant.toLowerCase())) {
    throw new SlipOperationError(`Merchant ${merchant} is a blocked protocol or burn address.`);
  }

  const slipId = BigInt(options.slipId);
  const lockKey = SlipMutex.keyFor(vault, slipId);

  return mutex.runExclusive(lockKey, async () => {
    const state = await readOnChainSlip({ publicClient, slipId, vault });
    if (state.status !== SlipStatus.ACTIVE) {
      throw new SlipOperationError(
        `Slip #${slipId.toString()} is not active (status=${state.status}).`,
      );
    }

    const signer = await toSlipSigner(options.claimSigner);
    const signerAddr = await signer.getAddress();
    if (signerAddr.toLowerCase() !== state.claimSigner.toLowerCase()) {
      throw new SlipOperationError(
        `Provided claimSigner (${signerAddr}) does not match on-chain slip.claimSigner (${state.claimSigner}).`,
      );
    }

    const headTs = await resolveChainHeadTimestamp(publicClient, options.chainTimestampSec);
    if (state.cancelLockedUntil > headTs) {
      if (
        merchant.toLowerCase() === state.creator.toLowerCase() ||
        merchant.toLowerCase() === state.refundBeneficiary.toLowerCase()
      ) {
        throw new SlipOperationError(
          'No take-back slip cannot be split to its creator or refund beneficiary.',
        );
      }
      const isKept =
        state.nonce > 0n ||
        state.refundFeeRequired ||
        state.refundBeneficiary.toLowerCase() !== state.creator.toLowerCase();
      if (!isKept) {
        throw new SlipOperationError(
          'No take-back slip must be kept via keepSlip() before partial split spending.',
        );
      }
    }

    const resolution = resolveSplitPaymentWithDustCheck({
      slipAmount: state.amount,
      paymentAmount: options.paymentAmount,
      asset: state.asset,
      vault,
      allowFullCashOnDust: options.allowFullCashOnDust,
      maxDustToleranceUnits: options.maxDustToleranceUnits,
    });

    const effectivePayment = resolution.effectivePaymentAmount;
    const expectedChange = resolution.expectedChangeAmount;

    let changeReceiver: Address = ZERO_ADDRESS;
    let newChangeSigner: Address = ZERO_ADDRESS;
    let newChangePrivateKey: Hex | undefined;

    if (expectedChange > 0n) {
      changeReceiver = state.vaultAddress;
      const forbidden = [
        merchant,
        state.creator,
        state.claimSigner,
        state.refundBeneficiary,
        ...(options.userMainWallet ? [options.userMainWallet] : []),
      ];
      const forbiddenLower = new Set(forbidden.map((a) => a.toLowerCase()));

      if (options.newChangePrivateKey) {
        const pk = (
          options.newChangePrivateKey.startsWith('0x')
            ? options.newChangePrivateKey
            : `0x${options.newChangePrivateKey}`
        ) as Hex;
        const addr = getAddress(privateKeyToAccount(pk).address);
        if (forbiddenLower.has(addr.toLowerCase()) || BLOCKED_PAYMENT_TARGETS.has(addr.toLowerCase())) {
          throw new SlipOperationError('newChangePrivateKey collides with merchant, creator, or current signer.');
        }
        newChangePrivateKey = pk;
        newChangeSigner = addr;
      } else if (options.recoveryMasterKey) {
        const candidate = deriveSplitChangeSlipKey(options.recoveryMasterKey, vault, slipId);
        const candidateAddr = getAddress(privateKeyToAccount(candidate).address);
        if (!forbiddenLower.has(candidateAddr.toLowerCase())) {
          newChangePrivateKey = candidate;
          newChangeSigner = candidateAddr;
        } else {
          newChangePrivateKey = deriveNextSlipHolderKey(
            options.recoveryMasterKey,
            vault,
            slipId,
            state.claimSigner,
            forbidden,
          );
          newChangeSigner = getAddress(privateKeyToAccount(newChangePrivateKey).address);
        }
      } else {
        const fresh = generateFreshNonCollidingKey(forbidden);
        newChangePrivateKey = fresh.privateKey;
        newChangeSigner = fresh.address;
      }
    }

    await options.onBeforeBroadcast?.({
      parentSlipId: slipId,
      ...(newChangePrivateKey ? { newChangePrivateKey } : {}),
      newChangeSigner,
      expectedChangeAmount: expectedChange,
    });

    const deadline = computePermitDeadline(headTs, ttlSeconds);
    const { signature } = await signSplitPermit(signer, {
      slipId,
      paymentAmount: effectivePayment,
      merchant,
      changeReceiver,
      newChangeSigner,
      nonce: state.nonce,
      deadline,
      relayer: ZERO_ADDRESS,
      vault,
    });

    const callData = encodeFunctionData({
      abi: CRYPTO_SLIP_VAULT_V32_ABI,
      functionName: 'splitAndPayWithPermit',
      args: [
        slipId,
        effectivePayment,
        merchant,
        changeReceiver,
        newChangeSigner,
        ZERO_ADDRESS,
        deadline,
        signature,
      ],
    });

    const relayBody: Record<string, unknown> = {
      vault: state.vaultAddress,
      slipId: slipId.toString(),
      paymentAmount: effectivePayment.toString(),
      merchant,
      changeReceiver,
      newChangeSigner,
      relayer: ZERO_ADDRESS,
      deadline: deadline.toString(),
      signature,
    };

    const transportRes = await executeGaslessTransport({
      mode: options.mode,
      telegramInitData: options.telegramInitData,
      partnerKey: options.partnerKey,
      relayClient: options.relayClient,
      // Edge relay sponsors partial splits (`changeReceiver == vault && newChangeSigner != 0`); full-cash dust sweeps use cash/paymaster/direct
      ...(expectedChange > 0n ? { relayPath: '/api/relay/split', relayBody } : {}),
      operationKind: 'split',
      estimatedUsdMicro: estimateAssetUsdMicro(effectivePayment, state.asset),
      calls: [{ to: state.vaultAddress, data: callData }],
      publicClient,
      paymasterSignerKey: options.paymasterSignerKey,
      bundlerUrls: options.bundlerUrls,
      bundlerFetch: options.bundlerFetch,
      walletClient: options.walletClient,
      directBroadcast: options.directBroadcast,
      allowHumanRelayInAgentMode: options.allowHumanRelayInAgentMode,
      onStatus: options.onStatus,
    });

    let changeSlipId: bigint | null = null;
    let finalChangeAmount = expectedChange;

    if (expectedChange > 0n) {
      const receipt = await publicClient
        .waitForTransactionReceipt({ hash: transportRes.txHash })
        .catch(() => null);
      if (receipt?.logs) {
        for (const log of receipt.logs) {
          if (log.address.toLowerCase() !== state.vaultAddress.toLowerCase()) continue;
          try {
            const parsed = decodeEventLog({
              abi: CRYPTO_SLIP_VAULT_V32_ABI,
              data: log.data,
              topics: log.topics as [Hex, ...Hex[]],
            });
            if (parsed.eventName === 'SlipSplitAndPaid' && parsed.args.originalSlipId === slipId) {
              changeSlipId = parsed.args.changeSlipId;
              finalChangeAmount = parsed.args.changeAmount;
              break;
            }
          } catch {
            // ignore non-matching log
          }
        }
      }
    }

    const feeUnits = computeProtocolFeeCeiling(effectivePayment);
    const netMerchantAmount = effectivePayment > feeUnits ? effectivePayment - feeUnits : 0n;

    return {
      txHash: transportRes.txHash,
      parentSlipId: slipId,
      changeSlipId,
      ...(newChangePrivateKey ? { newChangePrivateKey } : {}),
      newChangeSigner,
      merchant,
      asset: state.asset,
      grossPaymentAmount: effectivePayment,
      feeUnits,
      netMerchantAmount,
      changeAmount: finalChangeAmount,
      routedFullCashOnDust: resolution.routedFullCashOnDust,
      transportTier: transportRes.tier,
    };
  });
}

// ============================================================================
// 4. `planCombineSlipBuckets()` & `combineSlips()` — Enforces `V-05`
// ============================================================================

export interface CombinableSlipDescriptor {
  readonly slipId: bigint;
  readonly asset: AnyAssetSymbol;
  readonly amount: bigint;
  readonly creator: Address;
  readonly cancelLockedUntil: bigint | number;
}

export interface PlannedCombineBatch<TSlip extends CombinableSlipDescriptor = CombinableSlipDescriptor> {
  /** `'unlocked'` or `'locked:<creatorLower>'` */
  readonly bucketKey: string;
  readonly lockedCreator: Address | null;
  readonly slips: readonly TSlip[];
  readonly totalAmount: bigint;
}

export interface CombineBucketPlan<TSlip extends CombinableSlipDescriptor = CombinableSlipDescriptor> {
  readonly batches: readonly PlannedCombineBatch<TSlip>[];
  /** Singletons (`length === 1`) that cannot run a pure `paymentAmount == 0` `rearrangeAndPayWithPermits` (`count >= 2` required). */
  readonly uncombinableSingletons: readonly TSlip[];
}

function chunkAvoidingTrailingSingleton<T>(items: readonly T[], maxPerBatch: number): T[][] {
  if (items.length <= maxPerBatch) return [Array.from(items)];
  const chunks: T[][] = [];
  let offset = 0;
  while (offset < items.length) {
    const remaining = items.length - offset;
    if (remaining <= maxPerBatch) {
      chunks.push(items.slice(offset));
      break;
    }
    if (remaining === maxPerBatch + 1 && maxPerBatch >= 3) {
      // Split e.g. 11 -> [9, 2] instead of [10, 1] so chunk #2 still has >= 2 slips for pure combine!
      chunks.push(items.slice(offset, offset + maxPerBatch - 1));
      offset += maxPerBatch - 1;
    } else {
      chunks.push(items.slice(offset, offset + maxPerBatch));
      offset += maxPerBatch;
    }
  }
  return chunks;
}

/**
 * Deterministic `V-05` Combine Planner (`CryptoSlipProtocolV32.sol:838-895`):
 * - Partitions `No take-back` (`cancelLockedUntil > currentTimestampSec`, e.g. `9_999_999_999n`) slips
 *   strictly by `slip.creator` so mixed creators NEVER revert `CancelLocked()` (`L889`)!
 * - If a locked creator bucket has only 1 slip AND an unlocked slip from that SAME `creator` exists,
 *   pairs it into that creator's bucket (`slips[id].creator == t.lockedCreator` holds true!) so it can combine.
 * - Groups all remaining unlocked slips (`cancelLockedUntil <= currentTimestampSec`) together (`t.lockedCreator == 0`).
 * - Enforces `<= 10` (`MAX_COMBINE_SLIPS`) slips per batch and avoids trailing `1`-slip chunks on pure combine!
 */
export function planCombineSlipBuckets<TSlip extends CombinableSlipDescriptor>(
  slips: readonly TSlip[],
  options?: {
    currentTimestampSec?: bigint | number;
    maxBatchSize?: number;
    allowSingleSlipBatch?: boolean;
  },
): CombineBucketPlan<TSlip> {
  if (slips.length === 0) {
    throw new SlipOperationError('At least one slip is required for planCombineSlipBuckets.');
  }
  const maxBatchSize = options?.maxBatchSize ?? MAX_COMBINE_SLIPS;
  if (!Number.isInteger(maxBatchSize) || maxBatchSize < 2 || maxBatchSize > MAX_COMBINE_SLIPS) {
    throw new SlipOperationError(`maxBatchSize must be between 2 and ${MAX_COMBINE_SLIPS}.`);
  }

  const nowSec = BigInt(options?.currentTimestampSec ?? Math.floor(Date.now() / 1000));
  const firstAsset = normalizeSdkAsset(slips[0]!.asset);
  const seenIds = new Set<string>();

  for (const s of slips) {
    if (normalizeSdkAsset(s.asset) !== firstAsset) {
      throw new SlipOperationError(
        `All slips in combineSlips must share the same asset (expected ${firstAsset}, got ${String(s.asset)}).`,
      );
    }
    const idStr = s.slipId.toString();
    if (seenIds.has(idStr)) {
      throw new SlipOperationError(`Duplicate slipId #${idStr} in combineSlips input.`);
    }
    seenIds.add(idStr);
  }

  const lockedByCreator = new Map<string, { creator: Address; items: TSlip[] }>();
  const unlockedPool: TSlip[] = [];

  for (const s of slips) {
    const lockUntil = BigInt(s.cancelLockedUntil);
    if (lockUntil > nowSec) {
      const cAddr = getAddress(s.creator);
      const key = cAddr.toLowerCase();
      const bucket = lockedByCreator.get(key) ?? { creator: cAddr, items: [] };
      bucket.items.push(s);
      lockedByCreator.set(key, bucket);
    } else {
      unlockedPool.push(s);
    }
  }

  // Rescue 1-slip locked buckets if a same-creator unlocked slip is available
  for (const [creatorLower, bucket] of lockedByCreator.entries()) {
    if (bucket.items.length === 1 && !options?.allowSingleSlipBatch) {
      const matchIdx = unlockedPool.findIndex(
        (u) => u.creator.toLowerCase() === creatorLower,
      );
      if (matchIdx >= 0 && unlockedPool.length !== 2) {
        const rescued = unlockedPool.splice(matchIdx, 1)[0]!;
        bucket.items.push(rescued);
      }
    }
  }

  const batches: PlannedCombineBatch<TSlip>[] = [];
  const uncombinableSingletons: TSlip[] = [];

  for (const [creatorLower, bucket] of lockedByCreator.entries()) {
    if (bucket.items.length < 2 && !options?.allowSingleSlipBatch) {
      uncombinableSingletons.push(...bucket.items);
      continue;
    }
    const chunks = options?.allowSingleSlipBatch
      ? Array.from({ length: Math.ceil(bucket.items.length / maxBatchSize) }, (_, i) =>
          bucket.items.slice(i * maxBatchSize, (i + 1) * maxBatchSize),
        )
      : chunkAvoidingTrailingSingleton(bucket.items, maxBatchSize);

    for (const chunk of chunks) {
      if (chunk.length < 2 && !options?.allowSingleSlipBatch) {
        uncombinableSingletons.push(...chunk);
        continue;
      }
      let sum = 0n;
      for (const c of chunk) sum += c.amount;
      batches.push({
        bucketKey: `locked:${creatorLower}`,
        lockedCreator: bucket.creator,
        slips: chunk,
        totalAmount: sum,
      });
    }
  }

  if (unlockedPool.length > 0) {
    if (unlockedPool.length < 2 && !options?.allowSingleSlipBatch) {
      uncombinableSingletons.push(...unlockedPool);
    } else {
      const chunks = options?.allowSingleSlipBatch
        ? Array.from({ length: Math.ceil(unlockedPool.length / maxBatchSize) }, (_, i) =>
            unlockedPool.slice(i * maxBatchSize, (i + 1) * maxBatchSize),
          )
        : chunkAvoidingTrailingSingleton(unlockedPool, maxBatchSize);

      for (const chunk of chunks) {
        if (chunk.length < 2 && !options?.allowSingleSlipBatch) {
          uncombinableSingletons.push(...chunk);
          continue;
        }
        let sum = 0n;
        for (const c of chunk) sum += c.amount;
        batches.push({
          bucketKey: 'unlocked',
          lockedCreator: null,
          slips: chunk,
          totalAmount: sum,
        });
      }
    }
  }

  return { batches, uncombinableSingletons };
}

export interface CombineSlipInputItem {
  readonly slipId: bigint | number | string;
  readonly claimSigner: SlipSignerInput;
}

export interface CombineSlipsOptions extends SharedTransportExecutionOptions {
  publicClient: BaseCompatiblePublicClient;
  slips: readonly CombineSlipInputItem[];
  /** Optional merchant payment (`0n` by default = pure consolidation into a single new vault slip). */
  paymentAmount?: bigint;
  merchant?: Address;
  vault?: VaultTag;
  recoveryMasterKey?: Hex;
  userMainWallet?: Address;
  chainTimestampSec?: bigint | number;
  ttlSeconds?: number;
  mutex?: SlipMutex;
}

export interface ExecutedCombineBatchResult {
  readonly bucketKey: string;
  readonly consumedSlipIds: readonly bigint[];
  readonly txHash: Hex;
  readonly changeSlipId: bigint | null;
  readonly newChangePrivateKey?: Hex;
  readonly newChangeSigner: Address;
  readonly paymentAmount: bigint;
  readonly expectedChangeAmount: bigint;
  readonly transportTier: GaslessTransportTier;
}

export interface CombineSlipsResult {
  readonly vault: VaultTag;
  readonly asset: SdkAssetSymbol;
  readonly executedBatches: readonly ExecutedCombineBatchResult[];
  readonly uncombinableSlipIds: readonly bigint[];
}

/**
 * Executes `rearrangeAndPayWithPermits` across `2..N` slips while automatically bucketing
 * `No take-back` (`9_999_999_999n`) slips by `slip.creator` (`V-05`) and chunking `<= 10` per tx!
 */
export async function combineSlips(options: CombineSlipsOptions): Promise<CombineSlipsResult> {
  const {
    publicClient,
    vault = ISSUE_VAULT,
    ttlSeconds = 3_600,
    mutex = defaultSlipMutex,
  } = options;
  if (!isV32ProtocolVault(vault)) {
    throw new SlipOperationError(`combineSlips requires a V3.2 vault ('v33' or 'v32').`);
  }
  if (options.slips.length === 0) {
    throw new SlipOperationError('combineSlips requires at least one input slip.');
  }

  const lockKeys = options.slips.map((s) => SlipMutex.keyFor(vault, s.slipId));

  return mutex.runExclusiveMulti(lockKeys, async () => {
    const headTs = await resolveChainHeadTimestamp(publicClient, options.chainTimestampSec);
    const loaded = await Promise.all(
      options.slips.map(async (item) => {
        const state = await readOnChainSlip({ publicClient, slipId: item.slipId, vault });
        if (state.status !== SlipStatus.ACTIVE) {
          throw new SlipOperationError(
            `Slip #${state.slipId.toString()} is not active (status=${state.status}).`,
          );
        }
        const signer = await toSlipSigner(item.claimSigner);
        const addr = await signer.getAddress();
        if (addr.toLowerCase() !== state.claimSigner.toLowerCase()) {
          throw new SlipOperationError(
            `Signer (${addr}) does not match slip #${state.slipId.toString()} claimSigner (${state.claimSigner}).`,
          );
        }
        if (state.cancelLockedUntil > headTs) {
          const isKept =
            state.nonce > 0n ||
            state.refundFeeRequired ||
            state.refundBeneficiary.toLowerCase() !== state.creator.toLowerCase();
          if (!isKept) {
            throw new SlipOperationError(
              `No take-back slip #${state.slipId.toString()} must be kept via keepSlip() before combining.`,
            );
          }
        }
        return {
          slipId: state.slipId,
          asset: state.asset,
          amount: state.amount,
          creator: state.creator,
          cancelLockedUntil: state.cancelLockedUntil,
          state,
          signer,
        };
      }),
    );

    const requestedPayment = options.paymentAmount ?? 0n;
    if (requestedPayment > 0n && options.slips.length > MAX_COMBINE_SLIPS) {
      throw new SlipOperationError(
        `combineSlips with paymentAmount > 0 supports up to ${MAX_COMBINE_SLIPS} slips in a single atomic payment; consolidate first with paymentAmount: 0n.`,
      );
    }

    const plan = planCombineSlipBuckets(loaded, {
      currentTimestampSec: headTs,
      maxBatchSize: MAX_COMBINE_SLIPS,
      allowSingleSlipBatch: requestedPayment > 0n,
    });

    if (requestedPayment > 0n && plan.batches.length !== 1) {
      throw new SlipOperationError(
        'Selected slips contain mixed-creator No take-back locks; consolidate each creator bucket with paymentAmount: 0n first before paying a merchant.',
      );
    }

    const asset = loaded[0]!.asset;
    const minUnits = minSlipAmount(asset, vault);
    const executedBatches: ExecutedCombineBatchResult[] = [];

    for (const batch of plan.batches) {
      const batchPayment = requestedPayment;
      const merchant =
        batchPayment > 0n
          ? options.merchant
            ? getAddress(options.merchant)
            : (() => {
                throw new SlipOperationError('merchant address is required when paymentAmount > 0n.');
              })()
          : ZERO_ADDRESS;

      if (batchPayment > 0n && BLOCKED_PAYMENT_TARGETS.has(merchant.toLowerCase())) {
        throw new SlipOperationError(`Merchant ${merchant} is a blocked destination.`);
      }
      if (batchPayment > batch.totalAmount) {
        throw new SlipOperationError('paymentAmount exceeds total input slip amount.');
      }

      const rawRemainder = batch.totalAmount - batchPayment;
      const expectedChange =
        batchPayment === 0n
          ? batch.totalAmount - computeProtocolFeeCeiling(batch.totalAmount)
          : rawRemainder;

      if (batchPayment === 0n && expectedChange < minUnits) {
        throw new SlipOperationError(
          `Combined net slip (${expectedChange.toString()}) would fall below minimum (${minUnits.toString()}).`,
        );
      }
      if (batchPayment > 0n && (batchPayment < minUnits || (rawRemainder > 0n && rawRemainder < minUnits))) {
        throw new DustCliffError({
          slipAmount: batch.totalAmount,
          paymentAmount: batchPayment,
          remainder: rawRemainder,
          minRequiredChange: minUnits,
          asset,
          vault,
        });
      }

      const forbidden = [
        merchant,
        ...(options.userMainWallet ? [options.userMainWallet] : []),
        ...batch.slips.flatMap((s) => [s.state.creator, s.state.claimSigner, s.state.refundBeneficiary]),
      ];

      let changeReceiver: Address = ZERO_ADDRESS;
      let newChangeSigner: Address = ZERO_ADDRESS;
      let newChangePrivateKey: Hex | undefined;

      if (expectedChange > 0n) {
        changeReceiver = vaultAddress(vault);
        if (options.recoveryMasterKey) {
          const anchorId = batch.slips[0]!.slipId;
          const cand = deriveSplitChangeSlipKey(options.recoveryMasterKey, vault, anchorId);
          const candAddr = getAddress(privateKeyToAccount(cand).address);
          const forbiddenSet = new Set(forbidden.map((a) => a.toLowerCase()));
          if (!forbiddenSet.has(candAddr.toLowerCase())) {
            newChangePrivateKey = cand;
            newChangeSigner = candAddr;
          } else {
            const fresh = generateFreshNonCollidingKey(forbidden);
            newChangePrivateKey = fresh.privateKey;
            newChangeSigner = fresh.address;
          }
        } else {
          const fresh = generateFreshNonCollidingKey(forbidden);
          newChangePrivateKey = fresh.privateKey;
          newChangeSigner = fresh.address;
        }
      }

      const deadline = computePermitDeadline(headTs, ttlSeconds);
      const batchSlipIds = batch.slips.map((s) => s.slipId);

      const signatures = await Promise.all(
        batch.slips.map(async (s) => {
          const signed = await signRearrangePermit(s.signer, {
            slipId: s.slipId,
            slipIds: batchSlipIds,
            paymentAmount: batchPayment,
            merchant,
            changeReceiver,
            newChangeSigner,
            nonce: s.state.nonce,
            deadline,
            relayer: ZERO_ADDRESS,
            vault,
          });
          return signed.signature;
        }),
      );

      const vAddr = vaultAddress(vault);
      const callData = encodeFunctionData({
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        functionName: 'rearrangeAndPayWithPermits',
        args: [
          batchSlipIds,
          signatures,
          batchPayment,
          merchant,
          changeReceiver,
          newChangeSigner,
          ZERO_ADDRESS,
          deadline,
        ],
      });

      const relayBody: Record<string, unknown> = {
        vault: vAddr,
        slipIds: batchSlipIds.map((id) => id.toString()),
        signatures,
        paymentAmount: batchPayment.toString(),
        merchant,
        changeReceiver,
        newChangeSigner,
        relayer: ZERO_ADDRESS,
        deadline: deadline.toString(),
      };

      const transportRes = await executeGaslessTransport({
        mode: options.mode,
        telegramInitData: options.telegramInitData,
        partnerKey: options.partnerKey,
        relayClient: options.relayClient,
        relayPath: '/api/relay/combine',
        relayBody,
        operationKind: 'combine',
        estimatedUsdMicro: estimateAssetUsdMicro(batch.totalAmount, asset),
        calls: [{ to: vAddr, data: callData }],
        publicClient,
        paymasterSignerKey: options.paymasterSignerKey,
        bundlerUrls: options.bundlerUrls,
        bundlerFetch: options.bundlerFetch,
        walletClient: options.walletClient,
        directBroadcast: options.directBroadcast,
        allowHumanRelayInAgentMode: options.allowHumanRelayInAgentMode,
        onStatus: options.onStatus,
      });

      let changeSlipId: bigint | null = null;
      if (expectedChange > 0n) {
        const receipt = await publicClient
          .waitForTransactionReceipt({ hash: transportRes.txHash })
          .catch(() => null);
        if (receipt?.logs) {
          for (const log of receipt.logs) {
            if (log.address.toLowerCase() !== vAddr.toLowerCase()) continue;
            try {
              const parsed = decodeEventLog({
                abi: CRYPTO_SLIP_VAULT_V32_ABI,
                data: log.data,
                topics: log.topics as [Hex, ...Hex[]],
              });
              if (parsed.eventName === 'SlipsRearrangedAndPaid') {
                changeSlipId = parsed.args.changeSlipId;
                break;
              }
            } catch {
              // ignore non-matching log
            }
          }
        }
      }

      executedBatches.push({
        bucketKey: batch.bucketKey,
        consumedSlipIds: batchSlipIds,
        txHash: transportRes.txHash,
        changeSlipId,
        ...(newChangePrivateKey ? { newChangePrivateKey } : {}),
        newChangeSigner,
        paymentAmount: batchPayment,
        expectedChangeAmount: expectedChange,
        transportTier: transportRes.tier,
      });
    }

    return {
      vault,
      asset,
      executedBatches,
      uncombinableSlipIds: plan.uncombinableSingletons.map((u) => u.slipId),
    };
  });
}

// ============================================================================
// 5. `assertCanonicalNaraV4SwapCalldata()` — Hard Invariant #1
// ============================================================================

const UR_EXECUTE_ABI = parseAbi([
  'function execute(bytes commands, bytes[] inputs, uint256 deadline)',
  'function execute(bytes commands, bytes[] inputs)',
]);

const V3_EXACT_IN_PARAMS = parseAbiParameters(
  'address recipient, uint256 amountIn, uint256 amountOutMin, bytes path, bool payerIsUser',
);
const WRAP_UNWRAP_PARAMS = parseAbiParameters('address recipient, uint256 amountMin');
const SWEEP_PARAMS = parseAbiParameters('address token, address recipient, uint256 amountMin');
const V4_SWAP_PARAMS = parseAbiParameters('bytes actions, bytes[] params');
const V4_SINGLE_PARAMS = parseAbiParameters(
  '((address currency0, address currency1, uint24 fee, int24 tickSpacing, address hooks) poolKey, bool zeroForOne, uint128 amountIn, uint128 amountOutMinimum, bytes hookData)',
);
const V4_TAKE_PARAMS = parseAbiParameters('address currency, address recipient, uint256 amount');
const V4_TAKE_ALL_PARAMS = parseAbiParameters('address currency, uint256 minAmount');

const ALLOWED_NARA_UR_COMMANDS = new Set([0x00, 0x04, 0x0b, 0x0c, 0x10]);
const ALLOWED_NARA_V4_ACTIONS = new Set([0x06, 0x0b, 0x0c, 0x0e, 0x0f]);

const SECONDARY_V3_NARA_POOL_NO_PREFIX = 'eed718d239c5508775e312f60eb12792a49d4bba';
const RETIRED_NARA_V4_HOOK_NO_PREFIX = '59aef9799dea01a7fb7da73bea10dfb08858a088';
const AERODROME_CLASSIC_ROUTER_LOWER = '0xcf77a3ba9a5ca399b7c97c74d54e5b1beb874e43';
const AERODROME_SLIPSTREAM_ROUTER_LOWER = '0xbe6d8f0d05cc4be24d5167a3ef062215be6d18a5';

export interface ValidateNaraV4SwapOptions {
  swapTarget: Address | string;
  swapData: Hex;
  /** `true` when buying `NARA` with `USDC`, `false` when selling `NARA` into `USDC`. */
  expectZeroForOne?: boolean;
  minNaraIn?: bigint;
  minAmountOut?: bigint;
  expectedRecipient?: Address | string;
}

/**
 * Enforces Hard Invariant #1 (`NO V3 IN OFFICIAL APPS EVER` — `shared/relayCore.mjs:assertNaraLegUsesCanonicalV4Hook` parity):
 * Validates `UniversalRouter` calldata for any `NARA` swap leg, hard-rejecting Uniswap V3 NARA pools (`0xEEd718...`),
 * `SwapRouter02`, Aerodrome routers/pools, external aggregators (`LI.FI`, `KyberSwap`, `ParaSwap`), and retired hooks,
 * and requiring 100% execution through `NARALiquidityHookV5` (`0x07d8F2Dfd121B10dE3176DeAb6A8C0eaa2646aCC`).
 */
export function assertCanonicalNaraV4SwapCalldata(options: ValidateNaraV4SwapOptions): void {
  const { swapTarget, swapData } = options;
  if (!swapTarget || !isAddress(swapTarget)) {
    throw new NonCanonicalNaraSwapError('Invalid swapTarget address.');
  }
  const targetLower = swapTarget.toLowerCase();
  if (
    targetLower === AERODROME_CLASSIC_ROUTER_LOWER ||
    targetLower === AERODROME_SLIPSTREAM_ROUTER_LOWER
  ) {
    throw new NonCanonicalNaraSwapError(
      'Aerodrome routers are strictly forbidden for NARA swaps; must use UniversalRouter + NARALiquidityHookV5.',
    );
  }
  if (targetLower !== UNIVERSAL_ROUTER_ADDRESS.toLowerCase()) {
    throw new NonCanonicalNaraSwapError(
      `NARA swapTarget (${swapTarget}) must be canonical Uniswap UniversalRouter (${UNIVERSAL_ROUTER_ADDRESS}).`,
    );
  }

  if (typeof swapData !== 'string' || !/^0x[0-9a-fA-F]{8,}$/.test(swapData) || swapData.length % 2 !== 0) {
    throw new NonCanonicalNaraSwapError('Malformed NARA swapData hex string.');
  }

  // Strip optional ERC-8021 builder code suffix before ABI decoding if present
  let cleanCalldata = swapData as Hex;
  if (cleanCalldata.toLowerCase().endsWith('80218021802180218021802180218021')) {
    const bodyWithoutMarker = cleanCalldata.slice(0, -36); // 16B marker + 1B schema + 1B len
    const lenByteHex = cleanCalldata.slice(-36, -34);
    const codeLenBytes = Number.parseInt(lenByteHex, 16);
    if (Number.isFinite(codeLenBytes) && bodyWithoutMarker.length >= 10 + codeLenBytes * 2) {
      cleanCalldata = bodyWithoutMarker.slice(0, bodyWithoutMarker.length - codeLenBytes * 2) as Hex;
    }
  }

  const dataLower = cleanCalldata.toLowerCase();
  if (
    dataLower.includes(SECONDARY_V3_NARA_POOL_NO_PREFIX) ||
    dataLower.includes(RETIRED_NARA_V4_HOOK_NO_PREFIX)
  ) {
    throw new NonCanonicalNaraSwapError(
      'Secondary Uniswap V3 NARA pool (0xEEd718...) and retired V4 hooks are permanently forbidden.',
    );
  }

  let commandsHex: string;
  let inputs: readonly Hex[];
  try {
    const decoded = decodeFunctionData({
      abi: UR_EXECUTE_ABI,
      data: cleanCalldata,
    });
    commandsHex = decoded.args[0].slice(2).toLowerCase();
    inputs = decoded.args[1];
  } catch {
    throw new NonCanonicalNaraSwapError(
      'NARA swapData must be valid UniversalRouter.execute(bytes,bytes[,uint256]) calldata.',
    );
  }

  if (commandsHex.length === 0 || commandsHex.length % 2 !== 0 || inputs.length !== commandsHex.length / 2) {
    throw new NonCanonicalNaraSwapError('UniversalRouter commands and inputs length mismatch.');
  }

  const usdcLower = USDC_BASE_ADDRESS.toLowerCase();
  const naraLower = NARA_BASE_ADDRESS.toLowerCase();
  const naraNoPrefix = naraLower.slice(2);
  const expectedHookLower = NARA_LIQUIDITY_HOOK_V5_ADDRESS.toLowerCase();
  const expectedRecipLower = options.expectedRecipient?.toLowerCase();
  const canonicalBridgeTokens = new Set<string>([
    usdcLower,
    WETH_BASE_ADDRESS.toLowerCase(),
    CBBTC_BASE_ADDRESS.toLowerCase(),
  ]);

  const isAllowedRouterRecipient = (rec: string): boolean => {
    const r = rec.toLowerCase();
    return (
      r === '0x0000000000000000000000000000000000000001' ||
      r === '0x0000000000000000000000000000000000000002' ||
      (expectedRecipLower !== undefined && r === expectedRecipLower) ||
      expectedRecipLower === undefined
    );
  };

  let sawCanonicalV4Hook = false;
  const cmdCount = commandsHex.length / 2;

  for (let i = 0; i < cmdCount; i++) {
    const rawCmd = Number.parseInt(commandsHex.slice(i * 2, i * 2 + 2), 16);
    if ((rawCmd & 0x80) !== 0) {
      throw new NonCanonicalNaraSwapError('UniversalRouter FLAG_ALLOW_REVERT (0x80) is forbidden.');
    }
    const cmd = rawCmd & 0x3f;
    if (!ALLOWED_NARA_UR_COMMANDS.has(cmd)) {
      throw new NonCanonicalNaraSwapError(
        `Disallowed UniversalRouter command 0x${cmd.toString(16).padStart(2, '0')} in NARA swap.`,
      );
    }
    const inp = inputs[i]!;

    if (cmd === 0x00) {
      let recipient: Address;
      let path: Hex;
      try {
        [recipient, , , path] = decodeAbiParameters(V3_EXACT_IN_PARAMS, inp);
      } catch {
        throw new NonCanonicalNaraSwapError('Malformed V3_SWAP_EXACT_IN input in UniversalRouter.');
      }
      if (path.toLowerCase().includes(naraNoPrefix) || inp.toLowerCase().includes(naraNoPrefix)) {
        throw new NonCanonicalNaraSwapError(
          'Uniswap V3 NARA routing is strictly forbidden; NARA leg must execute via NARALiquidityHookV5.',
        );
      }
      const pathHex = path.slice(2).toLowerCase();
      if (pathHex.length < 86 || (pathHex.length - 40) % 46 !== 0) {
        throw new NonCanonicalNaraSwapError('Invalid V3 bridge path byte length.');
      }
      for (let off = 0; off + 40 <= pathHex.length; off += 46) {
        const hopToken = `0x${pathHex.slice(off, off + 40)}`;
        if (!canonicalBridgeTokens.has(hopToken)) {
          throw new NonCanonicalNaraSwapError(`Disallowed V3 bridge token ${hopToken}.`);
        }
      }
      if (!isAllowedRouterRecipient(recipient)) {
        throw new NonCanonicalNaraSwapError(`Disallowed V3 swap recipient ${recipient}.`);
      }
    } else if (cmd === 0x0b || cmd === 0x0c) {
      let recipient: Address;
      try {
        [recipient] = decodeAbiParameters(WRAP_UNWRAP_PARAMS, inp);
      } catch {
        throw new NonCanonicalNaraSwapError('Malformed WRAP_ETH / UNWRAP_WETH input.');
      }
      if (!isAllowedRouterRecipient(recipient)) {
        throw new NonCanonicalNaraSwapError(`Disallowed wrap/unwrap recipient ${recipient}.`);
      }
    } else if (cmd === 0x04) {
      let recipient: Address;
      try {
        [, recipient] = decodeAbiParameters(SWEEP_PARAMS, inp);
      } catch {
        throw new NonCanonicalNaraSwapError('Malformed SWEEP input.');
      }
      if (!isAllowedRouterRecipient(recipient)) {
        throw new NonCanonicalNaraSwapError(`Disallowed SWEEP recipient ${recipient}.`);
      }
    } else if (cmd === 0x10) {
      let actions: Hex;
      let params: readonly Hex[];
      try {
        [actions, params] = decodeAbiParameters(V4_SWAP_PARAMS, inp);
      } catch {
        throw new NonCanonicalNaraSwapError('Malformed V4_SWAP encoding.');
      }
      const actionsHex = actions.slice(2).toLowerCase();
      if (actionsHex.length < 4 || actionsHex.length % 2 !== 0) {
        throw new NonCanonicalNaraSwapError('Invalid V4_SWAP actions byte length.');
      }
      const actionBytes: number[] = [];
      for (let j = 0; j < actionsHex.length; j += 2) {
        const ab = Number.parseInt(actionsHex.slice(j, j + 2), 16);
        if (!ALLOWED_NARA_V4_ACTIONS.has(ab)) {
          throw new NonCanonicalNaraSwapError(`Disallowed V4 action 0x${ab.toString(16)} in NARA swap.`);
        }
        actionBytes.push(ab);
      }
      const lastAction = actionBytes[actionBytes.length - 1];
      const hasSubsequentCmd = i + 1 < cmdCount;
      if (
        params.length !== actionBytes.length ||
        (lastAction !== 0x0f && !(lastAction === 0x0e && hasSubsequentCmd))
      ) {
        throw new NonCanonicalNaraSwapError(
          'V4_SWAP actions must match params length and end with TAKE_ALL (0x0f) or chained TAKE (0x0e).',
        );
      }

      let matchedSingleSwap = false;
      for (let j = 0; j < actionBytes.length; j++) {
        const ab = actionBytes[j]!;
        const param = params[j]!;
        if (ab === 0x06) {
          let single: {
            poolKey: {
              currency0: Address;
              currency1: Address;
              fee: number;
              tickSpacing: number;
              hooks: Address;
            };
            zeroForOne: boolean;
            amountIn: bigint;
            amountOutMinimum: bigint;
          };
          try {
            [single] = decodeAbiParameters(V4_SINGLE_PARAMS, param);
          } catch {
            throw new NonCanonicalNaraSwapError('Malformed V4 SWAP_EXACT_IN_SINGLE params.');
          }
          const pk = single.poolKey;
          if (
            pk.currency0.toLowerCase() !== usdcLower ||
            pk.currency1.toLowerCase() !== naraLower ||
            Number(pk.fee) !== 3000 ||
            Number(pk.tickSpacing) !== 60 ||
            pk.hooks.toLowerCase() !== expectedHookLower
          ) {
            throw new NonCanonicalNaraSwapError(
              `V4 PoolKey (${pk.hooks}) does not match canonical NARA V5 hooked pool (${NARA_LIQUIDITY_HOOK_V5_ADDRESS}).`,
            );
          }
          if (
            options.expectZeroForOne !== undefined &&
            Boolean(single.zeroForOne) !== Boolean(options.expectZeroForOne)
          ) {
            throw new NonCanonicalNaraSwapError('V4 swap zeroForOne direction mismatch.');
          }
          if (options.minNaraIn !== undefined && options.minNaraIn > 0n && single.amountIn < options.minNaraIn) {
            throw new NonCanonicalNaraSwapError('V4 amountIn is below required NARA input.');
          }
          if (single.amountIn === 0n && !actionBytes.includes(0x0b)) {
            throw new NonCanonicalNaraSwapError('V4 amountIn cannot be 0 without SETTLE (0x0b).');
          }
          if (
            options.minAmountOut !== undefined &&
            options.minAmountOut > 0n &&
            single.amountOutMinimum < options.minAmountOut
          ) {
            throw new NonCanonicalNaraSwapError('V4 amountOutMinimum is below required minimum output.');
          }
          matchedSingleSwap = true;
        } else if (ab === 0x0e) {
          if (j !== actionBytes.length - 1 || !hasSubsequentCmd) {
            throw new NonCanonicalNaraSwapError('Intermediate V4 TAKE (0x0e) action is forbidden.');
          }
          let takeCurrency: Address;
          let takeRecipient: Address;
          let takeAmount: bigint;
          try {
            [takeCurrency, takeRecipient, takeAmount] = decodeAbiParameters(V4_TAKE_PARAMS, param);
          } catch {
            throw new NonCanonicalNaraSwapError('Malformed V4 TAKE params.');
          }
          if (takeRecipient.toLowerCase() !== '0x0000000000000000000000000000000000000002') {
            throw new NonCanonicalNaraSwapError('V4 chained TAKE recipient must be ADDRESS_THIS (0x...0002).');
          }
          if (takeAmount !== 0n) {
            throw new NonCanonicalNaraSwapError('V4 chained TAKE amount must be OPEN_DELTA (0).');
          }
          if (options.expectZeroForOne !== undefined) {
            const expectedCurrency = options.expectZeroForOne ? naraLower : usdcLower;
            if (takeCurrency.toLowerCase() !== expectedCurrency) {
              throw new NonCanonicalNaraSwapError('V4 TAKE output currency mismatch.');
            }
          }
        } else if (ab === 0x0f) {
          if (j !== actionBytes.length - 1) {
            throw new NonCanonicalNaraSwapError('Intermediate V4 TAKE_ALL (0x0f) action is forbidden.');
          }
          let takeCurrency: Address;
          let takeMin: bigint;
          try {
            [takeCurrency, takeMin] = decodeAbiParameters(V4_TAKE_ALL_PARAMS, param);
          } catch {
            throw new NonCanonicalNaraSwapError('Malformed V4 TAKE_ALL params.');
          }
          if (options.expectZeroForOne !== undefined) {
            const expectedCurrency = options.expectZeroForOne ? naraLower : usdcLower;
            if (takeCurrency.toLowerCase() !== expectedCurrency) {
              throw new NonCanonicalNaraSwapError('V4 TAKE_ALL output currency mismatch.');
            }
          }
          if (options.minAmountOut !== undefined && options.minAmountOut > 0n && takeMin < options.minAmountOut) {
            throw new NonCanonicalNaraSwapError('V4 TAKE_ALL minAmount is below required output.');
          }
        }
      }

      if (!matchedSingleSwap) {
        throw new NonCanonicalNaraSwapError('V4_SWAP must include SWAP_EXACT_IN_SINGLE (0x06).');
      }
      sawCanonicalV4Hook = true;
    }
  }

  if (!sawCanonicalV4Hook) {
    throw new NonCanonicalNaraSwapError(
      'UniversalRouter calldata must execute NARA leg via canonical NARALiquidityHookV5.',
    );
  }
}

// ============================================================================
// 6. `refundSlipDirect()`, `scanReclaimableSlips()` & `withdrawReferralCredits()`
// ============================================================================

export interface RefundSlipDirectOptions {
  publicClient: BaseCompatiblePublicClient;
  slipId: bigint | number | string;
  vault?: VaultTag;
  walletClient?: BaseCompatibleWalletClient;
  paymasterSignerKey?: Hex;
  useCirclePaymaster?: boolean;
  bundlerUrls?: readonly string[];
  bundlerFetch?: BundlerFetchFn;
  mutex?: SlipMutex;
  onStatus?: (msg: string) => void;
}

export interface RefundSlipDirectResult {
  readonly txHash: Hex;
  readonly slipId: bigint;
  readonly vault: VaultTag;
  readonly asset: SdkAssetSymbol;
  readonly refundedAmountUnits: bigint;
  readonly feeUnits: 0n;
  readonly transportTier: 'circle_paymaster' | 'direct_eoa';
}

/**
 * Executes direct `vault.refundSlip(slipId)` from the creator/beneficiary wallet (`0%` fee for
 * un-kept revocable slips where `cancelLockedUntil == 0n`), via Circle `TokenPaymasterV08` or direct Base tx.
 */
export async function refundSlipDirect(
  options: RefundSlipDirectOptions,
): Promise<RefundSlipDirectResult> {
  const { publicClient, vault = ISSUE_VAULT, mutex = defaultSlipMutex } = options;
  const slipId = BigInt(options.slipId);
  const lockKey = SlipMutex.keyFor(vault, slipId);

  return mutex.runExclusive(lockKey, async () => {
    const state = await readOnChainSlip({ publicClient, slipId, vault });
    if (state.status !== SlipStatus.ACTIVE) {
      throw new SlipOperationError(
        `Slip #${slipId.toString()} is not active (status=${state.status}).`,
      );
    }
    const headTs = await resolveChainHeadTimestamp(publicClient);
    if (state.cancelLockedUntil > headTs) {
      throw new SlipOperationError(
        `Slip #${slipId.toString()} has No take-back enabled and cannot be refunded.`,
      );
    }
    if (state.refundFeeRequired || state.nonce > 0n) {
      throw new SlipOperationError(
        `Slip #${slipId.toString()} has already been kept/rotated (nonces=${state.nonce.toString()}); 0%-fee creator refund is no longer available.`,
      );
    }

    const rawCallData = encodeFunctionData({
      abi: CRYPTO_SLIP_VAULT_V32_ABI,
      functionName: 'refundSlip',
      args: [slipId],
    });

    if (options.paymasterSignerKey && (options.useCirclePaymaster || !options.walletClient)) {
      const pmRes = await executeViaCircleUsdcPaymaster({
        signerKey: options.paymasterSignerKey,
        calls: [{ to: state.vaultAddress, data: rawCallData }],
        publicClient,
        bundlerUrls: options.bundlerUrls,
        bundlerFetch: options.bundlerFetch,
        onStatus: options.onStatus,
      });
      return {
        txHash: pmRes.txHash,
        slipId,
        vault,
        asset: state.asset,
        refundedAmountUnits: state.amount,
        feeUnits: 0n,
        transportTier: 'circle_paymaster',
      };
    }

    if (!options.walletClient) {
      throw new SlipOperationError(
        'refundSlipDirect requires walletClient or paymasterSignerKey.',
      );
    }
    const account = options.walletClient.account;
    if (!account) {
      throw new SlipOperationError('walletClient must have an attached account.');
    }
    if (account.address.toLowerCase() !== state.refundBeneficiary.toLowerCase()) {
      throw new SlipOperationError(
        `Caller (${account.address}) does not match slip refundBeneficiary (${state.refundBeneficiary}).`,
      );
    }

    const attributed = appendBuilderCodeSuffix(rawCallData, DEFAULT_CRYPTOSLIP_BUILDER_CODE);
    const txHash = await options.walletClient.sendTransaction({
      account,
      chain: options.walletClient.chain ?? null,
      to: state.vaultAddress,
      value: 0n,
      data: attributed,
    });

    return {
      txHash,
      slipId,
      vault,
      asset: state.asset,
      refundedAmountUnits: state.amount,
      feeUnits: 0n,
      transportTier: 'direct_eoa',
    };
  });
}

export interface ScanReclaimableSlipsOptions {
  publicClient: BaseCompatiblePublicClient;
  creator: Address;
  vault?: VaultTag;
  /** Optional explicit candidate `slipIds` to check; if omitted, scans the most recent `scanWindow` slips on `vault`. */
  candidateSlipIds?: readonly (bigint | number | string)[];
  /** Number of recent slips to scan backwards from `vault.totalSlips()` (defaults to `400`). */
  scanWindow?: number;
  /** Minimum age in seconds before an unclaimed DM/bounty slip is returned (e.g. `7 * 86400` for 7 days; defaults to `0`). */
  minAgeSeconds?: number;
  currentTimestampSec?: bigint | number;
}

export interface ReclaimableSlipSummary {
  readonly slipId: bigint;
  readonly vault: VaultTag;
  readonly asset: SdkAssetSymbol;
  readonly amount: bigint;
  readonly createdAt: number;
  readonly ageSeconds: number;
  readonly claimSigner: Address;
}

/**
 * Scans `CryptoSlipVaultV32` via `Multicall3.aggregate3` (with automatic `readOnChainSlip` fallback)
 * to discover revocable, un-kept DM / bounty links created by `creator` where:
 * `status === ACTIVE && cancelLockedUntil === 0n && nonces === 0n && !refundFeeRequired && age >= minAgeSeconds`.
 */
export async function scanReclaimableSlips(
  options: ScanReclaimableSlipsOptions,
): Promise<ReclaimableSlipSummary[]> {
  const {
    publicClient,
    vault = ISSUE_VAULT,
    scanWindow = 400,
    minAgeSeconds = 0,
  } = options;
  const creatorLower = getAddress(options.creator).toLowerCase();
  const vAddr = vaultAddress(vault);
  const nowSec = Number(await resolveChainHeadTimestamp(publicClient, options.currentTimestampSec));

  let idsToScan: bigint[] = [];
  if (options.candidateSlipIds && options.candidateSlipIds.length > 0) {
    idsToScan = options.candidateSlipIds.map((id) => BigInt(id)).filter((id) => id > 0n);
  } else {
    const total = await publicClient.readContract({
      address: vAddr,
      abi: CRYPTO_SLIP_VAULT_V32_ABI,
      functionName: 'totalSlips',
    });
    if (total === 0n) return [];
    const count = BigInt(Math.max(1, scanWindow));
    const start = total > count ? total - count + 1n : 1n;
    for (let id = total; id >= start; id -= 1n) {
      idsToScan.push(id);
    }
  }

  const reclaimable: ReclaimableSlipSummary[] = [];

  // Batch via Multicall3 in chunks of 150 slips (3 calls per slip = 450 subcalls)
  for (let offset = 0; offset < idsToScan.length; offset += 150) {
    const chunk = idsToScan.slice(offset, offset + 150);
    let handledViaMulticall = false;

    try {
      const calls = chunk.flatMap((id) => [
        {
          target: vAddr,
          allowFailure: true,
          callData: encodeFunctionData({
            abi: CRYPTO_SLIP_VAULT_V32_ABI,
            functionName: 'slips',
            args: [id],
          }),
        },
        {
          target: vAddr,
          allowFailure: true,
          callData: encodeFunctionData({
            abi: CRYPTO_SLIP_VAULT_V32_ABI,
            functionName: 'nonces',
            args: [id],
          }),
        },
        {
          target: vAddr,
          allowFailure: true,
          callData: encodeFunctionData({
            abi: CRYPTO_SLIP_VAULT_V32_ABI,
            functionName: 'refundFeeRequired',
            args: [id],
          }),
        },
      ]);

      const multicallViewAbi = parseAbi([
        'function aggregate3((address target, bool allowFailure, bytes callData)[] calls) view returns ((bool success, bytes returnData)[])',
      ]);
      const rawResults = await publicClient.readContract({
        address: MULTICALL3_ADDRESS,
        abi: multicallViewAbi,
        functionName: 'aggregate3',
        args: [calls],
      });

      if (rawResults.length === chunk.length * 3) {
        handledViaMulticall = true;
        const slipOutParams = parseAbiParameters(
          'address asset, uint256 amount, uint48 createdAt, uint48 cancelLockedUntil, address creator, address claimSigner, uint8 status',
        );
        const uintParam = parseAbiParameters('uint256');
        const boolParam = parseAbiParameters('bool');

        for (let i = 0; i < chunk.length; i++) {
          const slipId = chunk[i]!;
          const rSlip = rawResults[i * 3];
          const rNonce = rawResults[i * 3 + 1];
          const rFee = rawResults[i * 3 + 2];
          if (!rSlip?.success || !rNonce?.success || !rFee?.success) continue;

          const [assetAddr, amount, createdAtRaw, cancelLockedRaw, sCreator, sClaimSigner, status] =
            decodeAbiParameters(slipOutParams, rSlip.returnData);
          const [nonce] = decodeAbiParameters(uintParam, rNonce.returnData);
          const [feeReq] = decodeAbiParameters(boolParam, rFee.returnData);

          const createdAt = Number(createdAtRaw);
          const ageSeconds = Math.max(0, nowSec - createdAt);

          if (
            Number(status) === SlipStatus.ACTIVE &&
            BigInt(cancelLockedRaw) === 0n &&
            nonce === 0n &&
            !feeReq &&
            sCreator.toLowerCase() === creatorLower &&
            sCreator.toLowerCase() !== sClaimSigner.toLowerCase() &&
            ageSeconds >= minAgeSeconds
          ) {
            reclaimable.push({
              slipId,
              vault,
              asset: resolveAssetMetadata(assetAddr).symbol,
              amount,
              createdAt,
              ageSeconds,
              claimSigner: getAddress(sClaimSigner),
            });
          }
        }
      }
    } catch {
      handledViaMulticall = false;
    }

    if (!handledViaMulticall) {
      const records = await Promise.all(
        chunk.map((id) => readOnChainSlip({ publicClient, slipId: id, vault }).catch(() => null)),
      );
      for (const rec of records) {
        if (!rec) continue;
        const ageSeconds = Math.max(0, nowSec - rec.createdAt);
        if (
          rec.status === SlipStatus.ACTIVE &&
          rec.cancelLockedUntil === 0n &&
          rec.nonce === 0n &&
          !rec.refundFeeRequired &&
          rec.creator.toLowerCase() === creatorLower &&
          rec.creator.toLowerCase() !== rec.claimSigner.toLowerCase() &&
          ageSeconds >= minAgeSeconds
        ) {
          reclaimable.push({
            slipId: rec.slipId,
            vault,
            asset: rec.asset,
            amount: rec.amount,
            createdAt: rec.createdAt,
            ageSeconds,
            claimSigner: rec.claimSigner,
          });
        }
      }
    }
  }

  return reclaimable;
}

export interface WithdrawReferralCreditsOptions {
  publicClient: BaseCompatiblePublicClient;
  referrer?: Address;
  to?: Address;
  assets?: readonly AnyAssetSymbol[];
  vault?: VaultTag;
  walletClient?: BaseCompatibleWalletClient;
  paymasterSignerKey?: Hex;
  useCirclePaymaster?: boolean;
  bundlerUrls?: readonly string[];
  bundlerFetch?: BundlerFetchFn;
  onStatus?: (msg: string) => void;
}

export interface ReferralCreditWithdrawalResult {
  readonly vault: VaultTag;
  readonly referrer: Address;
  readonly to: Address;
  readonly withdrawnByAsset: Readonly<Partial<Record<SdkAssetSymbol, bigint>>>;
  readonly txHashes: readonly Hex[];
}

/**
 * Reads accumulated `0.25%` lifetime `referralCredits[referrer][asset]` across canonical Base assets
 * (`USDC`, `cbBTC`, `ETH`, `NARA`) and withdraws all non-zero balances to `to` in 1 Circle Paymaster
 * `Simple7702Account.executeBatch` UserOp or direct Base transaction(s).
 */
export async function withdrawReferralCredits(
  options: WithdrawReferralCreditsOptions,
): Promise<ReferralCreditWithdrawalResult> {
  const {
    publicClient,
    vault = ISSUE_VAULT,
    assets = ['USDC', 'cbBTC', 'ETH', 'NARA'],
  } = options;
  if (!isV32ProtocolVault(vault)) {
    throw new SlipOperationError(`withdrawReferralCredits requires a V3.2 vault ('v33' or 'v32').`);
  }

  const referrerAddr = options.referrer
    ? getAddress(options.referrer)
    : options.walletClient?.account
      ? getAddress(options.walletClient.account.address)
      : options.paymasterSignerKey
        ? getAddress(
            privateKeyToAccount(
              (options.paymasterSignerKey.startsWith('0x')
                ? options.paymasterSignerKey
                : `0x${options.paymasterSignerKey}`) as Hex,
            ).address,
          )
        : (() => {
            throw new SlipOperationError('referrer address, walletClient, or paymasterSignerKey is required.');
          })();

  const destination = options.to ? getAddress(options.to) : referrerAddr;
  if (BLOCKED_PAYMENT_TARGETS.has(destination.toLowerCase())) {
    throw new SlipOperationError(`Destination ${destination} is a blocked address.`);
  }

  const vAddr = vaultAddress(vault);
  const uniqueAssets = [...new Set(assets.map((a) => normalizeSdkAsset(a)))];

  const balances = await Promise.all(
    uniqueAssets.map(async (sym) => {
      const tokenAddr = assetAddress(sym);
      const credit = await publicClient.readContract({
        address: vAddr,
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        functionName: 'referralCredits',
        args: [referrerAddr, tokenAddr],
      });
      return { symbol: sym, tokenAddr, credit };
    }),
  );

  const nonZero = balances.filter((b) => b.credit > 0n);
  const withdrawnByAsset: Partial<Record<SdkAssetSymbol, bigint>> = {};
  for (const b of nonZero) {
    withdrawnByAsset[b.symbol] = b.credit;
  }

  if (nonZero.length === 0) {
    return {
      vault,
      referrer: referrerAddr,
      to: destination,
      withdrawnByAsset,
      txHashes: [],
    };
  }

  const calls: UserOpCall[] = nonZero.map((b) => ({
    to: vAddr,
    data: encodeFunctionData({
      abi: CRYPTO_SLIP_VAULT_V32_ABI,
      functionName: 'withdrawReferralCredits',
      args: [b.tokenAddr, destination],
    }),
  }));

  if (options.paymasterSignerKey && (options.useCirclePaymaster || !options.walletClient)) {
    const pmRes = await executeViaCircleUsdcPaymaster({
      signerKey: options.paymasterSignerKey,
      calls,
      publicClient,
      bundlerUrls: options.bundlerUrls,
      bundlerFetch: options.bundlerFetch,
      onStatus: options.onStatus,
    });
    return {
      vault,
      referrer: referrerAddr,
      to: destination,
      withdrawnByAsset,
      txHashes: [pmRes.txHash],
    };
  }

  if (!options.walletClient?.account) {
    throw new SlipOperationError('walletClient with account (or paymasterSignerKey) is required.');
  }

  const account = options.walletClient.account;
  const senderCode = (await publicClient.getCode({ address: account.address }).catch(() => '0x')) ?? '0x';
  const isDelegated7702 =
    senderCode.toLowerCase() === '0xef0100e6cae83bde06e4c305530e199d7217f42808555b';

  if (calls.length > 1 && isDelegated7702) {
    const batchData = appendBuilderCodeSuffix(
      encodeSimple7702Calls(calls),
      DEFAULT_CRYPTOSLIP_BUILDER_CODE,
    );
    const txHash = await options.walletClient.sendTransaction({
      account,
      chain: options.walletClient.chain ?? null,
      to: account.address,
      value: 0n,
      data: batchData,
    });
    return {
      vault,
      referrer: referrerAddr,
      to: destination,
      withdrawnByAsset,
      txHashes: [txHash],
    };
  }

  const txHashes: Hex[] = [];
  for (const call of calls) {
    const attributed = appendBuilderCodeSuffix(call.data, DEFAULT_CRYPTOSLIP_BUILDER_CODE);
    const txHash = await options.walletClient.sendTransaction({
      account,
      chain: options.walletClient.chain ?? null,
      to: call.to,
      value: 0n,
      data: attributed,
    });
    txHashes.push(txHash);
  }

  return {
    vault,
    referrer: referrerAddr,
    to: destination,
    withdrawnByAsset,
    txHashes,
  };
}
