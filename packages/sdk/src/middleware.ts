import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import {
  decodeEventLog,
  formatUnits,
  getAddress,
  isAddress,
  isHex,
  type Address,
  type Hex,
} from 'viem';
import {
  CRYPTO_SLIP_TRADE_ROUTER_V32_ABI,
  CRYPTO_SLIP_VAULT_V32_ABI,
  ERC20_PERMIT_EIP3009_ABI,
} from './abi.js';
import {
  AKASH_RELAY_GATEWAY,
  BASE_CHAIN_ID,
  BLOCKED_PAYMENT_TARGETS,
  CANONICAL_SHARE_ORIGIN,
  DEFAULT_CRYPTOSLIP_BUILDER_CODE,
  ISSUE_VAULT,
  MAX_COMBINE_SLIPS,
  NO_TAKE_BACK_LOCK,
  OFFGRID_PERMANENT_LOCK_UNTIL,
  SlipStatus,
  VAULTS,
  WORKER_RELAY_GATEWAY,
  ZERO_ADDRESS,
  assetAddress,
  computeProtocolFeeCeiling,
  decimalsForAsset,
  deductProtocolFeeCeiling,
  grossUpForExactNet,
  minSlipAmount,
  normalizeSdkAsset,
  tradeRouterForVault,
  vaultTagForAddress,
  type AnyAssetSymbol,
  type SdkAssetSymbol,
} from './constants.js';
import {
  assertFragmentSafeUrl,
  buildPopupCheckoutUrl,
  buildWatchOnlyPosUrl,
  encodeSlipUrl,
  parseSlipUrl,
} from './link.js';
import { computePermitDeadline, signCashPermit } from './permits.js';
import {
  createSignedPaymentReceipt,
  verifyPaymentReceiptOnChain,
  type PaymentReceiptBundleV1,
  type ReceiptIssuerSigner,
  type ReceiptSettlementType,
  type ReceiptVerificationPublicClient,
} from './receipts.js';
import { voiceBase64UrlToBytes, voiceBytesToBase64Url } from './voice.js';

export const X_SLIP_HEADER = 'X-Slip' as const;
export const X_PAYMENT_TX_HEADER = 'X-Payment-Tx' as const;
export const X_ORDER_ID_HEADER = 'X-Order-Id' as const;
export const X_CRYPTOSLIP_ACCEPT_HEADER = 'X-CryptoSlip-Accept' as const;
export const X_CRYPTOSLIP_ERROR_HEADER = 'X-CryptoSlip-Error' as const;
export const X_PAYMENT_RECEIPT_HEADER = 'X-Payment-Receipt' as const;
export const X_PAYMENT_REFUND_SLIP_HEADER = 'X-Payment-Refund-Slip' as const;
export const X_PAYMENT_REFUND_AMOUNT_HEADER = 'X-Payment-Refund-Amount' as const;
export const X_CRYPTOSLIP_PARTNER_KEY_HEADER = 'X-CryptoSLIP-Partner-Key' as const;
export const X_CRYPTOSLIP_EVENT_HEADER = 'X-CryptoSLIP-Event' as const;
export const X_CRYPTOSLIP_DELIVERY_ID_HEADER = 'X-CryptoSLIP-Delivery-Id' as const;
export const X_CRYPTOSLIP_SIGNATURE_HEADER = 'X-CryptoSLIP-Signature' as const;

// ============================================================================
// Replay & Concurrent Race Defense (`V-03` / Module #3)
// ============================================================================

export type ReplayAcquireOutcome =
  | { acquired: true; keys: string[] }
  | { acquired: false; reason: 'in_flight'; conflictKey: string }
  | {
      acquired: false;
      reason: 'already_settled';
      conflictKey: string;
      receipt: PaymentReceiptBundleV1;
    };

/**
 * Deterministic in-process replay & race lock combining an atomic synchronous `inFlight` `Set`
 * with a bounded `settled` LRU cache keyed by `slip:<vaultLower>:<slipId>` and `tx:<txHashLower>`.
 *
 * Because `tryAcquire()` checks and mutates `inFlight` synchronously BEFORE any `await`, two
 * concurrent HTTP requests submitting the same `slipId` can NEVER both pass!
 */
export class SlipReplayGuard {
  private readonly inFlight = new Set<string>();
  private readonly settled = new Map<string, PaymentReceiptBundleV1>();
  private readonly maxSettledEntries: number;

  constructor(maxSettledEntries = 10_000) {
    this.maxSettledEntries = Math.max(64, maxSettledEntries);
  }

  static slipKey(vaultAddress: string, slipId: string | bigint | number): string {
    return `slip:${vaultAddress.toLowerCase()}:${BigInt(slipId).toString(10)}`;
  }

  static txKey(txHash: string): string {
    return `tx:${txHash.toLowerCase()}`;
  }

  tryAcquire(rawKeys: readonly string[]): ReplayAcquireOutcome {
    const keys = [...new Set(rawKeys.map((k) => k.trim().toLowerCase()).filter(Boolean))];
    if (keys.length === 0) {
      throw new Error('SlipReplayGuard requires at least one lock key');
    }

    for (const key of keys) {
      const existingReceipt = this.settled.get(key);
      if (existingReceipt) {
        // Refresh LRU position
        this.settled.delete(key);
        this.settled.set(key, existingReceipt);
        return {
          acquired: false,
          reason: 'already_settled',
          conflictKey: key,
          receipt: existingReceipt,
        };
      }
      if (this.inFlight.has(key)) {
        return {
          acquired: false,
          reason: 'in_flight',
          conflictKey: key,
        };
      }
    }

    for (const key of keys) {
      this.inFlight.add(key);
    }
    return { acquired: true, keys };
  }

  commit(keys: readonly string[], receipt: PaymentReceiptBundleV1): void {
    for (const raw of keys) {
      const key = raw.trim().toLowerCase();
      if (!key) continue;
      this.inFlight.delete(key);
      if (this.settled.has(key)) {
        this.settled.delete(key);
      }
      this.settled.set(key, receipt);
      while (this.settled.size > this.maxSettledEntries) {
        const oldestKey = this.settled.keys().next().value;
        if (oldestKey === undefined) break;
        this.settled.delete(oldestKey);
      }
    }
  }

  release(keys: readonly string[]): void {
    for (const raw of keys) {
      this.inFlight.delete(raw.trim().toLowerCase());
    }
  }

  isInFlight(key: string): boolean {
    return this.inFlight.has(key.trim().toLowerCase());
  }

  getSettled(key: string): PaymentReceiptBundleV1 | undefined {
    return this.settled.get(key.trim().toLowerCase());
  }
}

// ============================================================================
// Tollbooth Configuration, Challenge & Inbound Permit Schemas
// ============================================================================

export type TollboothPublicClient = ReceiptVerificationPublicClient & {
  readContract(args: {
    address: Address;
    abi: readonly unknown[];
    functionName: string;
    args?: readonly unknown[];
  }): Promise<unknown>;
  getBlock?(args?: { blockNumber?: bigint }): Promise<{ timestamp: bigint | number; number?: bigint | number }>;
};

export type InboundSignedPermitPayload =
  | {
      kind?: 'cash';
      vault?: 'v33' | 'v32' | Address;
      slipId: string | number;
      recipient?: Address;
      relayer?: Address;
      deadline: string | number;
      signature: Hex;
      referralConsentSignature?: Hex;
    }
  | {
      kind: 'split';
      vault?: 'v33' | 'v32' | Address;
      slipId: string | number;
      paymentAmount: string;
      merchant: Address;
      changeReceiver: Address;
      newChangeSigner: Address;
      relayer?: Address;
      deadline: string | number;
      signature: Hex;
    }
  | {
      kind: 'combine';
      vault?: 'v33' | 'v32' | Address;
      slipIds: Array<string | number>;
      signatures: Hex[];
      paymentAmount: string;
      merchant: Address;
      changeReceiver: Address;
      newChangeSigner: Address;
      relayer?: Address;
      deadline: string | number;
    };

export interface TollboothSettleRequest {
  mode: 'cash' | 'split' | 'combine';
  vault: 'v33' | 'v32';
  vaultAddress: Address;
  merchantAddress: Address;
  asset: SdkAssetSymbol;
  grossAmount: bigint;
  expectedNetAmount: bigint;
  relayBody: Record<string, unknown>;
}

export interface TollboothSettleResult {
  txHash: Hex;
  blockNumber?: number;
  blockTimestamp?: number;
  grossAmount?: bigint;
  feeAmount?: bigint;
  netAmount?: bigint;
}

export interface CryptoSlipTollboothConfig {
  /** Watch-only destination wallet or cold Safe receiving funds (zero private key on server!). */
  merchantAddress: Address | string;
  /** Accepted asset (`'USDC' | 'cbBTC' | 'ETH' | 'NARA'`, defaults to `'USDC'`). */
  asset?: AnyAssetSymbol;
  /** Minimum net atomic amount merchant must receive (used when `resolveMinNetAmount` is omitted). */
  minNetAmount: bigint;
  /** Optional dynamic per-request pricing hook. */
  resolveMinNetAmount?: (request: Request) => bigint | Promise<bigint>;
  /** Vault tag (`'v33'` default or `'v32'`). */
  vault?: 'v33' | 'v32';
  /** Fee handling mode: `'payer_gross_up'` (`default`, uses `grossUpForExactNet`) or `'merchant_absorbs'`. */
  feeMode?: 'payer_gross_up' | 'merchant_absorbs';
  /**
   * When `true` (`default`), requires inbound slips to carry `No take-back`
   * (`cancelLockedUntil === 9_999_999_999n` and `nonces(slipId) === 0n` on unrotated slips)
   * so senders cannot race a creator `refundSlip` against instant settlement.
   */
  requireNoTakeBack?: boolean;
  merchantLabel?: string;
  resolveOrderId?: (request: Request) => string | undefined;
  appOrigin?: string;
  /** Base `8453` RPC public client used to pre-verify `slips(slipId)` / `nonces(slipId)` and receipts. */
  publicClient: TollboothPublicClient;
  /** Custom settlement executor (defaults to Watch-Only Relay HTTP `/api/relay/{cash,split,rearrange}`). */
  settler?: (req: TollboothSettleRequest) => Promise<TollboothSettleResult>;
  relayUrls?: readonly string[];
  partnerApiKey?: string;
  fetchFn?: typeof fetch;
  /** Optional receipt signer (omit on zero-key watch-only servers). */
  receiptSigner?: ReceiptIssuerSigner;
  /** Verify settled relay `txHash` logs via `verifyPaymentReceiptOnChain` when receipt is available (`default: false` unless `verifySettledTxOnChain: true`, always `true` for `X-Payment-Tx` proofs). */
  verifySettledTxOnChain?: boolean;
  /** HTTP status returned when a concurrent/replayed `slipId` is rejected (`default: 409`). */
  replayStatusCode?: 409 | 402;
  replayGuard?: SlipReplayGuard;
  maxSettledCacheEntries?: number;
}

export interface CryptoSlipChallengeDescriptor {
  version: 1;
  scheme: 'cryptoslip-v32';
  chainId: 8453;
  vault: 'v33' | 'v32';
  vaultAddress: Address;
  recipient: Address;
  asset: SdkAssetSymbol;
  minNetAmount: string;
  grossAmountRequired: string;
  requireNoTakeBack: boolean;
  checkoutUrl: string;
  posUrl: string;
  builderCode: 'bc_ea68lz8s';
  merchantLabel?: string;
  orderId?: string;
}

export interface CryptoSlipSettlementContext {
  receipt: PaymentReceiptBundleV1;
  slipId: string;
  txHash: Hex;
  asset: SdkAssetSymbol;
  vault: 'v33' | 'v32';
  grossAmount: bigint;
  feeAmount: bigint;
  netAmount: bigint;
  minNetAmountRequired: bigint;
  overpaidNetAmount: bigint;
  orderId?: string;
}

export type TollboothVerificationResult =
  | { ok: true; context: CryptoSlipSettlementContext }
  | { ok: false; response: Response };

type OnChainSlipTuple = readonly [
  asset: Address,
  amount: bigint,
  createdAt: number | bigint,
  cancelLockedUntil: number | bigint,
  creator: Address,
  claimSigner: Address,
  status: number | bigint,
];

function decodeHeaderJsonOrString(raw: string): InboundSignedPermitPayload | null {
  const trimmed = raw.trim();
  if (trimmed.startsWith('{')) {
    return JSON.parse(trimmed) as InboundSignedPermitPayload;
  }
  // Support `b64:<base64url>` or pure base64url JSON envelopes that do not start with `http` or `slip_`
  if (!/^https?:/i.test(trimmed) && !trimmed.startsWith('slip_') && !trimmed.includes('#')) {
    try {
      const clean = trimmed.startsWith('b64:') ? trimmed.slice(4) : trimmed;
      const decoded = new TextDecoder().decode(voiceBase64UrlToBytes(clean));
      if (decoded.trim().startsWith('{')) {
        return JSON.parse(decoded) as InboundSignedPermitPayload;
      }
    } catch {
      return null;
    }
  }
  return null;
}

function extractProofToken(request: Request): { xSlip?: string; txHash?: Hex; orderId?: string; slipIdHint?: string } {
  const directSlip = request.headers.get(X_SLIP_HEADER) || request.headers.get('x-payment-slip');
  const auth = request.headers.get('authorization') || '';
  let xSlip = directSlip ? directSlip.trim() : undefined;
  if (!xSlip && /^CryptoSlip\s+/i.test(auth)) {
    xSlip = auth.replace(/^CryptoSlip\s+/i, '').trim();
  }
  const rawTx = (request.headers.get(X_PAYMENT_TX_HEADER) || request.headers.get('x-tx-hash') || '').trim();
  const txHash = /^0x[0-9a-fA-F]{64}$/.test(rawTx) ? (rawTx.toLowerCase() as Hex) : undefined;
  const orderId = (request.headers.get(X_ORDER_ID_HEADER) || '').trim() || undefined;
  const slipIdHint = (request.headers.get('x-slip-id') || '').trim() || undefined;
  return {
    ...(xSlip ? { xSlip } : {}),
    ...(txHash ? { txHash } : {}),
    ...(orderId ? { orderId } : {}),
    ...(slipIdHint ? { slipIdHint } : {}),
  };
}

function resolveVaultTagFromInput(
  rawVault: 'v33' | 'v32' | Address | string | undefined,
  fallback: 'v33' | 'v32',
): 'v33' | 'v32' {
  if (!rawVault) return fallback;
  if (rawVault === 'v33' || rawVault === 'v32') return rawVault;
  const tag = vaultTagForAddress(rawVault);
  if (tag === 'v33' || tag === 'v32') return tag;
  throw new Error(`Unsupported vault for tollbooth settlement: ${rawVault}`);
}

export function createDefaultRelaySettler(options: {
  relayUrls?: readonly string[];
  partnerApiKey?: string;
  fetchFn?: typeof fetch;
}): (req: TollboothSettleRequest) => Promise<TollboothSettleResult> {
  const gateways = options.relayUrls?.length
    ? [...options.relayUrls]
    : [WORKER_RELAY_GATEWAY, AKASH_RELAY_GATEWAY];
  const fetchImpl = options.fetchFn ?? globalThis.fetch;

  return async (req: TollboothSettleRequest): Promise<TollboothSettleResult> => {
    const endpointPath =
      req.mode === 'cash'
        ? '/api/relay/cash'
        : req.mode === 'split'
          ? '/api/relay/split'
          : '/api/relay/rearrange';
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Origin: CANONICAL_SHARE_ORIGIN,
    };
    if (options.partnerApiKey) {
      headers['X-CryptoSLIP-Partner-Key'] = options.partnerApiKey;
    }

    let lastError = 'Relay settlement failed';
    for (const base of gateways) {
      const cleanBase = base.replace(/\/+$/, '');
      try {
        const resp = await fetchImpl(`${cleanBase}${endpointPath}`, {
          method: 'POST',
          headers,
          body: JSON.stringify(req.relayBody),
          redirect: 'error',
        });
        const data = (await resp.json().catch(() => ({}))) as {
          txHash?: string;
          blockNumber?: number;
          blockTimestamp?: number;
          error?: string;
        };
        if (resp.ok && data.txHash && /^0x[0-9a-fA-F]{64}$/.test(data.txHash)) {
          return {
            txHash: data.txHash.toLowerCase() as Hex,
            blockNumber: data.blockNumber,
            blockTimestamp: data.blockTimestamp,
          };
        }
        lastError = data.error || `Relay HTTP ${resp.status}`;
        // Do not retry deterministic 4xx validation rejections on secondary gateway
        if (resp.status >= 400 && resp.status < 500 && resp.status !== 429) {
          break;
        }
      } catch (err) {
        lastError = err instanceof Error ? err.message : 'Relay network error';
      }
    }
    throw new Error(lastError);
  };
}

export function encodeReceiptHeaderValue(receipt: PaymentReceiptBundleV1): string {
  return voiceBytesToBase64Url(new TextEncoder().encode(JSON.stringify(receipt)));
}

export function decodeReceiptHeaderValue(headerVal: string): PaymentReceiptBundleV1 {
  const json = new TextDecoder().decode(voiceBase64UrlToBytes(headerVal.trim()));
  return JSON.parse(json) as PaymentReceiptBundleV1;
}

/**
 * Creates a Watch-Only HTTP `402` CryptoSLIP Tollbooth instance with built-in `V-03` concurrent
 * `slipId` replay protection, `V-05` mixed-creator `No take-back` combine protection, on-chain
 * `slips(slipId)` pre-verification, and cryptographic `PaymentReceiptBundleV1` generation.
 */
export function createCryptoSlipTollbooth(config: CryptoSlipTollboothConfig) {
  if (!isAddress(config.merchantAddress)) {
    throw new Error('Tollbooth merchantAddress must be a valid Base wallet or Safe address');
  }
  const merchantAddress = getAddress(config.merchantAddress);
  if (BLOCKED_PAYMENT_TARGETS.has(merchantAddress.toLowerCase())) {
    throw new Error(
      `Tollbooth merchantAddress ${merchantAddress} is a blocked protocol/token contract or compromised key`,
    );
  }
  if (config.minNetAmount <= 0n) {
    throw new Error('Tollbooth minNetAmount must be strictly positive');
  }

  const asset = normalizeSdkAsset(config.asset ?? 'USDC');
  const defaultVaultTag: 'v33' | 'v32' = config.vault ?? 'v33';
  const feeMode = config.feeMode ?? 'payer_gross_up';
  const requireNoTakeBack = config.requireNoTakeBack ?? true;
  const replayStatusCode = config.replayStatusCode ?? 409;
  const appOrigin = (config.appOrigin || CANONICAL_SHARE_ORIGIN).replace(/\/+$/, '');
  const replayGuard =
    config.replayGuard ?? new SlipReplayGuard(config.maxSettledCacheEntries ?? 10_000);
  const settler =
    config.settler ??
    createDefaultRelaySettler({
      relayUrls: config.relayUrls,
      partnerApiKey: config.partnerApiKey,
      fetchFn: config.fetchFn,
    });

  function computeChallenge(minNetAmount: bigint, orderId?: string): CryptoSlipChallengeDescriptor {
    const vaultAddr = VAULTS[defaultVaultTag].address;
    const grossRequired =
      feeMode === 'merchant_absorbs' ? minNetAmount : grossUpForExactNet(minNetAmount);
    const decimals = decimalsForAsset(asset);
    const humanAmount = Number(formatUnits(grossRequired, decimals));

    const checkoutUrl = buildPopupCheckoutUrl({
      recipientAddress: merchantAddress,
      amount: humanAmount,
      asset,
      feeMode: feeMode === 'merchant_absorbs' ? 'net' : 'gross',
      orderId,
      merchantName: config.merchantLabel,
      appOrigin,
    });
    const posUrl = buildWatchOnlyPosUrl({
      merchantAddress,
      asset,
      feeMode: feeMode === 'merchant_absorbs' ? 'net' : 'gross',
      merchantName: config.merchantLabel,
      origin: appOrigin,
    });

    return {
      version: 1,
      scheme: 'cryptoslip-v32',
      chainId: BASE_CHAIN_ID,
      vault: defaultVaultTag,
      vaultAddress: vaultAddr,
      recipient: merchantAddress,
      asset,
      minNetAmount: minNetAmount.toString(10),
      grossAmountRequired: grossRequired.toString(10),
      requireNoTakeBack,
      checkoutUrl,
      posUrl,
      builderCode: DEFAULT_CRYPTOSLIP_BUILDER_CODE,
      ...(config.merchantLabel ? { merchantLabel: config.merchantLabel } : {}),
      ...(orderId ? { orderId } : {}),
    };
  }

  function buildChallengeHeaders(
    challenge: CryptoSlipChallengeDescriptor,
    errorCode?: string,
  ): Record<string, string> {
    const realm = (config.merchantLabel || 'CryptoSLIP').replace(/"/g, '');
    const wwwAuth = [
      `CryptoSlip realm="${realm}"`,
      `chainId="${challenge.chainId}"`,
      `vault="${challenge.vaultAddress}"`,
      `recipient="${challenge.recipient}"`,
      `asset="${challenge.asset}"`,
      `minNetAmount="${challenge.minNetAmount}"`,
      `grossAmountRequired="${challenge.grossAmountRequired}"`,
      `checkoutUrl="${challenge.checkoutUrl}"`,
    ].join(', ');

    return {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'WWW-Authenticate': wwwAuth,
      [X_CRYPTOSLIP_ACCEPT_HEADER]: JSON.stringify(challenge),
      ...(errorCode ? { [X_CRYPTOSLIP_ERROR_HEADER]: errorCode } : {}),
    };
  }

  function buildErrorOrChallengeResponse(
    status: number,
    challenge: CryptoSlipChallengeDescriptor,
    message: string,
    errorCode: string,
  ): Response {
    return new Response(
      JSON.stringify({
        ok: false,
        error: message,
        code: errorCode,
        accept: challenge,
      }),
      {
        status,
        headers: buildChallengeHeaders(challenge, errorCode),
      },
    );
  }

  async function readSlipAndNonce(vaultAddr: Address, slipId: bigint) {
    const [slipRaw, nonceRaw] = await Promise.all([
      config.publicClient.readContract({
        address: vaultAddr,
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        functionName: 'slips',
        args: [slipId],
      }),
      config.publicClient.readContract({
        address: vaultAddr,
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        functionName: 'nonces',
        args: [slipId],
      }),
    ]);
    const tuple = slipRaw as OnChainSlipTuple;
    return {
      asset: tuple[0],
      amount: BigInt(tuple[1]),
      createdAt: BigInt(tuple[2]),
      cancelLockedUntil: BigInt(tuple[3]),
      creator: tuple[4],
      claimSigner: tuple[5],
      status: Number(tuple[6]),
      nonce: BigInt(nonceRaw as bigint | number),
    };
  }

  async function verifyRequest(request: Request): Promise<TollboothVerificationResult> {
    const minNetAmount = config.resolveMinNetAmount
      ? await config.resolveMinNetAmount(request)
      : config.minNetAmount;
    const extracted = extractProofToken(request);
    const orderId = extracted.orderId ?? config.resolveOrderId?.(request);
    const challenge = computeChallenge(minNetAmount, orderId);
    const grossRequired = BigInt(challenge.grossAmountRequired);
    const expectedTokenAddress = assetAddress(asset).toLowerCase();

    if (!extracted.xSlip && !extracted.txHash) {
      return {
        ok: false,
        response: buildErrorOrChallengeResponse(
          402,
          challenge,
          'Payment required. Submit X-Slip or complete checkout.',
          'payment_required',
        ),
      };
    }

    // ---- Path C: Pre-settled on-chain txHash proof (`X-Payment-Tx`) ----
    if (!extracted.xSlip && extracted.txHash) {
      const initialKeys = [SlipReplayGuard.txKey(extracted.txHash)];
      if (extracted.slipIdHint && /^\d+$/.test(extracted.slipIdHint) && BigInt(extracted.slipIdHint) > 0n) {
        initialKeys.push(
          SlipReplayGuard.slipKey(VAULTS[defaultVaultTag].address, extracted.slipIdHint),
        );
      }
      const lock = replayGuard.tryAcquire(initialKeys);
      if (!lock.acquired) {
        return {
          ok: false,
          response: buildErrorOrChallengeResponse(
            replayStatusCode,
            challenge,
            lock.reason === 'in_flight'
              ? 'Payment proof is already being verified in a concurrent request.'
              : 'Transaction hash has already been redeemed.',
            lock.reason === 'in_flight' ? 'tx_in_flight' : 'tx_already_settled',
          ),
        };
      }

      const acquiredKeys = [...lock.keys];
      let committed = false;
      try {
        const txReceipt = await config.publicClient.getTransactionReceipt({
          hash: extracted.txHash,
        });
        const txSucceeded =
          txReceipt.status === 'success' || txReceipt.status === 1 || txReceipt.status === '0x1';
        if (!txSucceeded) {
          return {
            ok: false,
            response: buildErrorOrChallengeResponse(
              402,
              challenge,
              'Submitted transaction reverted on-chain.',
              'invalid_tx_proof',
            ),
          };
        }

        const blockNum = Number(txReceipt.blockNumber);
        const [blockObj, txInfo] = await Promise.all([
          config.publicClient.getBlock
            ? config.publicClient.getBlock({ blockNumber: BigInt(blockNum) }).catch(() => null)
            : Promise.resolve(null),
          asset === 'ETH' && typeof config.publicClient.getTransaction === 'function'
            ? config.publicClient.getTransaction({ hash: extracted.txHash }).catch(() => null)
            : Promise.resolve(null),
        ]);
        const blockTs = blockObj ? Number(blockObj.timestamp) : Math.floor(Date.now() / 1000);

        const recipientLower = merchantAddress.toLowerCase();
        const v33VaultLower = VAULTS.v33.address.toLowerCase();
        const v32VaultLower = VAULTS.v32.address.toLowerCase();
        const v33RouterLower = tradeRouterForVault('v33').toLowerCase();
        const v32RouterLower = tradeRouterForVault('v32').toLowerCase();

        // 1. Collect protocol/referral fees & ERC-20 Transfer totals from txReceipt.logs
        let accruedFeeOnAsset = 0n;
        let erc20TransferredToMerchant = 0n;
        for (const log of txReceipt.logs) {
          const addrLower = log.address.toLowerCase();
          if (asset !== 'ETH' && addrLower === expectedTokenAddress) {
            try {
              const dec = decodeEventLog({
                abi: ERC20_PERMIT_EIP3009_ABI,
                data: log.data,
                topics: log.topics as [Hex, ...Hex[]],
              });
              if (dec.eventName === 'Transfer' && dec.args.to.toLowerCase() === recipientLower) {
                erc20TransferredToMerchant += BigInt(dec.args.value);
              }
            } catch {
              // Ignore unrelated token events
            }
          }
          if (addrLower === v33VaultLower || addrLower === v32VaultLower) {
            try {
              const dec = decodeEventLog({
                abi: CRYPTO_SLIP_VAULT_V32_ABI,
                data: log.data,
                topics: log.topics as [Hex, ...Hex[]],
              });
              if (
                dec.eventName === 'FeeAccrued' &&
                dec.args.asset.toLowerCase() === expectedTokenAddress
              ) {
                accruedFeeOnAsset += BigInt(dec.args.protocolFee) + BigInt(dec.args.referralFee);
              }
            } catch {
              // Handled in settlement pass below
            }
          }
        }

        // 2. Extract actual settlement type, vault, slipId(s), gross, fee & net from logs
        let detectedVault: 'v33' | 'v32' = defaultVaultTag;
        let detectedType: ReceiptSettlementType | null = null;
        let detectedSlipId = '0';
        let consumedSlipIds: string[] = [];
        let detectedGross = 0n;
        let detectedFee = 0n;
        let detectedNet = 0n;

        for (const log of txReceipt.logs) {
          const addrLower = log.address.toLowerCase();
          if (addrLower === v33RouterLower || addrLower === v32RouterLower) {
            try {
              const dec = decodeEventLog({
                abi: CRYPTO_SLIP_TRADE_ROUTER_V32_ABI,
                data: log.data,
                topics: log.topics as [Hex, ...Hex[]],
              });
              if (
                dec.eventName === 'SlipSwappedAndPaid' &&
                dec.args.merchant.toLowerCase() === recipientLower &&
                dec.args.outAsset.toLowerCase() === expectedTokenAddress
              ) {
                detectedVault = addrLower === v32RouterLower ? 'v32' : 'v33';
                detectedType = 'swap_pay';
                detectedSlipId = dec.args.inputSlipId.toString(10);
                consumedSlipIds = [detectedSlipId];
                detectedNet = BigInt(dec.args.amountOut);
                detectedFee = 0n;
                detectedGross = detectedNet;
                break;
              }
            } catch {
              // Ignore non-matching router logs
            }
          }

          if (addrLower === v33VaultLower || addrLower === v32VaultLower) {
            try {
              const dec = decodeEventLog({
                abi: CRYPTO_SLIP_VAULT_V32_ABI,
                data: log.data,
                topics: log.topics as [Hex, ...Hex[]],
              });
              const logVault: 'v33' | 'v32' = addrLower === v32VaultLower ? 'v32' : 'v33';

              if (
                dec.eventName === 'SlipCashed' &&
                dec.args.recipient.toLowerCase() === recipientLower
              ) {
                detectedVault = logVault;
                detectedType = 'claim';
                detectedSlipId = dec.args.slipId.toString(10);
                consumedSlipIds = [detectedSlipId];
                detectedNet = BigInt(dec.args.netPayout);
                detectedFee = accruedFeeOnAsset;
                detectedGross = detectedNet + detectedFee;
                break;
              }
              if (
                dec.eventName === 'SlipSplitAndPaid' &&
                dec.args.merchant.toLowerCase() === recipientLower
              ) {
                detectedVault = logVault;
                detectedType = 'split_pay';
                detectedSlipId = dec.args.originalSlipId.toString(10);
                consumedSlipIds = [detectedSlipId];
                detectedGross = BigInt(dec.args.paymentAmount);
                detectedFee = computeProtocolFeeCeiling(detectedGross);
                detectedNet = deductProtocolFeeCeiling(detectedGross);
                break;
              }
              if (
                dec.eventName === 'SlipsRearrangedAndPaid' &&
                dec.args.merchant.toLowerCase() === recipientLower &&
                dec.args.consumedSlipIds.length > 0
              ) {
                detectedVault = logVault;
                detectedType = 'combine_pay';
                consumedSlipIds = dec.args.consumedSlipIds.map((id) => id.toString(10));
                detectedSlipId = consumedSlipIds[0]!;
                detectedGross = BigInt(dec.args.paymentAmount);
                detectedFee = computeProtocolFeeCeiling(detectedGross);
                detectedNet = deductProtocolFeeCeiling(detectedGross);
                break;
              }
            } catch {
              // Ignore unrelated vault logs
            }
          }
        }

        // 3. Fallback to direct wallet transfer if no Vault/Router settlement event matched
        if (!detectedType) {
          if (asset !== 'ETH' && erc20TransferredToMerchant > 0n) {
            detectedType = 'direct_transfer';
            detectedSlipId = '0';
            detectedGross = erc20TransferredToMerchant;
            detectedFee = 0n;
            detectedNet = erc20TransferredToMerchant;
          } else if (
            asset === 'ETH' &&
            txInfo?.to &&
            txInfo.to.toLowerCase() === recipientLower &&
            BigInt(txInfo.value ?? 0n) > 0n
          ) {
            detectedType = 'direct_transfer';
            detectedSlipId = '0';
            detectedGross = BigInt(txInfo.value!);
            detectedFee = 0n;
            detectedNet = detectedGross;
          }
        }

        if (!detectedType || detectedNet <= 0n) {
          return {
            ok: false,
            response: buildErrorOrChallengeResponse(
              402,
              challenge,
              'No matching payment settlement to merchant found in transaction logs.',
              'invalid_tx_proof',
            ),
          };
        }

        if (
          extracted.slipIdHint &&
          /^\d+$/.test(extracted.slipIdHint) &&
          !consumedSlipIds.includes(extracted.slipIdHint)
        ) {
          return {
            ok: false,
            response: buildErrorOrChallengeResponse(
              402,
              challenge,
              `X-Slip-Id hint (${extracted.slipIdHint}) does not match settled transaction slip.`,
              'invalid_tx_proof',
            ),
          };
        }

        // 4. Lock every discovered consumed slipId in SlipReplayGuard so settled slips can never replay!
        const extraSlipKeys = consumedSlipIds
          .map((id) => SlipReplayGuard.slipKey(VAULTS[detectedVault].address, id))
          .filter((k) => !acquiredKeys.includes(k));
        if (extraSlipKeys.length > 0) {
          const extraLock = replayGuard.tryAcquire(extraSlipKeys);
          if (!extraLock.acquired) {
            return {
              ok: false,
              response: buildErrorOrChallengeResponse(
                replayStatusCode,
                challenge,
                extraLock.reason === 'in_flight'
                  ? 'Settled slip is currently locked in a concurrent request.'
                  : 'Settled slip has already been redeemed.',
                extraLock.reason === 'in_flight' ? 'slip_in_flight' : 'slip_already_settled',
              ),
            };
          }
          acquiredKeys.push(...extraLock.keys);
        }

        if (detectedNet < minNetAmount) {
          return {
            ok: false,
            response: buildErrorOrChallengeResponse(
              402,
              challenge,
              `Settled net amount (${detectedNet}) is below required minimum (${minNetAmount}).`,
              'insufficient_net_amount',
            ),
          };
        }

        const candidateReceipt = await createSignedPaymentReceipt({
          vault: detectedVault,
          slipId: detectedSlipId,
          txHash: extracted.txHash,
          blockNumber: blockNum,
          blockTimestamp: blockTs,
          settlementType: detectedType,
          asset,
          grossAmount: detectedGross,
          feeAmount: detectedFee,
          netAmount: detectedNet,
          recipient: merchantAddress,
          merchantLabel: config.merchantLabel,
          orderId,
          signer: config.receiptSigner,
        });

        const verified = await verifyPaymentReceiptOnChain(config.publicClient, candidateReceipt, {
          expectedRecipient: merchantAddress,
          expectedAsset: asset,
          minNetAmount,
        });
        if (!verified.valid) {
          return {
            ok: false,
            response: buildErrorOrChallengeResponse(
              402,
              challenge,
              verified.reason || 'On-chain transaction receipt did not satisfy payment challenge.',
              'invalid_tx_proof',
            ),
          };
        }

        const finalNet = verified.verifiedNetAmount ?? detectedNet;
        replayGuard.commit(acquiredKeys, candidateReceipt);
        committed = true;

        return {
          ok: true,
          context: {
            receipt: candidateReceipt,
            slipId: candidateReceipt.slipId,
            txHash: extracted.txHash,
            asset,
            vault: detectedVault,
            grossAmount: verified.verifiedGrossAmount ?? detectedGross,
            feeAmount: verified.verifiedFeeAmount ?? detectedFee,
            netAmount: finalNet,
            minNetAmountRequired: minNetAmount,
            overpaidNetAmount: finalNet > minNetAmount ? finalNet - minNetAmount : 0n,
            ...(orderId ? { orderId } : {}),
          },
        };
      } catch (err) {
        return {
          ok: false,
          response: buildErrorOrChallengeResponse(
            402,
            challenge,
            err instanceof Error ? err.message : 'Unable to verify payment transaction',
            'tx_verification_failed',
          ),
        };
      } finally {
        if (!committed) replayGuard.release(acquiredKeys);
      }
    }

    // ---- Path A & B: `X-Slip` (# slip URL or signed CashPermit / SplitPermit / Combine JSON) ----
    const rawSlipHeader = extracted.xSlip!;
    let parsedPermitJson: InboundSignedPermitPayload | null = null;
    try {
      parsedPermitJson = decodeHeaderJsonOrString(rawSlipHeader);
    } catch {
      return {
        ok: false,
        response: buildErrorOrChallengeResponse(
          402,
          challenge,
          'Malformed X-Slip JSON payload.',
          'malformed_slip_header',
        ),
      };
    }

    if (!parsedPermitJson) {
      // Path A: `#startapp=slip_...` URL or payload
      let parsedLink;
      try {
        assertFragmentSafeUrl(rawSlipHeader);
        parsedLink = parseSlipUrl(rawSlipHeader);
      } catch (err) {
        return {
          ok: false,
          response: buildErrorOrChallengeResponse(
            402,
            challenge,
            err instanceof Error ? err.message : 'Unsafe or invalid slip link.',
            'invalid_slip_url',
          ),
        };
      }
      if (!parsedLink || !parsedLink.claimKey) {
        return {
          ok: false,
          response: buildErrorOrChallengeResponse(
            402,
            challenge,
            'X-Slip link must be an open # fragment slip carrying its claim credential.',
            'missing_slip_key',
          ),
        };
      }
      if (parsedLink.vault !== 'v33' && parsedLink.vault !== 'v32') {
        return {
          ok: false,
          response: buildErrorOrChallengeResponse(
            402,
            challenge,
            'Only V3.2 (v33 / v32) slips are accepted by this tollbooth.',
            'unsupported_vault',
          ),
        };
      }

      const slipVaultTag = parsedLink.vault;
      const slipVaultAddr = VAULTS[slipVaultTag].address;
      const lockKeys = [SlipReplayGuard.slipKey(slipVaultAddr, parsedLink.id)];

      // Synchronous atomic replay/race lock BEFORE any `await`!
      const lock = replayGuard.tryAcquire(lockKeys);
      if (!lock.acquired) {
        return {
          ok: false,
          response: buildErrorOrChallengeResponse(
            replayStatusCode,
            challenge,
            lock.reason === 'in_flight'
              ? `Slip #${parsedLink.id} is already settling in a concurrent request.`
              : `Slip #${parsedLink.id} has already been settled.`,
            lock.reason === 'in_flight' ? 'slip_in_flight' : 'slip_already_settled',
          ),
        };
      }

      let committed = false;
      try {
        const slipIdBig = BigInt(parsedLink.id);
        const [onChain, latestBlock] = await Promise.all([
          readSlipAndNonce(slipVaultAddr, slipIdBig),
          config.publicClient.getBlock
            ? config.publicClient.getBlock().catch(() => null)
            : Promise.resolve(null),
        ]);

        if (onChain.status !== SlipStatus.ACTIVE) {
          return {
            ok: false,
            response: buildErrorOrChallengeResponse(
              402,
              challenge,
              `Slip #${parsedLink.id} is not active on Base (status=${onChain.status}).`,
              'slip_not_active',
            ),
          };
        }
        if (onChain.asset.toLowerCase() !== expectedTokenAddress) {
          return {
            ok: false,
            response: buildErrorOrChallengeResponse(
              402,
              challenge,
              `Slip asset mismatch: expected ${asset}.`,
              'asset_mismatch',
            ),
          };
        }
        if (onChain.amount < grossRequired) {
          return {
            ok: false,
            response: buildErrorOrChallengeResponse(
              402,
              challenge,
              `Slip amount (${onChain.amount}) is below required ${grossRequired} ${asset} units.`,
              'insufficient_slip_amount',
            ),
          };
        }
        if (requireNoTakeBack) {
          if (onChain.cancelLockedUntil !== NO_TAKE_BACK_LOCK || onChain.nonce !== 0n) {
            return {
              ok: false,
              response: buildErrorOrChallengeResponse(
                402,
                challenge,
                'Instant settlement requires a No take-back slip (cancelLockedUntil = 9_999_999_999, nonce = 0).',
                'no_take_back_required',
              ),
            };
          }
        }
        if (
          parsedLink.claimAddress &&
          onChain.claimSigner.toLowerCase() !== parsedLink.claimAddress.toLowerCase()
        ) {
          return {
            ok: false,
            response: buildErrorOrChallengeResponse(
              402,
              challenge,
              'Slip claim credential does not match on-chain claimSigner.',
              'signer_mismatch',
            ),
          };
        }

        const headSec = latestBlock
          ? BigInt(latestBlock.timestamp)
          : BigInt(Math.floor(Date.now() / 1000));
        const deadline = computePermitDeadline(headSec, 900n);
        const signedCash = await signCashPermit(parsedLink.claimKey, {
          slipId: slipIdBig,
          recipient: merchantAddress,
          nonce: onChain.nonce,
          deadline,
          relayer: ZERO_ADDRESS,
          vault: slipVaultTag,
        });

        const feeAmount = computeProtocolFeeCeiling(onChain.amount);
        const expectedNet = deductProtocolFeeCeiling(onChain.amount);
        if (expectedNet < minNetAmount) {
          return {
            ok: false,
            response: buildErrorOrChallengeResponse(
              402,
              challenge,
              'Slip net payout after protocol fee is below required minimum.',
              'insufficient_net_amount',
            ),
          };
        }

        const settled = await settler({
          mode: 'cash',
          vault: slipVaultTag,
          vaultAddress: slipVaultAddr,
          merchantAddress,
          asset,
          grossAmount: onChain.amount,
          expectedNetAmount: expectedNet,
          relayBody: {
            vault: slipVaultAddr,
            slipId: parsedLink.id,
            recipient: merchantAddress,
            relayer: ZERO_ADDRESS,
            deadline: deadline.toString(10),
            signature: signedCash.signature,
          },
        });

        const finalGross = settled.grossAmount ?? onChain.amount;
        const finalFee = settled.feeAmount ?? feeAmount;
        const finalNet = settled.netAmount ?? expectedNet;
        const receipt = await createSignedPaymentReceipt({
          vault: slipVaultTag,
          slipId: parsedLink.id,
          txHash: settled.txHash,
          blockNumber: settled.blockNumber ?? Number(latestBlock?.number ?? 1),
          blockTimestamp: settled.blockTimestamp ?? Number(headSec),
          settlementType: 'claim',
          asset,
          grossAmount: finalGross,
          feeAmount: finalFee,
          netAmount: finalNet,
          recipient: merchantAddress,
          merchantLabel: config.merchantLabel,
          orderId,
          signer: config.receiptSigner,
        });

        if (config.verifySettledTxOnChain) {
          const onChainVerify = await verifyPaymentReceiptOnChain(config.publicClient, receipt, {
            expectedRecipient: merchantAddress,
            expectedAsset: asset,
            minNetAmount,
          });
          if (!onChainVerify.valid) {
            throw new Error(onChainVerify.reason || 'On-chain settlement verification failed');
          }
        }

        const commitKeys = [...lock.keys, SlipReplayGuard.txKey(settled.txHash)];
        replayGuard.commit(commitKeys, receipt);
        committed = true;

        return {
          ok: true,
          context: {
            receipt,
            slipId: parsedLink.id,
            txHash: settled.txHash,
            asset,
            vault: slipVaultTag,
            grossAmount: finalGross,
            feeAmount: finalFee,
            netAmount: finalNet,
            minNetAmountRequired: minNetAmount,
            overpaidNetAmount: finalNet > minNetAmount ? finalNet - minNetAmount : 0n,
            ...(orderId ? { orderId } : {}),
          },
        };
      } catch (err) {
        return {
          ok: false,
          response: buildErrorOrChallengeResponse(
            402,
            challenge,
            err instanceof Error ? err.message : 'Slip settlement failed',
            'settlement_failed',
          ),
        };
      } finally {
        if (!committed) replayGuard.release(lock.keys);
      }
    }

    // ---- Path B: Pre-signed CashPermit / SplitPermit / Combine JSON ----
    let slipVaultTag: 'v33' | 'v32';
    try {
      slipVaultTag = resolveVaultTagFromInput(parsedPermitJson.vault, defaultVaultTag);
    } catch (err) {
      return {
        ok: false,
        response: buildErrorOrChallengeResponse(
          402,
          challenge,
          err instanceof Error ? err.message : 'Unsupported vault',
          'unsupported_vault',
        ),
      };
    }
    const slipVaultAddr = VAULTS[slipVaultTag].address;
    const permitKind = parsedPermitJson.kind ?? 'cash';

    const slipIdsStr: string[] =
      permitKind === 'combine' && 'slipIds' in parsedPermitJson
        ? parsedPermitJson.slipIds.map((id) => String(id))
        : 'slipId' in parsedPermitJson
          ? [String(parsedPermitJson.slipId)]
          : [];

    if (
      slipIdsStr.length === 0 ||
      slipIdsStr.length > MAX_COMBINE_SLIPS ||
      !slipIdsStr.every((id) => /^\d+$/.test(id) && BigInt(id) > 0n)
    ) {
      return {
        ok: false,
        response: buildErrorOrChallengeResponse(
          402,
          challenge,
          'Invalid slipId list in signed permit header.',
          'invalid_slip_id',
        ),
      };
    }

    const lockKeys = slipIdsStr.map((id) => SlipReplayGuard.slipKey(slipVaultAddr, id));
    const lock = replayGuard.tryAcquire(lockKeys);
    if (!lock.acquired) {
      return {
        ok: false,
        response: buildErrorOrChallengeResponse(
          replayStatusCode,
          challenge,
          lock.reason === 'in_flight'
            ? 'Slip is already settling in a concurrent request.'
            : 'Slip has already been settled.',
          lock.reason === 'in_flight' ? 'slip_in_flight' : 'slip_already_settled',
        ),
      };
    }

    let committed = false;
    try {
      const onChainSlips = await Promise.all(
        slipIdsStr.map((id) => readSlipAndNonce(slipVaultAddr, BigInt(id))),
      );

      let totalSlipBacking = 0n;
      let lockedCreatorLower: string | null = null;
      for (let idx = 0; idx < onChainSlips.length; idx++) {
        const s = onChainSlips[idx]!;
        if (s.status !== SlipStatus.ACTIVE) {
          return {
            ok: false,
            response: buildErrorOrChallengeResponse(
              402,
              challenge,
              `Slip #${slipIdsStr[idx]} is not active on Base.`,
              'slip_not_active',
            ),
          };
        }
        if (s.asset.toLowerCase() !== expectedTokenAddress) {
          return {
            ok: false,
            response: buildErrorOrChallengeResponse(
              402,
              challenge,
              `Slip #${slipIdsStr[idx]} asset mismatch: expected ${asset}.`,
              'asset_mismatch',
            ),
          };
        }
        if (requireNoTakeBack && permitKind === 'cash') {
          if (s.cancelLockedUntil !== NO_TAKE_BACK_LOCK || s.nonce !== 0n) {
            return {
              ok: false,
              response: buildErrorOrChallengeResponse(
                402,
                challenge,
                'No take-back slip (cancelLockedUntil = 9_999_999_999, nonce = 0) is required.',
                'no_take_back_required',
              ),
            };
          }
        }
        // V-05 Defense: prevent mixed-creator No take-back Combine reverts (`CancelLocked()`)
        if (permitKind === 'combine' && s.cancelLockedUntil === NO_TAKE_BACK_LOCK) {
          const cLower = s.creator.toLowerCase();
          if (lockedCreatorLower === null) {
            lockedCreatorLower = cLower;
          } else if (lockedCreatorLower !== cLower) {
            return {
              ok: false,
              response: buildErrorOrChallengeResponse(
                402,
                challenge,
                'V-05 guard: No take-back slips from different creators cannot be combined in one transaction.',
                'mixed_locked_creators',
              ),
            };
          }
        }
        totalSlipBacking += s.amount;
      }

      let paymentGross: bigint;
      let settlementType: ReceiptSettlementType;
      let relayBody: Record<string, unknown>;

      if (permitKind === 'cash' && (!parsedPermitJson.kind || parsedPermitJson.kind === 'cash')) {
        const targetRecipient = parsedPermitJson.recipient
          ? getAddress(parsedPermitJson.recipient)
          : merchantAddress;
        if (targetRecipient.toLowerCase() !== merchantAddress.toLowerCase()) {
          return {
            ok: false,
            response: buildErrorOrChallengeResponse(
              402,
              challenge,
              'CashPermit recipient does not match merchantAddress.',
              'recipient_mismatch',
            ),
          };
        }
        if (!isHex(parsedPermitJson.signature)) {
          throw new Error('Invalid CashPermit signature');
        }
        paymentGross = totalSlipBacking;
        settlementType = 'claim';
        relayBody = {
          vault: slipVaultAddr,
          slipId: slipIdsStr[0]!,
          recipient: merchantAddress,
          relayer: parsedPermitJson.relayer ?? ZERO_ADDRESS,
          deadline: String(parsedPermitJson.deadline),
          signature: parsedPermitJson.signature,
          ...(parsedPermitJson.referralConsentSignature
            ? { referralConsentSignature: parsedPermitJson.referralConsentSignature }
            : {}),
        };
      } else if (permitKind === 'split' && parsedPermitJson.kind === 'split') {
        if (getAddress(parsedPermitJson.merchant).toLowerCase() !== merchantAddress.toLowerCase()) {
          return {
            ok: false,
            response: buildErrorOrChallengeResponse(
              402,
              challenge,
              'SplitPermit merchant does not match merchantAddress.',
              'recipient_mismatch',
            ),
          };
        }
        paymentGross = BigInt(parsedPermitJson.paymentAmount);
        const remainder = totalSlipBacking - paymentGross;
        const minChange = minSlipAmount(asset, slipVaultTag);
        if (remainder < 0n || (remainder > 0n && remainder < minChange)) {
          return {
            ok: false,
            response: buildErrorOrChallengeResponse(
              402,
              challenge,
              `V-03 dust cliff: split remainder (${remainder}) is below ${asset} minimum (${minChange}).`,
              'dust_cliff',
            ),
          };
        }
        const changeReceiverAddr = getAddress(parsedPermitJson.changeReceiver);
        const newChangeSignerAddr = getAddress(parsedPermitJson.newChangeSigner);
        const changeIsZero = changeReceiverAddr.toLowerCase() === ZERO_ADDRESS;
        const signerIsZero = newChangeSignerAddr.toLowerCase() === ZERO_ADDRESS;
        if (remainder === 0n ? !changeIsZero || !signerIsZero : changeIsZero || signerIsZero) {
          return {
            ok: false,
            response: buildErrorOrChallengeResponse(
              402,
              challenge,
              remainder === 0n
                ? 'Exact full-amount split requires changeReceiver and newChangeSigner to be zero address.'
                : 'Partial split with change requires non-zero changeReceiver and newChangeSigner.',
              'invalid_change_signer',
            ),
          };
        }
        settlementType = 'split_pay';
        relayBody = {
          vault: slipVaultAddr,
          slipId: slipIdsStr[0]!,
          paymentAmount: paymentGross.toString(10),
          merchant: merchantAddress,
          changeReceiver: changeReceiverAddr,
          newChangeSigner: newChangeSignerAddr,
          relayer: parsedPermitJson.relayer ?? ZERO_ADDRESS,
          deadline: String(parsedPermitJson.deadline),
          signature: parsedPermitJson.signature,
        };
      } else if (permitKind === 'combine' && parsedPermitJson.kind === 'combine') {
        if (getAddress(parsedPermitJson.merchant).toLowerCase() !== merchantAddress.toLowerCase()) {
          return {
            ok: false,
            response: buildErrorOrChallengeResponse(
              402,
              challenge,
              'RearrangePermit merchant does not match merchantAddress.',
              'recipient_mismatch',
            ),
          };
        }
        paymentGross = BigInt(parsedPermitJson.paymentAmount);
        const remainder = totalSlipBacking - paymentGross;
        const minChange = minSlipAmount(asset, slipVaultTag);
        if (remainder < 0n || (remainder > 0n && remainder < minChange)) {
          return {
            ok: false,
            response: buildErrorOrChallengeResponse(
              402,
              challenge,
              `V-03 dust cliff: combine remainder (${remainder}) is below ${asset} minimum (${minChange}).`,
              'dust_cliff',
            ),
          };
        }
        const changeReceiverAddr = getAddress(parsedPermitJson.changeReceiver);
        const newChangeSignerAddr = getAddress(parsedPermitJson.newChangeSigner);
        const changeIsZero = changeReceiverAddr.toLowerCase() === ZERO_ADDRESS;
        const signerIsZero = newChangeSignerAddr.toLowerCase() === ZERO_ADDRESS;
        if (remainder === 0n ? !changeIsZero || !signerIsZero : changeIsZero || signerIsZero) {
          return {
            ok: false,
            response: buildErrorOrChallengeResponse(
              402,
              challenge,
              remainder === 0n
                ? 'Exact full-amount combine requires changeReceiver and newChangeSigner to be zero address.'
                : 'Partial combine with change requires non-zero changeReceiver and newChangeSigner.',
              'invalid_change_signer',
            ),
          };
        }
        settlementType = 'combine_pay';
        relayBody = {
          vault: slipVaultAddr,
          slipIds: slipIdsStr,
          signatures: parsedPermitJson.signatures,
          paymentAmount: paymentGross.toString(10),
          merchant: merchantAddress,
          changeReceiver: changeReceiverAddr,
          newChangeSigner: newChangeSignerAddr,
          relayer: parsedPermitJson.relayer ?? ZERO_ADDRESS,
          deadline: String(parsedPermitJson.deadline),
        };
      } else {
        throw new Error('Unsupported permit payload kind');
      }

      if (paymentGross < grossRequired || paymentGross > totalSlipBacking) {
        return {
          ok: false,
          response: buildErrorOrChallengeResponse(
            402,
            challenge,
            `Permit paymentAmount (${paymentGross}) does not satisfy required gross (${grossRequired}).`,
            'insufficient_slip_amount',
          ),
        };
      }

      const expectedFee = computeProtocolFeeCeiling(paymentGross);
      const expectedNet = deductProtocolFeeCeiling(paymentGross);

      const settled = await settler({
        mode: permitKind,
        vault: slipVaultTag,
        vaultAddress: slipVaultAddr,
        merchantAddress,
        asset,
        grossAmount: paymentGross,
        expectedNetAmount: expectedNet,
        relayBody,
      });

      const finalGross = settled.grossAmount ?? paymentGross;
      const finalFee = settled.feeAmount ?? expectedFee;
      const finalNet = settled.netAmount ?? expectedNet;

      const receipt = await createSignedPaymentReceipt({
        vault: slipVaultTag,
        slipId: slipIdsStr[0]!,
        txHash: settled.txHash,
        blockNumber: settled.blockNumber ?? 1,
        blockTimestamp: settled.blockTimestamp ?? Math.floor(Date.now() / 1000),
        settlementType,
        asset,
        grossAmount: finalGross,
        feeAmount: finalFee,
        netAmount: finalNet,
        recipient: merchantAddress,
        merchantLabel: config.merchantLabel,
        orderId,
        signer: config.receiptSigner,
      });

      const commitKeys = [...lock.keys, SlipReplayGuard.txKey(settled.txHash)];
      replayGuard.commit(commitKeys, receipt);
      committed = true;

      return {
        ok: true,
        context: {
          receipt,
          slipId: slipIdsStr[0]!,
          txHash: settled.txHash,
          asset,
          vault: slipVaultTag,
          grossAmount: finalGross,
          feeAmount: finalFee,
          netAmount: finalNet,
          minNetAmountRequired: minNetAmount,
          overpaidNetAmount: finalNet > minNetAmount ? finalNet - minNetAmount : 0n,
          ...(orderId ? { orderId } : {}),
        },
      };
    } catch (err) {
      return {
        ok: false,
        response: buildErrorOrChallengeResponse(
          402,
          challenge,
          err instanceof Error ? err.message : 'Permit settlement failed',
          'settlement_failed',
        ),
      };
    } finally {
      if (!committed) replayGuard.release(lock.keys);
    }
  }

  function wrapFetch(
    handler: (
      request: Request,
      context: CryptoSlipSettlementContext,
    ) => Response | Promise<Response>,
  ): (request: Request) => Promise<Response> {
    return async (request: Request): Promise<Response> => {
      const result = await verifyRequest(request);
      if (!result.ok) return result.response;

      const downstream = await handler(request, result.context);
      const headers = new Headers(downstream.headers);
      if (!headers.has(X_PAYMENT_RECEIPT_HEADER)) {
        headers.set(X_PAYMENT_RECEIPT_HEADER, encodeReceiptHeaderValue(result.context.receipt));
      }
      return new Response(downstream.body, {
        status: downstream.status,
        statusText: downstream.statusText,
        headers,
      });
    };
  }

  return {
    config,
    replayGuard,
    computeChallenge,
    verifyRequest,
    wrapFetch,
  };
}

// ============================================================================
// Universal Hono / Express / Fetch Adapter (`withCryptoSlip`)
// ============================================================================

export interface HonoContextLike {
  req: { raw: Request };
  res?: Response;
  set?: (key: string, value: unknown) => void;
}

export interface NodeIncomingMessageLike {
  method?: string;
  url?: string;
  originalUrl?: string;
  headers?: Record<string, string | string[] | undefined>;
  cryptoSlip?: CryptoSlipSettlementContext;
  cryptoSlipReceipt?: PaymentReceiptBundleV1;
}

export interface NodeServerResponseLike {
  statusCode?: number;
  setHeader(name: string, value: string): unknown;
  status?: (code: number) => NodeServerResponseLike;
  json?: (body: unknown) => unknown;
  end?: (chunk?: string) => unknown;
}

function nodeReqToWebRequest(req: NodeIncomingMessageLike): Request {
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers ?? {})) {
    if (Array.isArray(v)) {
      for (const item of v) headers.append(k, item);
    } else if (typeof v === 'string') {
      headers.set(k, v);
    }
  }
  const host = headers.get('host') || 'localhost';
  const proto = headers.get('x-forwarded-proto') || 'https';
  const path = req.originalUrl || req.url || '/';
  return new Request(`${proto}://${host}${path.startsWith('/') ? path : `/${path}`}`, {
    method: req.method || 'GET',
    headers,
  });
}

export function withCryptoSlip(
  config: CryptoSlipTollboothConfig,
  fetchHandler: (
    request: Request,
    context: CryptoSlipSettlementContext,
  ) => Response | Promise<Response>,
): (request: Request) => Promise<Response>;
export function withCryptoSlip(
  config: CryptoSlipTollboothConfig,
): (
  arg1: Request | HonoContextLike | NodeIncomingMessageLike,
  arg2?: (() => Promise<void>) | NodeServerResponseLike,
  arg3?: (err?: unknown) => void,
) => Promise<Response | void>;
export function withCryptoSlip(
  config: CryptoSlipTollboothConfig,
  fetchHandler?: (
    request: Request,
    context: CryptoSlipSettlementContext,
  ) => Response | Promise<Response>,
) {
  const tollbooth = createCryptoSlipTollbooth(config);

  if (fetchHandler) {
    return tollbooth.wrapFetch(fetchHandler);
  }

  return async (
    arg1: Request | HonoContextLike | NodeIncomingMessageLike,
    arg2?: (() => Promise<void>) | NodeServerResponseLike,
    arg3?: (err?: unknown) => void,
  ): Promise<Response | void> => {
    // 1. Direct Fetch `Request` invocation
    if (arg1 instanceof Request) {
      const verified = await tollbooth.verifyRequest(arg1);
      if (!verified.ok) return verified.response;
      return new Response(JSON.stringify({ ok: true, receipt: verified.context.receipt }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          [X_PAYMENT_RECEIPT_HEADER]: encodeReceiptHeaderValue(verified.context.receipt),
        },
      });
    }

    // 2. Hono middleware `(c, next)`
    if (
      typeof arg1 === 'object' &&
      arg1 !== null &&
      'req' in arg1 &&
      (arg1 as HonoContextLike).req?.raw instanceof Request &&
      typeof arg2 === 'function'
    ) {
      const c = arg1 as HonoContextLike;
      const next = arg2 as () => Promise<void>;
      const verified = await tollbooth.verifyRequest(c.req.raw);
      if (!verified.ok) return verified.response;

      c.set?.('cryptoSlip', verified.context);
      c.set?.('cryptoSlipReceipt', verified.context.receipt);
      await next();
      if (c.res) {
        const headers = new Headers(c.res.headers);
        if (!headers.has(X_PAYMENT_RECEIPT_HEADER)) {
          headers.set(X_PAYMENT_RECEIPT_HEADER, encodeReceiptHeaderValue(verified.context.receipt));
        }
        c.res = new Response(c.res.body, {
          status: c.res.status,
          statusText: c.res.statusText,
          headers,
        });
      }
      return;
    }

    // 3. Express / Connect / Node HTTP `(req, res, next)`
    const nodeReq = arg1 as NodeIncomingMessageLike;
    const nodeRes = arg2 as NodeServerResponseLike;
    const next = arg3;
    const webReq = nodeReqToWebRequest(nodeReq);
    const verified = await tollbooth.verifyRequest(webReq);

    if (!verified.ok) {
      const resp = verified.response;
      resp.headers.forEach((value, key) => {
        nodeRes.setHeader(key, value);
      });
      const bodyText = await resp.text();
      if (typeof nodeRes.status === 'function' && typeof nodeRes.json === 'function') {
        const statusRes = nodeRes.status(resp.status);
        statusRes.json?.(JSON.parse(bodyText));
      } else {
        nodeRes.statusCode = resp.status;
        nodeRes.end?.(bodyText);
      }
      return;
    }

    nodeReq.cryptoSlip = verified.context;
    nodeReq.cryptoSlipReceipt = verified.context.receipt;
    nodeRes.setHeader(X_PAYMENT_RECEIPT_HEADER, encodeReceiptHeaderValue(verified.context.receipt));
    next?.();
  };
}

// ============================================================================
// Stateless `x402` Overcharge Refund Helper (`attachRefundSlipHeader`)
// ============================================================================

export interface MintedRefundSlipDescriptor {
  /** Either return a pre-encoded `#startapp=slip_..._cl9999999999_k...` URL or `(slipId, claimKey)` below. */
  slipUrl?: string;
  slipId?: string | bigint | number;
  claimKey?: Hex | string;
  vault?: 'v33' | 'v32';
}

export interface AttachRefundSlipHeaderOptions {
  asset?: AnyAssetSymbol;
  vault?: 'v33' | 'v32';
  origin?: string;
  /** Either specify `refundDelta` directly OR pass `paidNetAmount` + `usedNetAmount`. */
  refundDelta?: bigint;
  paidNetAmount?: bigint;
  usedNetAmount?: bigint;
  /** Pre-minted refund slip URL (`https://slip.naraprotocol.io/#startapp=slip_..._cl9999999999_k...`). */
  refundSlipUrl?: string;
  /** Pre-minted refund slip ID + `claimKey` (encoded automatically with `_cl9999999999` `No take-back`). */
  slipId?: string | bigint | number;
  claimKey?: Hex | string;
  /** Optional async minter invoked ONLY when `refundDelta >= minSlipAmount(asset, vault)`. */
  mintRefundSlip?: (params: {
    refundDelta: bigint;
    asset: SdkAssetSymbol;
    vault: 'v33' | 'v32';
    cancelLockedUntil: 9999999999n;
  }) => Promise<MintedRefundSlipDescriptor> | MintedRefundSlipDescriptor;
  note?: string;
}

/**
 * Stateless `x402` Overcharge Refund Helper: when a metered LLM or compute endpoint consumes
 * less than the pre-paid amount AND `refundDelta >= minSlipAmount(asset, vault)`, mints or
 * formats a `No take-back` (`_cl9999999999`) `#` slip link and attaches it as
 * `X-Payment-Refund-Slip` so callers recover unused funds with zero server database!
 */
export async function attachRefundSlipHeader(
  response: Response,
  options: AttachRefundSlipHeaderOptions,
): Promise<Response> {
  const asset = normalizeSdkAsset(options.asset ?? 'USDC');
  const vault = options.vault ?? (ISSUE_VAULT === 'v32' ? 'v32' : 'v33');
  const origin = (options.origin || CANONICAL_SHARE_ORIGIN).replace(/\/+$/, '');

  const refundDelta =
    options.refundDelta !== undefined
      ? options.refundDelta
      : options.paidNetAmount !== undefined && options.usedNetAmount !== undefined
        ? options.paidNetAmount > options.usedNetAmount
          ? options.paidNetAmount - options.usedNetAmount
          : 0n
        : 0n;

  const minimum = minSlipAmount(asset, vault);
  if (refundDelta <= 0n || refundDelta < minimum) {
    // Sub-minimum dust cannot form a valid V3.2 slip (`BelowMinimum()`): return response untouched.
    return response;
  }

  let finalRefundUrl = options.refundSlipUrl;
  let resolvedSlipId = options.slipId;
  let resolvedClaimKey = options.claimKey;
  let resolvedVault = vault;

  if (!finalRefundUrl && resolvedSlipId === undefined && options.mintRefundSlip) {
    const minted = await options.mintRefundSlip({
      refundDelta,
      asset,
      vault,
      cancelLockedUntil: NO_TAKE_BACK_LOCK,
    });
    finalRefundUrl = minted.slipUrl;
    resolvedSlipId = minted.slipId;
    resolvedClaimKey = minted.claimKey;
    if (minted.vault) resolvedVault = minted.vault;
  }

  if (!finalRefundUrl) {
    if (resolvedSlipId === undefined || !resolvedClaimKey) {
      throw new Error(
        'attachRefundSlipHeader requires refundSlipUrl, (slipId + claimKey), or mintRefundSlip callback',
      );
    }
    const decimals = decimalsForAsset(asset);
    const humanAmount = Number(formatUnits(refundDelta, decimals));
    const encoded = encodeSlipUrl({
      id: resolvedSlipId,
      amount: humanAmount,
      asset,
      vault: resolvedVault,
      mode: 'open',
      claimKey: resolvedClaimKey,
      cancelLockedUntil: OFFGRID_PERMANENT_LOCK_UNTIL,
      origin,
      note: options.note,
    });
    finalRefundUrl = encoded.webUrl;
  }

  assertFragmentSafeUrl(finalRefundUrl);
  const parsedRefund = parseSlipUrl(finalRefundUrl);
  if (!parsedRefund || parsedRefund.cancelLockedUntil !== OFFGRID_PERMANENT_LOCK_UNTIL) {
    throw new Error(
      'Refund slip URL attached to X-Payment-Refund-Slip MUST carry No take-back (_cl9999999999)',
    );
  }

  const headers = new Headers(response.headers);
  headers.set(X_PAYMENT_REFUND_SLIP_HEADER, finalRefundUrl);
  headers.set(X_PAYMENT_REFUND_AMOUNT_HEADER, refundDelta.toString(10));

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

// ============================================================================
// Signed Partner Webhooks (`slip.claimed`, `slip.kept`, `checkout.paid`)
// ============================================================================

export type PartnerWebhookEventType = 'slip.claimed' | 'slip.kept' | 'checkout.paid';

export interface PartnerWebhookPayload {
  version: 1;
  id: string;
  event: PartnerWebhookEventType;
  partnerSlug: string;
  chainId: 8453;
  vault: string;
  vaultAddress: Address;
  slipId: string;
  consumedSlipIds?: string[];
  txHash: Hex;
  creator: Address;
  recipient?: Address | null;
  asset: string;
  assetAddress: Address;
  amount: string;
  grossAmount?: string;
  feeAmount?: string;
  netAmount?: string;
  timestamp: number;
}

export interface VerifyPartnerWebhookSignatureParams {
  rawBody: string | Uint8Array;
  signatureHeader: string | null | undefined;
  secret: string;
  /** Maximum allowed clock/replay skew in seconds (`default: 300`). */
  toleranceSeconds?: number;
  /** Optional deterministic current Unix timestamp in seconds (defaults to `Math.floor(Date.now() / 1000)`). */
  nowSeconds?: number;
}

const DEFAULT_PARTNER_WEBHOOK_TOLERANCE_SECONDS = 300;
const MAX_SIGNATURE_TAGS = 4;
const PARTNER_WEBHOOK_SIGNING_DOMAIN = 'cryptoslip-webhook-signing-v1';

function bytesToLowerHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += (bytes[i] ?? 0).toString(16).padStart(2, '0');
  }
  return out;
}

function hex64ToBytes32(hexStr: string): Uint8Array | null {
  if (!/^[0-9a-fA-F]{64}$/.test(hexStr)) return null;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(hexStr.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Verifies `X-CryptoSLIP-Signature: t=<unixSec>,v1=<hmacSha256Hex>` over `${unixSec}.${rawBody}`
 * using constant-time 32-byte HMAC-SHA256 comparison and a timestamp replay window (`default 300s`).
 * Supports both explicit `partner.webhookSecret` and domain-separated partner signing key derivation
 * (`HMAC-SHA256('cryptoslip-webhook-signing-v1', rawPartnerKey)`). Leaked `sha256(rawPartnerKey)` digests never verify.
 */
export function verifyPartnerWebhookSignature(
  params: VerifyPartnerWebhookSignatureParams,
): boolean {
  const trimmedSecret = typeof params?.secret === 'string' ? params.secret.trim() : '';
  if (!trimmedSecret) {
    return false;
  }
  if (
    typeof params.signatureHeader !== 'string' ||
    params.signatureHeader.trim().length === 0 ||
    params.signatureHeader.length > 1024
  ) {
    return false;
  }
  const tolerance = params.toleranceSeconds ?? DEFAULT_PARTNER_WEBHOOK_TOLERANCE_SECONDS;
  if (!Number.isFinite(tolerance) || tolerance < 0) {
    return false;
  }

  let timestampSec: number | null = null;
  const v1Candidates: Uint8Array[] = [];
  for (const part of params.signatureHeader.split(',')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx <= 0) return false;
    const key = trimmed.slice(0, eqIdx).trim();
    const val = trimmed.slice(eqIdx + 1).trim();
    if (key === 't') {
      if (timestampSec !== null || !/^[1-9][0-9]{0,14}$/.test(val)) return false;
      const parsedTs = Number(val);
      if (!Number.isSafeInteger(parsedTs) || parsedTs <= 0) return false;
      timestampSec = parsedTs;
    } else if (key === 'v1') {
      if (v1Candidates.length >= MAX_SIGNATURE_TAGS) return false;
      const decoded = hex64ToBytes32(val);
      if (!decoded) return false;
      v1Candidates.push(decoded);
    }
  }

  if (timestampSec === null || v1Candidates.length === 0) {
    return false;
  }

  const nowSec = params.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (!Number.isFinite(nowSec) || nowSec <= 0 || Math.abs(nowSec - timestampSec) > tolerance) {
    return false;
  }

  const encoder = new TextEncoder();
  let bodyBytes: Uint8Array;
  if (typeof params.rawBody === 'string') {
    bodyBytes = encoder.encode(params.rawBody);
  } else if (params.rawBody instanceof Uint8Array) {
    bodyBytes = params.rawBody;
  } else {
    return false;
  }

  const prefixBytes = encoder.encode(`${timestampSec}.`);
  const signedBytes = new Uint8Array(prefixBytes.length + bodyBytes.length);
  signedBytes.set(prefixBytes, 0);
  signedBytes.set(bodyBytes, prefixBytes.length);

  const secretBytes = encoder.encode(trimmedSecret);
  const expectedDirect = hmac(sha256, secretBytes, signedBytes);
  const derivedSigningKeyHex = bytesToLowerHex(
    hmac(sha256, encoder.encode(PARTNER_WEBHOOK_SIGNING_DOMAIN), secretBytes),
  );
  const expectedDerived = hmac(sha256, encoder.encode(derivedSigningKeyHex), signedBytes);

  let matched = 0;
  for (const candidate of v1Candidates) {
    let diffDirect = 0;
    let diffDerived = 0;
    for (let i = 0; i < 32; i++) {
      diffDirect |= (candidate[i] ?? 0) ^ (expectedDirect[i] ?? 0);
      diffDerived |= (candidate[i] ?? 0) ^ (expectedDerived[i] ?? 0);
    }
    if (diffDirect === 0 || diffDerived === 0) {
      matched = 1;
    }
  }

  return matched === 1;
}
