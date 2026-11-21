import {
  decodeEventLog,
  formatUnits,
  getAddress,
  isAddress,
  isHex,
  keccak256,
  recoverMessageAddress,
  recoverTypedDataAddress,
  stringToHex,
  type Address,
  type Hex,
} from 'viem';
import { CRYPTO_SLIP_TRADE_ROUTER_V32_ABI, CRYPTO_SLIP_VAULT_V32_ABI, ERC20_PERMIT_EIP3009_ABI } from './abi.js';
import {
  BASE_CHAIN_ID,
  DEFAULT_CRYPTOSLIP_BUILDER_CODE,
  ERC8021_MARKER_HEX,
  NATIVE_ETH_ADDRESS,
  VAULTS,
  assetAddress,
  computeProtocolFeeCeiling,
  decimalsForAsset,
  normalizeSdkAsset,
  tradeRouterForVault,
  vaultTagForAddress,
  type AnyAssetSymbol,
  type SdkAssetSymbol,
} from './constants.js';

export type ReceiptSettlementType =
  | 'mint'
  | 'claim'
  | 'keep'
  | 'split_pay'
  | 'combine_pay'
  | 'swap_pay'
  | 'direct_transfer';

export interface PaymentReceiptBundleV1 {
  version: 1;
  chainId: 8453;
  vault: 'v33' | 'v32';
  vaultAddress: Address;
  slipId: string;
  txHash: Hex;
  blockNumber: number;
  blockTimestamp: number;
  settlementType: ReceiptSettlementType;
  asset: SdkAssetSymbol;
  grossAmount: string;
  feeAmount: string;
  netAmount: string;
  recipient: Address;
  merchantLabel?: string;
  orderId?: string;
  orderDigest?: Hex;
  builderCode: 'bc_ea68lz8s';
  issuedAt: string;
  issuer?: Address;
  signature?: Hex;
}

export const PAYMENT_RECEIPT_EIP712_TYPES = {
  PaymentReceiptV1: [
    { name: 'version', type: 'uint8' },
    { name: 'chainId', type: 'uint256' },
    { name: 'vault', type: 'string' },
    { name: 'vaultAddress', type: 'address' },
    { name: 'slipId', type: 'string' },
    { name: 'txHash', type: 'bytes32' },
    { name: 'blockNumber', type: 'uint256' },
    { name: 'blockTimestamp', type: 'uint256' },
    { name: 'settlementType', type: 'string' },
    { name: 'asset', type: 'string' },
    { name: 'grossAmount', type: 'uint256' },
    { name: 'feeAmount', type: 'uint256' },
    { name: 'netAmount', type: 'uint256' },
    { name: 'recipient', type: 'address' },
    { name: 'merchantLabel', type: 'string' },
    { name: 'orderId', type: 'string' },
    { name: 'orderDigest', type: 'bytes32' },
    { name: 'builderCode', type: 'string' },
    { name: 'issuedAt', type: 'string' },
  ],
} as const;

const ZERO_BYTES32 = ('0x' + '00'.repeat(32)) as Hex;

export interface ReceiptIssuerSigner {
  address?: Address | string;
  getAddress?: () => Promise<string> | string;
  signTypedData?: (params: any, maybeTypes?: any, maybeValue?: any) => Promise<string>;
  signMessage?: (message: any) => Promise<string>;
}

export interface CreateSignedPaymentReceiptInput {
  vault?: 'v33' | 'v32';
  vaultAddress?: Address | string;
  slipId: string | bigint | number;
  txHash: Hex | string;
  blockNumber: number | bigint;
  blockTimestamp: number | bigint;
  settlementType: ReceiptSettlementType;
  asset: AnyAssetSymbol | string;
  grossAmount: bigint | string;
  feeAmount?: bigint | string;
  netAmount: bigint | string;
  recipient: Address | string;
  merchantLabel?: string;
  orderId?: string;
  orderDigest?: Hex;
  issuedAt?: string;
  signer?: ReceiptIssuerSigner;
}

export interface PaymentReceiptLogLike {
  address: string;
  topics: readonly Hex[] | Hex[];
  data: Hex;
}

export interface PaymentReceiptTxReceiptLike {
  status: 'success' | 'reverted' | number | string;
  blockNumber: bigint | number;
  transactionHash?: Hex;
  logs: readonly PaymentReceiptLogLike[] | PaymentReceiptLogLike[];
}

export interface ReceiptVerificationPublicClient {
  getTransactionReceipt(args: { hash: Hex }): Promise<PaymentReceiptTxReceiptLike>;
  getBlock?(args: { blockNumber: bigint }): Promise<{ timestamp: bigint | number }>;
  getTransaction?(args: { hash: Hex }): Promise<{ to?: Address | string | null; value?: bigint; input?: Hex }>;
  readContract?(args: {
    address: Address;
    abi: readonly unknown[];
    functionName: string;
    args?: readonly unknown[];
  }): Promise<unknown>;
}

export interface VerifyPaymentReceiptOptions {
  expectedRecipient?: Address | string;
  minNetAmount?: bigint;
  expectedAsset?: AnyAssetSymbol | string;
  expectedOrderId?: string;
  expectedIssuer?: Address | string;
  requireIssuerSignature?: boolean;
  verifyBlockTimestamp?: boolean;
  maxTimestampSkewSec?: number;
}

export interface VerifyPaymentReceiptResult {
  valid: boolean;
  reason?: string;
  verifiedNetAmount?: bigint;
  verifiedGrossAmount?: bigint;
  verifiedFeeAmount?: bigint;
  blockNumber?: number;
  blockTimestamp?: number;
  issuerVerified?: boolean;
  builderCodePresent?: boolean;
}

function parseNonNegativeUintString(raw: bigint | string, field: string): string {
  const str = typeof raw === 'bigint' ? raw.toString(10) : String(raw ?? '').trim();
  if (!/^(?:0|[1-9]\d*)$/.test(str)) {
    throw new Error(`Invalid ${field}: expected base-10 non-negative integer units`);
  }
  return str;
}

function sanitizeReceiptLabel(raw: string | undefined, maxLen: number): string | undefined {
  if (!raw) return undefined;
  let out = '';
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charCodeAt(i);
    out += c < 32 || c === 127 ? ' ' : raw[i]!;
  }
  const trimmed = out.replace(/\s+/g, ' ').trim().slice(0, maxLen);
  return trimmed || undefined;
}

export function computeOrderDigest(orderId: string): Hex {
  return keccak256(stringToHex(orderId));
}

export function buildPaymentReceiptTypedData(bundle: Omit<PaymentReceiptBundleV1, 'signature'>) {
  return {
    domain: {
      name: 'CryptoSLIP Payment Receipt',
      version: '1',
      chainId: BigInt(bundle.chainId),
      verifyingContract: getAddress(bundle.vaultAddress),
    },
    types: PAYMENT_RECEIPT_EIP712_TYPES,
    primaryType: 'PaymentReceiptV1' as const,
    message: {
      version: bundle.version,
      chainId: BigInt(bundle.chainId),
      vault: bundle.vault,
      vaultAddress: getAddress(bundle.vaultAddress),
      slipId: bundle.slipId,
      txHash: bundle.txHash,
      blockNumber: BigInt(bundle.blockNumber),
      blockTimestamp: BigInt(bundle.blockTimestamp),
      settlementType: bundle.settlementType,
      asset: bundle.asset,
      grossAmount: BigInt(bundle.grossAmount),
      feeAmount: BigInt(bundle.feeAmount),
      netAmount: BigInt(bundle.netAmount),
      recipient: getAddress(bundle.recipient),
      merchantLabel: bundle.merchantLabel ?? '',
      orderId: bundle.orderId ?? '',
      orderDigest: bundle.orderDigest ?? ZERO_BYTES32,
      builderCode: bundle.builderCode,
      issuedAt: bundle.issuedAt,
    },
  };
}

export function buildPaymentReceiptCanonicalMessage(bundle: Omit<PaymentReceiptBundleV1, 'signature'>): string {
  return [
    'CRYPTOSLIP_PAYMENT_RECEIPT_V1',
    `chainId:${bundle.chainId}`,
    `vault:${bundle.vault}:${getAddress(bundle.vaultAddress)}`,
    `slipId:${bundle.slipId}`,
    `txHash:${bundle.txHash.toLowerCase()}`,
    `block:${bundle.blockNumber}:${bundle.blockTimestamp}`,
    `type:${bundle.settlementType}`,
    `asset:${bundle.asset}`,
    `amounts:${bundle.grossAmount}:${bundle.feeAmount}:${bundle.netAmount}`,
    `recipient:${getAddress(bundle.recipient)}`,
    `order:${bundle.orderId ?? ''}:${bundle.orderDigest ?? ZERO_BYTES32}`,
    `builder:${bundle.builderCode}`,
    `issuedAt:${bundle.issuedAt}`,
  ].join('\n');
}

async function resolveSignerAddress(signer: ReceiptIssuerSigner): Promise<Address> {
  if (signer.address && isAddress(signer.address)) {
    return getAddress(signer.address);
  }
  if (typeof signer.getAddress === 'function') {
    const addr = await signer.getAddress();
    if (isAddress(addr)) return getAddress(addr);
  }
  throw new Error('Receipt signer does not expose a valid address');
}

async function signReceiptWithUniversalSigner(
  signer: ReceiptIssuerSigner,
  bundle: Omit<PaymentReceiptBundleV1, 'signature'>,
): Promise<Hex> {
  const typed = buildPaymentReceiptTypedData(bundle);
  if (typeof signer.signTypedData === 'function') {
    // Detect ethers v6 Signer (arity >= 3) vs viem LocalAccount / WalletClient / SlipSigner (single object param).
    if (signer.signTypedData.length >= 3) {
      const ethersDomain = {
        name: typed.domain.name,
        version: typed.domain.version,
        chainId: Number(typed.domain.chainId),
        verifyingContract: typed.domain.verifyingContract,
      };
      const ethersTypes = {
        PaymentReceiptV1: [...PAYMENT_RECEIPT_EIP712_TYPES.PaymentReceiptV1],
      };
      const sig = await signer.signTypedData(ethersDomain, ethersTypes, typed.message);
      if (!isHex(sig)) throw new Error('Invalid EIP-712 signature returned by signer');
      return sig;
    }
    const sig = await signer.signTypedData({
      domain: {
        name: typed.domain.name,
        version: typed.domain.version,
        chainId: Number(typed.domain.chainId),
        verifyingContract: typed.domain.verifyingContract,
      },
      types: typed.types,
      primaryType: typed.primaryType,
      message: typed.message,
    });
    if (!isHex(sig)) throw new Error('Invalid EIP-712 signature returned by signer');
    return sig;
  }

  if (typeof signer.signMessage === 'function') {
    const canonical = buildPaymentReceiptCanonicalMessage(bundle);
    // Support both viem `{ message }` and ethers `signMessage(string)` conventions.
    let sig: string;
    try {
      sig = await signer.signMessage({ message: canonical });
    } catch {
      sig = await signer.signMessage(canonical);
    }
    if (!isHex(sig)) throw new Error('Invalid EIP-191 signature returned by signer');
    return sig;
  }

  throw new Error('Receipt signer must implement signTypedData or signMessage');
}

/**
 * Creates a `PaymentReceiptBundleV1` proof-of-payment bundle, optionally signed by an `issuer`
 * wallet (EIP-712 `PaymentReceiptV1` or EIP-191 fallback). Watch-only POS servers with zero
 * private keys can omit `signer` and rely on deterministic on-chain verification.
 */
export async function createSignedPaymentReceipt(
  input: CreateSignedPaymentReceiptInput,
): Promise<PaymentReceiptBundleV1> {
  const vaultTag: 'v33' | 'v32' = input.vault
    ? input.vault
    : input.vaultAddress
      ? (() => {
          const detected = vaultTagForAddress(input.vaultAddress);
          if (detected !== 'v33' && detected !== 'v32') {
            throw new Error(`Receipt vaultAddress must be canonical v33 or v32: ${input.vaultAddress}`);
          }
          return detected;
        })()
      : 'v33';

  const expectedVaultAddr = VAULTS[vaultTag].address;
  if (input.vaultAddress && getAddress(input.vaultAddress) !== expectedVaultAddr) {
    throw new Error(`Vault tag ${vaultTag} does not match vaultAddress ${input.vaultAddress}`);
  }

  const txHashStr = String(input.txHash || '').trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(txHashStr)) {
    throw new Error('Invalid transaction hash for receipt');
  }
  if (!isAddress(input.recipient)) {
    throw new Error('Invalid recipient address for receipt');
  }

  const slipIdStr = parseNonNegativeUintString(
    typeof input.slipId === 'number' ? BigInt(input.slipId) : input.slipId,
    'slipId',
  );
  const blockNumber = Number(input.blockNumber);
  const blockTimestamp = Number(input.blockTimestamp);
  if (!Number.isSafeInteger(blockNumber) || blockNumber < 0) {
    throw new Error('Invalid blockNumber for receipt');
  }
  if (!Number.isSafeInteger(blockTimestamp) || blockTimestamp <= 0) {
    throw new Error('Invalid blockTimestamp for receipt');
  }

  const asset = normalizeSdkAsset(input.asset);
  const grossStr = parseNonNegativeUintString(input.grossAmount, 'grossAmount');
  const netStr = parseNonNegativeUintString(input.netAmount, 'netAmount');
  const grossBig = BigInt(grossStr);
  const netBig = BigInt(netStr);
  if (netBig <= 0n) {
    throw new Error('Receipt netAmount must be strictly positive');
  }
  const computedFee = input.feeAmount !== undefined
    ? BigInt(parseNonNegativeUintString(input.feeAmount, 'feeAmount'))
    : grossBig >= netBig
      ? grossBig - netBig
      : 0n;
  if (grossBig - computedFee !== netBig) {
    throw new Error('Receipt amounts inconsistent: grossAmount - feeAmount must equal netAmount');
  }

  const merchantLabel = sanitizeReceiptLabel(input.merchantLabel, 64);
  const orderId = sanitizeReceiptLabel(input.orderId, 128);
  const orderDigest = input.orderDigest ?? (orderId ? computeOrderDigest(orderId) : undefined);
  if (orderDigest && !/^0x[0-9a-fA-F]{64}$/.test(orderDigest)) {
    throw new Error('Invalid orderDigest: expected 32-byte hex');
  }

  const issuedAt = input.issuedAt ?? new Date().toISOString();

  const unsignedBundle: PaymentReceiptBundleV1 = {
    version: 1,
    chainId: BASE_CHAIN_ID,
    vault: vaultTag,
    vaultAddress: expectedVaultAddr,
    slipId: slipIdStr,
    txHash: txHashStr.toLowerCase() as Hex,
    blockNumber,
    blockTimestamp,
    settlementType: input.settlementType,
    asset,
    grossAmount: grossStr,
    feeAmount: computedFee.toString(10),
    netAmount: netStr,
    recipient: getAddress(input.recipient),
    ...(merchantLabel ? { merchantLabel } : {}),
    ...(orderId ? { orderId } : {}),
    ...(orderDigest ? { orderDigest: orderDigest.toLowerCase() as Hex } : {}),
    builderCode: DEFAULT_CRYPTOSLIP_BUILDER_CODE,
    issuedAt,
  };

  if (!input.signer) {
    return unsignedBundle;
  }

  const issuer = await resolveSignerAddress(input.signer);
  const withIssuer: PaymentReceiptBundleV1 = { ...unsignedBundle, issuer };
  const signature = await signReceiptWithUniversalSigner(input.signer, withIssuer);
  return { ...withIssuer, signature };
}

/**
 * Verifies the cryptographic EIP-712 (or EIP-191) `issuer` signature on a `PaymentReceiptBundleV1`.
 */
export async function verifyPaymentReceiptSignature(bundle: PaymentReceiptBundleV1): Promise<boolean> {
  if (!bundle.issuer || !bundle.signature) return false;
  if (!isAddress(bundle.issuer) || !isHex(bundle.signature)) return false;
  const expectedIssuer = getAddress(bundle.issuer).toLowerCase();
  const { signature, ...unsigned } = bundle;

  try {
    const typed = buildPaymentReceiptTypedData(unsigned);
    const recovered = await recoverTypedDataAddress({
      domain: {
        name: typed.domain.name,
        version: typed.domain.version,
        chainId: typed.domain.chainId,
        verifyingContract: typed.domain.verifyingContract,
      },
      types: typed.types,
      primaryType: typed.primaryType,
      message: typed.message,
      signature,
    });
    if (recovered.toLowerCase() === expectedIssuer) return true;
  } catch {
    // Fall through to EIP-191 canonical message verification
  }

  try {
    const canonical = buildPaymentReceiptCanonicalMessage(unsigned);
    const recoveredMsg = await recoverMessageAddress({ message: canonical, signature });
    return recoveredMsg.toLowerCase() === expectedIssuer;
  } catch {
    return false;
  }
}

/**
 * 1-RPC-batch cryptographic verification of a `PaymentReceiptBundleV1` against Base (`8453`).
 *
 * Fetches `getTransactionReceipt` (+ `getBlock` timestamp & `getTransaction` when needed) in one
 * concurrent batch, verifies exact Vault / TradeRouter settlement event topics AND canonical
 * ERC-20 `Transfer` logs (preventing cross-asset decimal spoofing), and checks optional `issuer`
 * EIP-712/EIP-191 signatures.
 */
export async function verifyPaymentReceiptOnChain(
  publicClient: ReceiptVerificationPublicClient,
  bundle: PaymentReceiptBundleV1,
  options: VerifyPaymentReceiptOptions = {},
): Promise<VerifyPaymentReceiptResult> {
  try {
    if (bundle.version !== 1 || bundle.chainId !== BASE_CHAIN_ID) {
      return { valid: false, reason: 'Unsupported receipt version or chainId' };
    }
    if (bundle.builderCode !== DEFAULT_CRYPTOSLIP_BUILDER_CODE) {
      return { valid: false, reason: 'Invalid receipt builderCode' };
    }
    if (bundle.vault !== 'v33' && bundle.vault !== 'v32') {
      return { valid: false, reason: 'Unsupported receipt vault tag' };
    }
    const canonicalVault = VAULTS[bundle.vault].address;
    if (!isAddress(bundle.vaultAddress) || getAddress(bundle.vaultAddress) !== canonicalVault) {
      return { valid: false, reason: 'Receipt vaultAddress does not match canonical Base vault' };
    }
    if (!/^0x[0-9a-fA-F]{64}$/.test(bundle.txHash)) {
      return { valid: false, reason: 'Malformed receipt txHash' };
    }
    if (!isAddress(bundle.recipient)) {
      return { valid: false, reason: 'Malformed receipt recipient address' };
    }

    const recipientChecksum = getAddress(bundle.recipient);
    const recipientLower = recipientChecksum.toLowerCase();
    if (options.expectedRecipient && getAddress(options.expectedRecipient).toLowerCase() !== recipientLower) {
      return { valid: false, reason: 'Receipt recipient does not match expected recipient' };
    }

    const asset = normalizeSdkAsset(bundle.asset);
    if (options.expectedAsset && normalizeSdkAsset(options.expectedAsset) !== asset) {
      return { valid: false, reason: 'Receipt asset does not match expected asset' };
    }

    if (options.expectedOrderId !== undefined && bundle.orderId !== options.expectedOrderId) {
      return { valid: false, reason: 'Receipt orderId does not match expected orderId' };
    }
    if (bundle.orderId && bundle.orderDigest) {
      if (computeOrderDigest(bundle.orderId).toLowerCase() !== bundle.orderDigest.toLowerCase()) {
        return { valid: false, reason: 'Receipt orderDigest does not match keccak256(orderId)' };
      }
    }

    const grossBig = BigInt(parseNonNegativeUintString(bundle.grossAmount, 'grossAmount'));
    const feeBig = BigInt(parseNonNegativeUintString(bundle.feeAmount, 'feeAmount'));
    const netBig = BigInt(parseNonNegativeUintString(bundle.netAmount, 'netAmount'));
    if (netBig <= 0n || grossBig - feeBig !== netBig) {
      return { valid: false, reason: 'Receipt gross, fee, and net amounts do not balance' };
    }
    if (options.minNetAmount !== undefined && netBig < options.minNetAmount) {
      return { valid: false, reason: 'Receipt netAmount is below required minimum' };
    }

    // Verify optional / required issuer signature before RPC checks
    let issuerVerified: boolean | undefined;
    if (options.requireIssuerSignature && (!bundle.issuer || !bundle.signature)) {
      return { valid: false, reason: 'Receipt is missing required issuer signature' };
    }
    if (options.expectedIssuer) {
      if (!bundle.issuer || getAddress(bundle.issuer).toLowerCase() !== getAddress(options.expectedIssuer).toLowerCase()) {
        return { valid: false, reason: 'Receipt issuer does not match expected issuer' };
      }
    }
    if (bundle.issuer || bundle.signature) {
      issuerVerified = await verifyPaymentReceiptSignature(bundle);
      if (!issuerVerified) {
        return { valid: false, reason: 'Receipt issuer signature verification failed', issuerVerified: false };
      }
    }

    const needTxLookup =
      (bundle.settlementType === 'direct_transfer' && asset === 'ETH') || Boolean(publicClient.getTransaction);
    const shouldVerifyBlockTs = options.verifyBlockTimestamp !== false && typeof publicClient.getBlock === 'function';

    // Single concurrent RPC batch (viem batch HTTP transport coalesces into 1 JSON-RPC POST)
    const [txReceipt, blockInfo, txInfo] = await Promise.all([
      publicClient.getTransactionReceipt({ hash: bundle.txHash }),
      shouldVerifyBlockTs
        ? publicClient.getBlock!({ blockNumber: BigInt(bundle.blockNumber) }).catch(() => null)
        : Promise.resolve(null),
      needTxLookup && typeof publicClient.getTransaction === 'function'
        ? publicClient.getTransaction({ hash: bundle.txHash }).catch(() => null)
        : Promise.resolve(null),
    ]);

    const txSucceeded =
      txReceipt.status === 'success' || txReceipt.status === 1 || txReceipt.status === '0x1';
    if (!txSucceeded) {
      return { valid: false, reason: 'On-chain transaction reverted or failed' };
    }

    const onChainBlockNumber = Number(txReceipt.blockNumber);
    if (onChainBlockNumber !== bundle.blockNumber) {
      return {
        valid: false,
        reason: `Receipt blockNumber ${bundle.blockNumber} does not match on-chain ${onChainBlockNumber}`,
      };
    }

    let verifiedBlockTimestamp = bundle.blockTimestamp;
    if (blockInfo) {
      verifiedBlockTimestamp = Number(blockInfo.timestamp);
      const maxSkew = options.maxTimestampSkewSec ?? 0;
      if (Math.abs(verifiedBlockTimestamp - bundle.blockTimestamp) > maxSkew) {
        return {
          valid: false,
          reason: `Receipt blockTimestamp ${bundle.blockTimestamp} does not match block ${verifiedBlockTimestamp}`,
        };
      }
    } else if (options.verifyBlockTimestamp === true && typeof publicClient.getBlock === 'function') {
      return { valid: false, reason: 'Unable to fetch block header to verify blockTimestamp' };
    }

    const builderCodePresent = txInfo?.input
      ? txInfo.input.toLowerCase().endsWith(ERC8021_MARKER_HEX)
      : undefined;

    const expectedTokenAddr = assetAddress(asset).toLowerCase();
    const vaultAddrLower = canonicalVault.toLowerCase();
    const routerAddrLower = tradeRouterForVault(bundle.vault).toLowerCase();
    const slipIdBig = BigInt(parseNonNegativeUintString(bundle.slipId, 'slipId'));

    // Scan ERC-20 Transfer logs for canonical ERC-20 assets
    let matchedErc20TransferAmount = 0n;
    if (asset !== 'ETH') {
      for (const log of txReceipt.logs) {
        if (log.address.toLowerCase() !== expectedTokenAddr) continue;
        try {
          const decoded = decodeEventLog({
            abi: ERC20_PERMIT_EIP3009_ABI,
            data: log.data,
            topics: log.topics as [Hex, ...Hex[]],
          });
          if (decoded.eventName === 'Transfer') {
            const toAddr = String(decoded.args.to || '').toLowerCase();
            const val = BigInt(decoded.args.value);
            if (bundle.settlementType === 'mint') {
              if (toAddr === vaultAddrLower) matchedErc20TransferAmount += val;
            } else if (toAddr === recipientLower) {
              matchedErc20TransferAmount += val;
            }
          }
        } catch {
          // Ignore unrelated events on token contract
        }
      }
    }

    // Settlement-specific event verification
    if (bundle.settlementType === 'direct_transfer') {
      if (asset === 'ETH') {
        if (!txInfo || !txInfo.to || txInfo.to.toLowerCase() !== recipientLower || BigInt(txInfo.value ?? 0n) !== netBig) {
          return { valid: false, reason: 'Direct ETH transfer recipient or value mismatch' };
        }
      } else if (matchedErc20TransferAmount !== netBig) {
        return {
          valid: false,
          reason: `Direct ${asset} Transfer log mismatch (expected ${netBig}, saw ${matchedErc20TransferAmount})`,
        };
      }
    } else if (bundle.settlementType === 'swap_pay') {
      let sawSwapPay = false;
      for (const log of txReceipt.logs) {
        if (log.address.toLowerCase() !== routerAddrLower) continue;
        try {
          const decoded = decodeEventLog({
            abi: CRYPTO_SLIP_TRADE_ROUTER_V32_ABI,
            data: log.data,
            topics: log.topics as [Hex, ...Hex[]],
          });
          if (
            decoded.eventName === 'SlipSwappedAndPaid' &&
            decoded.args.inputSlipId === slipIdBig &&
            decoded.args.merchant.toLowerCase() === recipientLower &&
            decoded.args.outAsset.toLowerCase() === expectedTokenAddr &&
            decoded.args.amountOut === netBig
          ) {
            sawSwapPay = true;
            break;
          }
        } catch {
          // Ignore non-matching log
        }
      }
      if (!sawSwapPay) {
        return { valid: false, reason: 'No matching SlipSwappedAndPaid event found in transaction logs' };
      }
      if (asset !== 'ETH' && matchedErc20TransferAmount < netBig) {
        return { valid: false, reason: `Missing canonical ${asset} Transfer log to recipient` };
      }
    } else {
      let sawVaultEvent = false;
      for (const log of txReceipt.logs) {
        if (log.address.toLowerCase() !== vaultAddrLower) continue;
        try {
          const decoded = decodeEventLog({
            abi: CRYPTO_SLIP_VAULT_V32_ABI,
            data: log.data,
            topics: log.topics as [Hex, ...Hex[]],
          });

          if (
            bundle.settlementType === 'mint' &&
            decoded.eventName === 'SlipMinted' &&
            decoded.args.slipId === slipIdBig &&
            decoded.args.asset.toLowerCase() === expectedTokenAddr &&
            decoded.args.amount === netBig
          ) {
            sawVaultEvent = true;
            break;
          }

          if (
            bundle.settlementType === 'keep' &&
            decoded.eventName === 'SlipAccepted' &&
            decoded.args.slipId === slipIdBig &&
            decoded.args.newHolder.toLowerCase() === recipientLower
          ) {
            sawVaultEvent = true;
            break;
          }

          if (
            bundle.settlementType === 'claim' &&
            decoded.eventName === 'SlipCashed' &&
            decoded.args.slipId === slipIdBig &&
            decoded.args.recipient.toLowerCase() === recipientLower &&
            decoded.args.netPayout === netBig
          ) {
            sawVaultEvent = true;
            break;
          }

          if (
            bundle.settlementType === 'split_pay' &&
            decoded.eventName === 'SlipSplitAndPaid' &&
            decoded.args.originalSlipId === slipIdBig &&
            decoded.args.merchant.toLowerCase() === recipientLower
          ) {
            const paymentGross = decoded.args.paymentAmount;
            const expectedFee = computeProtocolFeeCeiling(paymentGross);
            const expectedNet = paymentGross - expectedFee;
            if (paymentGross === grossBig && expectedNet === netBig) {
              sawVaultEvent = true;
              break;
            }
          }

          if (
            bundle.settlementType === 'combine_pay' &&
            decoded.eventName === 'SlipsRearrangedAndPaid' &&
            decoded.args.merchant.toLowerCase() === recipientLower &&
            decoded.args.consumedSlipIds.includes(slipIdBig)
          ) {
            const paymentGross = decoded.args.paymentAmount;
            const expectedFee = computeProtocolFeeCeiling(paymentGross);
            const expectedNet = paymentGross - expectedFee;
            if (paymentGross === grossBig && expectedNet === netBig) {
              sawVaultEvent = true;
              break;
            }
          }
        } catch {
          // Ignore other vault events
        }
      }

      if (!sawVaultEvent) {
        return {
          valid: false,
          reason: `No matching ${bundle.settlementType} event found on CryptoSlipVaultV32`,
        };
      }

      // Cross-verify canonical ERC-20 Transfer log to prevent cross-asset decimal confusion
      if (
        asset !== 'ETH' &&
        (bundle.settlementType === 'claim' ||
          bundle.settlementType === 'split_pay' ||
          bundle.settlementType === 'combine_pay')
      ) {
        if (matchedErc20TransferAmount < netBig) {
          return {
            valid: false,
            reason: `Missing matching ${asset} Transfer log to recipient for ${bundle.settlementType}`,
          };
        }
      }

      // For native ETH slip settlements without ERC-20 Transfer logs, verify slip asset on-chain when readContract is available
      if (
        asset === 'ETH' &&
        typeof publicClient.readContract === 'function' &&
        (bundle.settlementType === 'claim' ||
          bundle.settlementType === 'split_pay' ||
          bundle.settlementType === 'combine_pay' ||
          bundle.settlementType === 'keep')
      ) {
        const slipTuple = (await publicClient
          .readContract({
            address: canonicalVault,
            abi: CRYPTO_SLIP_VAULT_V32_ABI,
            functionName: 'slips',
            args: [slipIdBig],
          })
          .catch(() => null)) as readonly [Address, ...unknown[]] | null;
        if (slipTuple && slipTuple[0].toLowerCase() !== NATIVE_ETH_ADDRESS) {
          return { valid: false, reason: 'On-chain slip asset is not native ETH' };
        }
      }
    }

    return {
      valid: true,
      verifiedNetAmount: netBig,
      verifiedGrossAmount: grossBig,
      verifiedFeeAmount: feeBig,
      blockNumber: onChainBlockNumber,
      blockTimestamp: verifiedBlockTimestamp,
      ...(issuerVerified !== undefined ? { issuerVerified } : {}),
      ...(builderCodePresent !== undefined ? { builderCodePresent } : {}),
    };
  } catch (err) {
    return {
      valid: false,
      reason: err instanceof Error ? err.message : 'Receipt verification failed',
    };
  }
}

// ============================================================================
// CSV & Printable Obsidian/Pearl HTML Export (100% AGENTS.md Rule #3 Green-Zone)
// ============================================================================

export const PAYMENT_RECEIPT_CSV_HEADER =
  'IssuedAtUTC,BlockTimestampUTC,BlockNumber,SettlementType,Asset,GrossUnits,FeeUnits,NetUnits,FormattedNetAmount,Recipient,Vault,SlipId,TxHash,MerchantLabel,OrderId,BuilderCode,Issuer';

function escapeCsvCell(value: string | number | undefined): string {
  const raw = String(value ?? '');
  const formulaSafe = /^[=+\-@\t\r]/.test(raw) ? `'${raw}` : raw;
  return `"${formulaSafe.replace(/"/g, '""')}"`;
}

export function formatReceiptHumanAmount(rawUnits: string | bigint, asset: SdkAssetSymbol): string {
  const decimals = decimalsForAsset(asset);
  const formatted = formatUnits(BigInt(rawUnits), decimals);
  if (asset === 'USDC') {
    const [whole = '0', frac = ''] = formatted.split('.');
    const twoDec = frac.length >= 2 ? frac.slice(0, 6).replace(/0+$/, '') : frac;
    const paddedFrac = twoDec.length < 2 ? twoDec.padEnd(2, '0') : twoDec;
    return `${whole}.${paddedFrac} USDC`;
  }
  const trimmed = formatted.includes('.') ? formatted.replace(/\.?0+$/, '') : formatted;
  return `${trimmed || '0'} ${asset}`;
}

export function formatReceiptCsvRow(bundle: PaymentReceiptBundleV1): string {
  const blockIso = new Date(bundle.blockTimestamp * 1000).toISOString();
  const humanNet = formatReceiptHumanAmount(bundle.netAmount, bundle.asset);
  return [
    escapeCsvCell(bundle.issuedAt),
    escapeCsvCell(blockIso),
    escapeCsvCell(bundle.blockNumber),
    escapeCsvCell(bundle.settlementType),
    escapeCsvCell(bundle.asset),
    escapeCsvCell(bundle.grossAmount),
    escapeCsvCell(bundle.feeAmount),
    escapeCsvCell(bundle.netAmount),
    escapeCsvCell(humanNet),
    escapeCsvCell(bundle.recipient),
    escapeCsvCell(bundle.vault),
    escapeCsvCell(bundle.slipId),
    escapeCsvCell(bundle.txHash),
    escapeCsvCell(bundle.merchantLabel ?? ''),
    escapeCsvCell(bundle.orderId ?? ''),
    escapeCsvCell(bundle.builderCode),
    escapeCsvCell(bundle.issuer ?? ''),
  ].join(',');
}

export function formatReceiptsCsv(bundles: readonly PaymentReceiptBundleV1[]): string {
  return [PAYMENT_RECEIPT_CSV_HEADER, ...bundles.map((b) => formatReceiptCsvRow(b))].join('\n');
}

function escapeHtml(raw: string): string {
  return raw
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function shortHex(hex: string, head = 8, tail = 6): string {
  if (hex.length <= head + tail + 2) return hex;
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}

function humanSettlementLabel(settlementType: ReceiptSettlementType): string {
  switch (settlementType) {
    case 'mint':
      return 'Slip created';
    case 'claim':
      return 'Slip claimed to wallet';
    case 'keep':
      return 'Kept in Slips';
    case 'split_pay':
      return 'Fractional slip payment';
    case 'combine_pay':
      return 'Combined slip payment';
    case 'swap_pay':
      return 'Cross-asset slip payment';
    case 'direct_transfer':
      return 'Direct wallet payment';
  }
}

/**
 * Renders a self-contained, zero-external-request, print-ready Obsidian/Pearl HTML receipt
 * strictly obeying `AGENTS.md` Rule #3 & `DESIGN.md` tokens (`tabular-nums`, `#090B0A` Obsidian
 * canvas on screen, crisp `#FFFFFF` Pearl print stylesheet, zero forbidden custodial/jargon words).
 */
export function renderPrintableReceiptHtml(bundle: PaymentReceiptBundleV1): string {
  const netLabel = escapeHtml(formatReceiptHumanAmount(bundle.netAmount, bundle.asset));
  const grossLabel = escapeHtml(formatReceiptHumanAmount(bundle.grossAmount, bundle.asset));
  const feeLabel = escapeHtml(formatReceiptHumanAmount(bundle.feeAmount, bundle.asset));
  const methodLabel = escapeHtml(humanSettlementLabel(bundle.settlementType));
  const settledIso = escapeHtml(new Date(bundle.blockTimestamp * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC'));
  const recipientFull = escapeHtml(bundle.recipient);
  const recipientShort = escapeHtml(shortHex(bundle.recipient, 8, 6));
  const txFull = escapeHtml(bundle.txHash);
  const txShort = escapeHtml(shortHex(bundle.txHash, 10, 8));
  const vaultShort = escapeHtml(`${bundle.vault} (${shortHex(bundle.vaultAddress, 6, 4)})`);
  const slipIdSafe = escapeHtml(bundle.slipId);
  const merchantRow = bundle.merchantLabel
    ? `<div class="meta-row"><span class="meta-key">Merchant</span><span class="meta-val">${escapeHtml(bundle.merchantLabel)}</span></div>`
    : '';
  const orderRow = bundle.orderId
    ? `<div class="meta-row"><span class="meta-key">Order reference</span><span class="meta-val mono">${escapeHtml(bundle.orderId)}</span></div>`
    : '';
  const issuerRow = bundle.issuer
    ? `<div class="meta-row"><span class="meta-key">Signed receipt</span><span class="meta-val mono" title="${escapeHtml(bundle.issuer)}">${escapeHtml(shortHex(bundle.issuer, 8, 6))}</span></div>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Payment Receipt · CryptoSLIP</title>
<style>
  :root {
    --bg: #090B0A;
    --surface1: #111413;
    --surface2: #171B19;
    --accent: #5E6AD2;
    --periwinkle: #818CF8;
    --ink1: #F5F7F6;
    --ink2: #9CA49F;
    --hairline: rgba(255, 255, 255, 0.08);
    --catchlight: rgba(255, 255, 255, 0.14);
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--ink1);
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "Segoe UI", Roboto, sans-serif;
    font-size: 16px;
    line-height: 1.45;
    font-variant-numeric: tabular-nums;
    padding: 32px 16px;
    display: flex;
    justify-content: center;
  }
  .receipt-frame {
    width: 100%;
    max-width: 480px;
    background: var(--surface1);
    border: 1px solid var(--hairline);
    border-top-color: var(--catchlight);
    border-radius: 24px;
    padding: 28px 24px;
  }
  .top-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 20px;
  }
  .brand-mark {
    font-size: 15px;
    font-weight: 700;
    letter-spacing: -0.01em;
    color: var(--ink1);
  }
  .verified-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border-radius: 9999px;
    background: rgba(129, 140, 248, 0.14);
    border: 1px solid rgba(129, 140, 248, 0.35);
    color: var(--periwinkle);
    font-size: 12px;
    font-weight: 700;
  }
  .hero-title {
    font-size: 24px;
    font-weight: 700;
    letter-spacing: -0.02em;
    color: var(--ink1);
  }
  .hero-sub {
    font-size: 15px;
    color: var(--ink2);
    margin-top: 4px;
  }
  .amount-stage {
    margin: 24px 0;
    padding: 20px;
    border-radius: 16px;
    background: var(--surface2);
    border: 1px solid var(--hairline);
  }
  .amount-caption {
    font-size: 13px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--ink2);
  }
  .amount-value {
    font-size: 36px;
    font-weight: 800;
    letter-spacing: -0.03em;
    color: var(--ink1);
    margin-top: 6px;
    font-variant-numeric: tabular-nums;
  }
  .tear-divider {
    border-top: 1px dashed rgba(255, 255, 255, 0.14);
    margin: 20px 0;
  }
  .meta-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .meta-row {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: 16px;
    font-size: 15px;
  }
  .meta-key {
    color: var(--ink2);
    flex-shrink: 0;
  }
  .meta-val {
    color: var(--ink1);
    font-weight: 600;
    text-align: right;
    word-break: break-all;
    font-variant-numeric: tabular-nums;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 13px;
  }
  .foot-note {
    margin-top: 24px;
    padding-top: 16px;
    border-top: 1px solid var(--hairline);
    font-size: 13px;
    color: var(--ink2);
    text-align: center;
  }
  @media print {
    :root {
      --bg: #FFFFFF;
      --surface1: #FFFFFF;
      --surface2: #F6F8F7;
      --ink1: #090B0A;
      --ink2: #4A524E;
      --periwinkle: #3E4AB8;
      --hairline: #DDE2DF;
      --catchlight: #DDE2DF;
    }
    body { padding: 0; }
    .receipt-frame { max-width: 100%; border-color: #DDE2DF; }
    .tear-divider { border-top-color: #BFC7C2; }
  }
</style>
</head>
<body>
  <main class="receipt-frame">
    <div class="top-bar">
      <span class="brand-mark">CryptoSLIP</span>
      <span class="verified-pill">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"></polyline></svg>
        Confirmed
      </span>
    </div>
    <h1 class="hero-title">Payment Receipt</h1>
    <p class="hero-sub">Non-custodial settlement on Base</p>
    <section class="amount-stage" aria-label="Settled amount">
      <div class="amount-caption">Net settled</div>
      <div class="amount-value">${netLabel}</div>
    </section>
    <div class="meta-list">
      ${merchantRow}
      ${orderRow}
      <div class="meta-row"><span class="meta-key">Method</span><span class="meta-val">${methodLabel}</span></div>
      <div class="meta-row"><span class="meta-key">Gross amount</span><span class="meta-val">${grossLabel}</span></div>
      <div class="meta-row"><span class="meta-key">Protocol fee</span><span class="meta-val">${feeLabel}</span></div>
      <div class="meta-row"><span class="meta-key">Recipient wallet</span><span class="meta-val mono" title="${recipientFull}">${recipientShort}</span></div>
    </div>
    <div class="tear-divider"></div>
    <div class="meta-list">
      <div class="meta-row"><span class="meta-key">Slip ID</span><span class="meta-val mono">#${slipIdSafe}</span></div>
      <div class="meta-row"><span class="meta-key">Smart contract</span><span class="meta-val mono">${vaultShort}</span></div>
      <div class="meta-row"><span class="meta-key">Transaction</span><span class="meta-val mono" title="${txFull}">${txShort}</span></div>
      <div class="meta-row"><span class="meta-key">Confirmation height</span><span class="meta-val mono">#${bundle.blockNumber}</span></div>
      <div class="meta-row"><span class="meta-key">Settled at</span><span class="meta-val mono">${settledIso}</span></div>
      <div class="meta-row"><span class="meta-key">Builder attribution</span><span class="meta-val mono">${escapeHtml(bundle.builderCode)}</span></div>
      ${issuerRow}
    </div>
    <p class="foot-note">1:1 asset-backed smart contract settlement · Base Chain ID 8453 · Verify independently via transaction hash ${txShort}</p>
  </main>
</body>
</html>`;
}
