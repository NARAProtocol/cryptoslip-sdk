import type { Address, Hex } from 'viem';

export type VaultTag = 'v2' | 'v3' | 'v32' | 'v33';
export type VaultKey = VaultTag;

/** Canonical SDK asset symbols (`cbBTC` on-chain) plus `'BTC'` link alias for 100% client parity. */
export type SdkAssetSymbol = 'USDC' | 'cbBTC' | 'ETH' | 'NARA';
export type SupportedLinkAsset = 'USDC' | 'BTC' | 'ETH' | 'NARA';
export type AnyAssetSymbol = SdkAssetSymbol | SupportedLinkAsset;

export const BASE_CHAIN_ID = 8453 as const;
export const BASE_CHAIN_ID_BIG = 8453n;

/** Active production issuance vault on Base Mainnet (`8453`). */
export const ISSUE_VAULT: VaultTag = 'v33';

// ============================================================================
// Canonical Base Mainnet (8453) Protocol Registry
// ============================================================================

export const CANONICAL_VAULT_V33_ADDRESS = '0x3f80aa68Fb4834d6E119EE1cf932C14419Cf63EB' as const satisfies Address;
export const CANONICAL_NFT_V33_ADDRESS = '0x356a701DABDeabe61F7Fc79D730617CEcbd7B94f' as const satisfies Address;
export const CANONICAL_TRADE_ROUTER_V33_ADDRESS = '0x2069CA17D45d3421D28f15F20262575333CECF51' as const satisfies Address;

/** Live `DOMAIN_SEPARATOR()` on `CryptoSlipVaultV32` (`v33` on Base `8453`). */
export const V33_VAULT_DOMAIN_SEPARATOR =
  '0x076870709b393d478b4c211d268fbfca58f1c82b2adadbd300e74064781b9475' as const satisfies Hex;

export const CANONICAL_VAULT_V32_ADDRESS = '0x38BF0321FA7489576978353a6a8da4A3e85C2F18' as const satisfies Address;
export const CANONICAL_NFT_V32_ADDRESS = '0x36181Ca1B0210b6Ea8E56755dA7B06c34ba481C0' as const satisfies Address;
export const CANONICAL_TRADE_ROUTER_V32_ADDRESS = '0x295E72cB3dc09582F32e0fEB7e0e650752219a7f' as const satisfies Address;

export const CANONICAL_VAULT_V3_ADDRESS = '0x4Dc2b5A801A81b17b8d05C737c727FEd1f30699A' as const satisfies Address;
export const CANONICAL_NFT_V3_ADDRESS = '0x7e6dc2579596aeB994cb3774D804b54fFc20CF79' as const satisfies Address;

export const CANONICAL_VAULT_V2_ADDRESS = '0x87aadDF2d3aa11Cddf36939715508066a99BA415' as const satisfies Address;
export const CANONICAL_NFT_V2_ADDRESS = '0x0B76801738e922Be7EDf397A6434837aF431E159' as const satisfies Address;

export const TREASURY_SAFE_ADDRESS = '0xe320C281c86079eA85f2Bc67864E873A61D551E3' as const satisfies Address;

export const MULTICALL3_ADDRESS = '0xcA11bde05977b3631167028862bE2a173976CA11' as const satisfies Address;
export const CIRCLE_TOKEN_PAYMASTER_V08_ADDRESS = '0x0578cFB241215b77442a541325d6A4E6dFE700Ec' as const satisfies Address;
export const CIRCLE_USDC_PAYMASTER_V08 = CIRCLE_TOKEN_PAYMASTER_V08_ADDRESS;
export const CIRCLE_TOKEN_PAYMASTER_V07_ADDRESS = '0x6C973eBe80dCD8660841D4356bf15c32460271C9' as const satisfies Address;
export const ENTRY_POINT_V08_ADDRESS = '0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108' as const satisfies Address;
export const ENTRY_POINT_V08 = ENTRY_POINT_V08_ADDRESS;
export const ENTRY_POINT_V07_ADDRESS = '0x0000000071727De22E5E9d8BAf0edAc6f37da032' as const satisfies Address;
export const SIMPLE_7702_ACCOUNT_ADDRESS = '0xe6Cae83BdE06E4c305530e199D7217f42808555B' as const satisfies Address;
export const SIMPLE_7702_ACCOUNT = SIMPLE_7702_ACCOUNT_ADDRESS;
export const CANONICAL_SIMPLE_7702_DELEGATION_CODE =
  `0xef0100${SIMPLE_7702_ACCOUNT_ADDRESS.slice(2).toLowerCase()}` as Hex;

/** Mandatory Uniswap V4 Hook for 100% of NARA swap legs inside official apps & SDKs. */
export const NARA_LIQUIDITY_HOOK_V5_ADDRESS = '0x07d8F2Dfd121B10dE3176DeAb6A8C0eaa2646aCC' as const satisfies Address;
export const NARALiquidityHookV5 = NARA_LIQUIDITY_HOOK_V5_ADDRESS;

export const UNIVERSAL_ROUTER_ADDRESS = '0x6fF5693b99212Da76ad316178A184AB56D299b43' as const satisfies Address;
export const UNISWAP_UNIVERSAL_ROUTER = UNIVERSAL_ROUTER_ADDRESS;
export const UNISWAP_PERMIT2_ADDRESS = '0x000000000022D473030F116dDEE9F6B43aC78BA3' as const satisfies Address;

// ============================================================================
// Canonical Web, Sovereign ENS, Relay & Voice Origins
// ============================================================================

export const CANONICAL_SHARE_ORIGIN = 'https://slip.naraprotocol.io' as const;
export const SOVEREIGN_ENS_ORIGIN = 'https://cryptoslip.eth.limo' as const;
export const TELEGRAM_APP_LINK = 'https://t.me/cryptoslip_bot/SLIP' as const;
export const WORKER_RELAY_GATEWAY = 'https://cryptoslip-edge.naraprotocol.workers.dev' as const;
export const AKASH_RELAY_GATEWAY = 'https://relay1.cryptoslip.tech' as const;
export const VOICE_GATEWAY_URL = 'https://cryptoslip-voice.naraprotocol.workers.dev' as const;

/** Compressed secp256k1 public key for the Cloudflare Worker Slip Seal (`cs-seal-v1`). */
export const SLIP_SEAL_PUBLIC_KEY =
  '0x0318c3235a0cdf1fed964e75bafe560897a68dbf8be4802b7b8f40a10d5dbe98b8' as const satisfies Hex;

export const DEFAULT_BASE_RPC_URLS = [
  'https://mainnet.base.org',
  'https://1rpc.io/base',
  'https://base.llamarpc.com',
] as const;

export const PUBLIC_BASE_BUNDLERS = [
  'https://public.pimlico.io/v2/8453/rpc',
  'https://api.candide.dev/public/v3/8453',
] as const;

// ============================================================================
// Vault Registry & Helpers
// ============================================================================

export interface VaultDeploymentInfo {
  readonly tag: VaultTag;
  readonly address: Address;
  readonly nft: Address;
  readonly tradeRouter: Address | null;
  readonly domainName: 'Crypto Slip Protocol';
  readonly domainVersion: '2' | '3';
}

export const VAULTS: Readonly<Record<VaultTag, VaultDeploymentInfo>> = {
  v2: {
    tag: 'v2',
    address: CANONICAL_VAULT_V2_ADDRESS,
    nft: CANONICAL_NFT_V2_ADDRESS,
    tradeRouter: null,
    domainName: 'Crypto Slip Protocol',
    domainVersion: '2',
  },
  v3: {
    tag: 'v3',
    address: CANONICAL_VAULT_V3_ADDRESS,
    nft: CANONICAL_NFT_V3_ADDRESS,
    tradeRouter: null,
    domainName: 'Crypto Slip Protocol',
    domainVersion: '3',
  },
  v32: {
    tag: 'v32',
    address: CANONICAL_VAULT_V32_ADDRESS,
    nft: CANONICAL_NFT_V32_ADDRESS,
    tradeRouter: CANONICAL_TRADE_ROUTER_V32_ADDRESS,
    domainName: 'Crypto Slip Protocol',
    domainVersion: '3',
  },
  v33: {
    tag: 'v33',
    address: CANONICAL_VAULT_V33_ADDRESS,
    nft: CANONICAL_NFT_V33_ADDRESS,
    tradeRouter: CANONICAL_TRADE_ROUTER_V33_ADDRESS,
    domainName: 'Crypto Slip Protocol',
    domainVersion: '3',
  },
} as const;

export const TRADE_ROUTERS_BY_VAULT: Readonly<Record<'v32' | 'v33', Address>> = {
  v32: CANONICAL_TRADE_ROUTER_V32_ADDRESS,
  v33: CANONICAL_TRADE_ROUTER_V33_ADDRESS,
} as const;

export const isV32ProtocolVault = (vault?: VaultTag | string | null): vault is 'v32' | 'v33' =>
  vault === 'v32' || vault === 'v33';

export const vaultAddress = (tag: VaultTag = ISSUE_VAULT): Address => VAULTS[tag].address;

export const tradeRouterForVault = (tag: VaultTag = ISSUE_VAULT): Address =>
  tag === 'v32' ? CANONICAL_TRADE_ROUTER_V32_ADDRESS : CANONICAL_TRADE_ROUTER_V33_ADDRESS;

export const vaultTagForAddress = (address: string): VaultTag | null => {
  const lower = (address || '').trim().toLowerCase();
  if (lower === CANONICAL_VAULT_V33_ADDRESS.toLowerCase()) return 'v33';
  if (lower === CANONICAL_VAULT_V32_ADDRESS.toLowerCase()) return 'v32';
  if (lower === CANONICAL_VAULT_V3_ADDRESS.toLowerCase()) return 'v3';
  if (lower === CANONICAL_VAULT_V2_ADDRESS.toLowerCase()) return 'v2';
  return null;
};

export const vaultOfRecord = (record?: { vault?: VaultTag } | null): VaultTag =>
  record?.vault === 'v33'
    ? 'v33'
    : record?.vault === 'v32'
      ? 'v32'
      : record?.vault === 'v3'
        ? 'v3'
        : 'v2';

// ============================================================================
// Canonical Base Assets, Micro-Minimums & Referral Binding Thresholds
// ============================================================================

export const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000' as const satisfies Address;
export const NATIVE_ETH_ADDRESS = ZERO_ADDRESS;
export const USDC_BASE_ADDRESS = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' as const satisfies Address;
export const CBBTC_BASE_ADDRESS = '0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf' as const satisfies Address;
export const NARA_BASE_ADDRESS = '0x91FB78A9F46B67f54BbD4489941d19666b2fAe0f' as const satisfies Address;
export const WETH_BASE_ADDRESS = '0x4200000000000000000000000000000000000006' as const satisfies Address;

export interface AssetMetadata {
  readonly symbol: SdkAssetSymbol;
  readonly linkAsset: SupportedLinkAsset;
  readonly address: Address;
  readonly decimals: number;
  readonly minSlipAmountV33: bigint;
  readonly minSlipAmountV32: bigint;
  readonly referralBindMinAmountV33: bigint;
  readonly humanMinimumV33: string;
}

export const ASSETS: Readonly<Record<SdkAssetSymbol, AssetMetadata>> = {
  USDC: {
    symbol: 'USDC',
    linkAsset: 'USDC',
    address: USDC_BASE_ADDRESS,
    decimals: 6,
    minSlipAmountV33: 100_000n,
    minSlipAmountV32: 100_000n,
    referralBindMinAmountV33: 100_000n,
    humanMinimumV33: '0.10 USDC',
  },
  cbBTC: {
    symbol: 'cbBTC',
    linkAsset: 'BTC',
    address: CBBTC_BASE_ADDRESS,
    decimals: 8,
    minSlipAmountV33: 100n,
    minSlipAmountV32: 1_000n,
    referralBindMinAmountV33: 100n,
    humanMinimumV33: '100 sats',
  },
  ETH: {
    symbol: 'ETH',
    linkAsset: 'ETH',
    address: NATIVE_ETH_ADDRESS,
    decimals: 18,
    minSlipAmountV33: 1_000_000_000_000n,
    minSlipAmountV32: 100_000_000_000_000n,
    referralBindMinAmountV33: 1_000_000_000_000n,
    humanMinimumV33: '0.000001 ETH',
  },
  NARA: {
    symbol: 'NARA',
    linkAsset: 'NARA',
    address: NARA_BASE_ADDRESS,
    decimals: 18,
    minSlipAmountV33: 1_000_000_000_000n,
    minSlipAmountV32: 1_000_000_000_000_000n,
    referralBindMinAmountV33: 1_000_000_000_000n,
    humanMinimumV33: '0.000001 NARA',
  },
} as const;

/** Exact `v33` micro-minimums matching `shared/slip-minimums.json` and `CryptoSlipProtocolV32.sol:1269`. */
export const V33_MICRO_MINIMUMS: Readonly<Record<SdkAssetSymbol, bigint>> = {
  USDC: 100_000n,
  cbBTC: 100n,
  ETH: 1_000_000_000_000n,
  NARA: 1_000_000_000_000n,
} as const;

/** Exact `_canBindReferrer` minimums on `v33` (`CryptoSlipProtocolV32.sol:1401-1409`). */
export const REFERRAL_BIND_MINIMUMS_V33: Readonly<Record<SdkAssetSymbol, bigint>> = {
  USDC: 100_000n,
  cbBTC: 100n,
  ETH: 1_000_000_000_000n,
  NARA: 1_000_000_000_000n,
} as const;

export function normalizeSdkAsset(asset: AnyAssetSymbol | string): SdkAssetSymbol {
  const upper = String(asset || '').trim().toUpperCase();
  if (upper === 'USDC') return 'USDC';
  if (upper === 'CBBTC' || upper === 'BTC') return 'cbBTC';
  if (upper === 'ETH') return 'ETH';
  if (upper === 'NARA') return 'NARA';
  throw new Error(`Unsupported CryptoSLIP asset: ${String(asset)}`);
}

export function toLinkAsset(asset: AnyAssetSymbol | string): SupportedLinkAsset {
  const sym = normalizeSdkAsset(asset);
  return sym === 'cbBTC' ? 'BTC' : sym;
}

export function resolveAssetMetadata(assetOrAddress: AnyAssetSymbol | string): AssetMetadata {
  const raw = String(assetOrAddress || '').trim();
  if (/^0x[0-9a-fA-F]{40}$/.test(raw)) {
    const lower = raw.toLowerCase();
    if (lower === NATIVE_ETH_ADDRESS) return ASSETS.ETH;
    if (lower === USDC_BASE_ADDRESS.toLowerCase()) return ASSETS.USDC;
    if (lower === CBBTC_BASE_ADDRESS.toLowerCase()) return ASSETS.cbBTC;
    if (lower === NARA_BASE_ADDRESS.toLowerCase()) return ASSETS.NARA;
    throw new Error(`Unsupported CryptoSLIP asset address: ${raw}`);
  }
  return ASSETS[normalizeSdkAsset(raw)];
}

export function assetAddress(asset: AnyAssetSymbol | string): Address {
  return resolveAssetMetadata(asset).address;
}

export function decimalsForAsset(asset: AnyAssetSymbol | string): number {
  return resolveAssetMetadata(asset).decimals;
}

/**
 * Computes `minSlipAmount` matching `CryptoSlipProtocolV32.sol:1269-1273` (`v33` micro-minimums,
 * or preserved `v32` initial floors when `vault === 'v32'`).
 */
export function minSlipAmount(
  assetOrAddress: AnyAssetSymbol | string,
  vault: VaultTag = ISSUE_VAULT,
): bigint {
  const meta = resolveAssetMetadata(assetOrAddress);
  return vault === 'v32' ? meta.minSlipAmountV32 : meta.minSlipAmountV33;
}

/**
 * Pure bucket helper matching `CryptoSlipProtocolV32.sol:1269-1273` for arbitrary ERC-20 decimals.
 */
export function minSlipAmountByDecimals(decimals: number, isNativeEth = false): bigint {
  if (isNativeEth) return 1_000_000_000_000n;
  if (decimals <= 6) return 100_000n;
  if (decimals <= 8) return 100n;
  return 1_000_000_000_000n;
}

/**
 * Mirrors `_canBindReferrer` + `cashWithPermit`/`acceptWithPermit` referral preconditions
 * (`CryptoSlipProtocolV32.sol:578-584, 986-992, 1401-1409`).
 */
export function canBindReferrerOnV33(params: {
  caller: Address | string;
  creator: Address | string;
  claimSignerAtClaim: Address | string;
  recipient: Address | string;
  assetOrAddress: AnyAssetSymbol | string;
  amount: bigint;
  refundFeeRequiredAtMint?: boolean;
}): boolean {
  const caller = params.caller.toLowerCase();
  const creator = params.creator.toLowerCase();
  const claimSigner = params.claimSignerAtClaim.toLowerCase();
  const recipient = params.recipient.toLowerCase();
  if (
    creator === ZERO_ADDRESS ||
    recipient === ZERO_ADDRESS ||
    creator === claimSigner ||
    caller === creator ||
    creator === recipient ||
    creator === TREASURY_SAFE_ADDRESS.toLowerCase() ||
    recipient === TREASURY_SAFE_ADDRESS.toLowerCase() ||
    Boolean(params.refundFeeRequiredAtMint)
  ) {
    return false;
  }
  const meta = resolveAssetMetadata(params.assetOrAddress);
  return params.amount >= meta.referralBindMinAmountV33;
}

// ============================================================================
// Lifecycle Enums, Lock Sentinels & Fee Math (`CryptoSlipProtocolV32.sol:293, 1658`)
// ============================================================================

export const SlipStatus = {
  NONE: 0,
  ACTIVE: 1,
  CASHED: 2,
  REVOKED: 3,
  SPLIT: 4,
} as const;
export type SlipStatusCode = (typeof SlipStatus)[keyof typeof SlipStatus];

export const FEE_BPS = 50n;
export const BPS_DENOMINATOR = 10_000n;
export const REFERRAL_FEE_SPLIT_BPS = 25n;

/** Permanent V3.2 `No take-back` lock sentinel (`9_999_999_999` = Nov 20, 2286 UTC). */
export const NO_TAKE_BACK_LOCK = 9_999_999_999n;
export const OFFGRID_PERMANENT_LOCK_UNTIL = 9_999_999_999;

export const MAX_COMBINE_SLIPS = 10;
export const MAX_RELAYER_BOUNTY_WEI = 1_000_000_000_000_000n; // 0.001 ether
export const VOICE_MIN_USD_MICRO = 1_000_000n; // $1.00 floor for burn-on-play voice notes
export const MIN_CIRCLE_PAYMASTER_USDC_UNITS = 100_000n; // $0.10 USDC
export const MAX_CIRCLE_PAYMASTER_PERMIT_UNITS = 1_000_000n; // $1.00 USDC cap

/**
 * Exact ceiling fee matching `CryptoSlipProtocolV32._fee(grossAmount)` (`L293, L1658`):
 * `(grossAmount * 50n + 9999n) / 10000n`.
 */
export function computeProtocolFeeCeiling(grossAmount: bigint): bigint {
  if (grossAmount < 0n) {
    throw new RangeError('grossAmount must be non-negative');
  }
  if (grossAmount === 0n) return 0n;
  return (grossAmount * FEE_BPS + (BPS_DENOMINATOR - 1n)) / BPS_DENOMINATOR;
}

/**
 * Exact net payout after deducting `computeProtocolFeeCeiling(grossAmount)`.
 */
export function deductProtocolFeeCeiling(grossAmount: bigint): bigint {
  const fee = computeProtocolFeeCeiling(grossAmount);
  return grossAmount > fee ? grossAmount - fee : 0n;
}

/**
 * Exact 50/50 fee split between treasury (`protocolFee`) and `referrer` (`referralFee`),
 * matching `CryptoSlipProtocolV32._accrueFeeWithReferral` (`L1671-1684`).
 */
export function computeFeeAndReferralSplit(
  grossAmount: bigint,
  hasValidReferrer: boolean,
): { totalFee: bigint; protocolFee: bigint; referralFee: bigint; netAmount: bigint } {
  const totalFee = computeProtocolFeeCeiling(grossAmount);
  const referralFee = hasValidReferrer ? totalFee / 2n : 0n;
  const protocolFee = totalFee - referralFee;
  const netAmount = grossAmount > totalFee ? grossAmount - totalFee : 0n;
  return { totalFee, protocolFee, referralFee, netAmount };
}

/**
 * Smallest `gross` amount such that `gross - computeProtocolFeeCeiling(gross) >= targetNet`.
 * Byte-for-byte mathematical parity with `invertSlipSettlementFeeFloorWei` (`naraDexRouter.ts:1863`)
 * and `invertVaultFeeForNetUnits` (`paymentPlanner.ts:78`).
 */
export function grossUpForExactNet(targetNet: bigint): bigint {
  if (targetNet < 0n) {
    throw new RangeError('targetNet must be non-negative');
  }
  if (targetNet === 0n) return 0n;
  let gross = (targetNet * BPS_DENOMINATOR + 9_949n) / (BPS_DENOMINATOR - FEE_BPS);
  while (gross - computeProtocolFeeCeiling(gross) < targetNet) {
    gross += 1n;
  }
  return gross;
}

export const invertSlipSettlementFeeFloorWei = grossUpForExactNet;

// ============================================================================
// ERC-8021 Base Builder Code Attribution (`client/src/lib/erc8021.ts` Parity)
// ============================================================================

export const ERC8021_MARKER_HEX = '80218021802180218021802180218021' as const;
export const DEFAULT_CRYPTOSLIP_BUILDER_CODE = 'bc_ea68lz8s' as const;
export const DEFAULT_NARA_BUILDER_CODE = 'bc_g71jff6u' as const;
export const NARA_IN_APP_BUILDER_CODES = [
  DEFAULT_CRYPTOSLIP_BUILDER_CODE,
  DEFAULT_NARA_BUILDER_CODE,
] as const;

const VALID_BUILDER_CODE_RE = /^[A-Za-z0-9_.-]{1,64}$/;

const NARA_DUAL_ATTRIBUTION_TARGETS = new Set<string>([
  '0x91fb78a9f46b67f54bbd4489941d19666b2fae0f', // NARATokenV5
  '0xd93fbebfb33fac9288125074625d4750573b1a53', // NARAEpochEngineV5
  '0x7f866a9fbe41d54f0d9c35b6892fcf27ea766db2', // NARAPrincipalLedgerV5
  '0xc72671d9438388638547444524f6542b650c9264', // NARARewardLedgerV5
  '0x8c5f088d9d09dbb90ab6f3aaa049a8fd5d5fffda', // NARAPositionNFTV5
  '0x04ac83045d26259d46400ce6beb9bbd0641df225', // NARAPositionSaleV5
  '0x6ff5693b99212da76ad316178a184ab56d299b43', // Uniswap UniversalRouter
  '0x2069ca17d45d3421d28f15f20262575333cecf51', // CryptoSlipTradeRouterV32 (v33)
  '0x295e72cb3dc09582f32e0feb7e0e650752219a7f', // CryptoSlipTradeRouterV32 (v32)
]);

const SWAP_ROUTER_TARGETS = new Set<string>([
  '0x6ff5693b99212da76ad316178a184ab56d299b43',
  '0x2069ca17d45d3421d28f15f20262575333cecf51',
  '0x295e72cb3dc09582f32e0feb7e0e650752219a7f',
]);

const PERSONAL_ERC20_SELECTORS = new Set<string>([
  '0xa9059cbb', // transfer(address,uint256)
  '0x095ea7b3', // approve(address,uint256)
  '0xe3ee160e', // transferWithAuthorization(...,bytes)
  '0xcf092995', // transferWithAuthorization(...,uint8,bytes32,bytes32)
]);

const NARA_TOKEN_ADDR_HEX_NO_PREFIX = '91fb78a9f46b67f54bbd4489941d19666b2fae0f';

export function normalizeBuilderCodes(
  input: string | readonly string[] | null | undefined,
): string[] {
  if (!input) return [];
  const rawList = Array.isArray(input) ? input : String(input).split(',');
  const seen = new Set<string>();
  const out: string[] = [];
  for (const item of rawList) {
    const code = String(item ?? '').trim();
    if (!code || !VALID_BUILDER_CODE_RE.test(code) || seen.has(code)) continue;
    seen.add(code);
    out.push(code);
  }
  return out;
}

/**
 * Encodes ERC-8021 Schema 0 attribution suffix (`codesHex || codesLength(1B) || 0x00 || 8021*8`).
 * Byte-for-byte identical to `client/src/lib/erc8021.ts:toErc8021DataSuffix`.
 */
export function toErc8021DataSuffix(
  codesInput: string | readonly string[] | null | undefined = DEFAULT_CRYPTOSLIP_BUILDER_CODE,
): Hex | '' {
  const codes = normalizeBuilderCodes(codesInput);
  if (codes.length === 0) return '';

  const joined = codes.join(',');
  if (joined.length > 255) return '';

  let codesHex = '';
  for (let i = 0; i < joined.length; i++) {
    codesHex += joined.charCodeAt(i).toString(16).padStart(2, '0');
  }
  const codesLenHex = joined.length.toString(16).padStart(2, '0');
  return `0x${codesHex}${codesLenHex}00${ERC8021_MARKER_HEX}`;
}

/**
 * Appends the ERC-8021 Base Builder Code suffix (`bc_ea68lz8s` by default) to contract calldata.
 * Never mutates empty `0x` native ETH transfers (`allowEmptyCalldata` defaults to `true` for
 * direct parity with `client/src/lib/erc8021.ts:appendErc8021DataSuffix`, while callers sending
 * raw tx requests can check `data.length >= 10`). Idempotent when suffix is already present.
 */
export function appendBuilderCodeSuffix(
  data: Hex | string,
  codesInput: string | readonly string[] | null | undefined = DEFAULT_CRYPTOSLIP_BUILDER_CODE,
): Hex {
  if (typeof data !== 'string' || !/^0x(?:[0-9a-fA-F]{2})*$/.test(data)) {
    throw new Error('appendBuilderCodeSuffix requires even-length 0x-prefixed hex calldata');
  }
  if (data.toLowerCase().endsWith(ERC8021_MARKER_HEX)) {
    return data as Hex;
  }
  const suffix = toErc8021DataSuffix(codesInput);
  if (!suffix) return data as Hex;
  return `${data}${suffix.slice(2)}` as Hex;
}

/** Exact string-preserving alias matching `client/src/lib/erc8021.ts:appendErc8021DataSuffix`. */
export function appendErc8021DataSuffix(
  data: string,
  codesInput: string | readonly string[] | null | undefined = DEFAULT_CRYPTOSLIP_BUILDER_CODE,
): string {
  if (typeof data !== 'string' || !/^0x(?:[0-9a-fA-F]{2})*$/.test(data)) {
    return data;
  }
  if (data.toLowerCase().endsWith(ERC8021_MARKER_HEX)) {
    return data;
  }
  const suffix = toErc8021DataSuffix(codesInput);
  if (!suffix) return data;
  return `${data}${suffix.slice(2)}`;
}

export function isNaraDualAttributionTarget(to: string | null | undefined, data?: string): boolean {
  if (typeof to !== 'string') return false;
  const lower = to.toLowerCase();
  if (!NARA_DUAL_ATTRIBUTION_TARGETS.has(lower)) return false;
  if (typeof data === 'string' && data.length >= 10) {
    const selector = data.slice(0, 10).toLowerCase();
    if (PERSONAL_ERC20_SELECTORS.has(selector)) return false;
  }
  if (SWAP_ROUTER_TARGETS.has(lower) && typeof data === 'string') {
    return data.toLowerCase().includes(NARA_TOKEN_ADDR_HEX_NO_PREFIX);
  }
  return true;
}

// ============================================================================
// Blocked Payment & Signer Destinations (`onChainService.ts:4545-4568` Parity)
// ============================================================================

export const BLOCKED_PAYMENT_TARGETS: ReadonlySet<string> = new Set<string>([
  ZERO_ADDRESS,
  '0x000000000000000000000000000000000000dead',
  USDC_BASE_ADDRESS.toLowerCase(),
  CBBTC_BASE_ADDRESS.toLowerCase(),
  NARA_BASE_ADDRESS.toLowerCase(),
  WETH_BASE_ADDRESS.toLowerCase(),
  CANONICAL_VAULT_V33_ADDRESS.toLowerCase(),
  CANONICAL_NFT_V33_ADDRESS.toLowerCase(),
  CANONICAL_TRADE_ROUTER_V33_ADDRESS.toLowerCase(),
  CANONICAL_VAULT_V32_ADDRESS.toLowerCase(),
  CANONICAL_NFT_V32_ADDRESS.toLowerCase(),
  CANONICAL_TRADE_ROUTER_V32_ADDRESS.toLowerCase(),
  CANONICAL_VAULT_V3_ADDRESS.toLowerCase(),
  CANONICAL_NFT_V3_ADDRESS.toLowerCase(),
  CANONICAL_VAULT_V2_ADDRESS.toLowerCase(),
  CANONICAL_NFT_V2_ADDRESS.toLowerCase(),
  '0x5f3a378b685e309ae7404a7483420e49f2fbe6aa',
  '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266',
  '0x70997970c51812dc3a010c7d01b50e0d17dc79c8',
  '0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc',
]);
