import {
  decodeAbiParameters,
  decodeFunctionData,
  getAddress,
  isAddress,
  parseAbi,
  parseAbiParameters,
  zeroAddress,
  type Address,
  type Hex,
} from 'viem';
import { BLOCKED_PAYMENT_TARGETS } from './constants.js';

export { BLOCKED_PAYMENT_TARGETS } from './constants.js';

export type PolicyAssetSymbol = 'USDC' | 'cbBTC' | 'BTC' | 'ETH' | 'NARA';

export type PolicyErrorCode =
  | 'SPEND_CAP_EXCEEDED'
  | 'DAILY_CAP_EXCEEDED'
  | 'RATE_LIMIT_EXCEEDED'
  | 'INVALID_DESTINATION'
  | 'BLOCKED_DESTINATION'
  | 'RECIPIENT_NOT_ALLOWLISTED'
  | 'DOMAIN_NOT_ALLOWLISTED'
  | 'FORBIDDEN_SWAP_ROUTE'
  | 'UNTRUSTED_PERMIT_SPENDER'
  | 'OUTBOUND_SLIP_LINK_DISABLED'
  | 'RAW_SIGNING_BLOCKED';

export class PolicyViolationError extends Error {
  readonly code: PolicyErrorCode;

  constructor(code: PolicyErrorCode, message: string) {
    super(message);
    this.name = 'PolicyViolationError';
    this.code = code;
  }
}

export const POLICY_TOKEN_ADDRESSES = {
  USDC: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  cbBTC: '0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf',
  NARA: '0x91FB78A9F46B67f54BbD4489941d19666b2fAe0f',
  WETH: '0x4200000000000000000000000000000000000006',
} as const satisfies Record<string, Address>;

export const POLICY_CANONICAL_CONTRACTS = {
  vaultV33: '0x3f80aa68Fb4834d6E119EE1cf932C14419Cf63EB',
  nftV33: '0x356a701DABDeabe61F7Fc79D730617CEcbd7B94f',
  tradeRouterV33: '0x2069CA17D45d3421D28f15F20262575333CECF51',
  vaultV32: '0x38BF0321FA7489576978353a6a8da4A3e85C2F18',
  nftV32: '0x36181Ca1B0210b6Ea8E56755dA7B06c34ba481C0',
  tradeRouterV32: '0x295E72cB3dc09582F32e0fEB7e0e650752219a7f',
  vaultV3: '0x4Dc2b5A801A81b17b8d05C737c727FEd1f30699A',
  nftV3: '0x7e6dc2579596aeB994cb3774D804b54fFc20CF79',
  vaultV2: '0x87aadDF2d3aa11Cddf36939715508066a99BA415',
  nftV2: '0x0B76801738e922Be7EDf397A6434837aF431E159',
  naraLiquidityHookV5: '0x07d8F2Dfd121B10dE3176DeAb6A8C0eaa2646aCC',
  universalRouter: '0x6fF5693b99212Da76ad316178A184AB56D299b43',
  tokenPaymasterV08: '0x0578cFB241215b77442a541325d6A4E6dFE700Ec',
  entryPointV08: '0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108',
  simple7702Account: '0xe6Cae83BdE06E4c305530e199D7217f42808555B',
  multicall3: '0xcA11bde05977b3631167028862bE2a173976CA11',
  permit2: '0x000000000022D473030F116dDEE9F6B43aC78BA3',
  poolManagerV4: '0x498581fF718922c3f8e6A244956aF099B2652b2b',
} as const satisfies Record<string, Address>;

const SECONDARY_V3_NARA_POOL_LOWER = '0xeed718d239c5508775e312f60eb12792a49d4bba';
const RETIRED_NARA_V4_HOOK_LOWER = '0x59aef9799dea01a7fb7da73bea10dfb08858a088';

const ALLOWED_SWAP_ROUTERS_NON_NARA = new Set<string>([
  POLICY_CANONICAL_CONTRACTS.universalRouter.toLowerCase(),
  '0x2626664c2603336e57b271c5c0b26f421741e481', // Uniswap V3 SwapRouter02 (ETH/cbBTC <-> USDC only)
  '0x6131b5fae19ea4f9d964eac0408e4408b66337b5', // KyberSwap (non-NARA bridge leg only)
  '0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae', // LI.FI Diamond (non-NARA bridge leg only)
]);

const TRUSTED_V32_VAULTS_LOWER = new Set<string>([
  POLICY_CANONICAL_CONTRACTS.vaultV33.toLowerCase(),
  POLICY_CANONICAL_CONTRACTS.vaultV32.toLowerCase(),
]);

const TRUSTED_PERMIT_SPENDERS_LOWER = new Set<string>([
  POLICY_CANONICAL_CONTRACTS.vaultV33.toLowerCase(),
  POLICY_CANONICAL_CONTRACTS.vaultV32.toLowerCase(),
  POLICY_CANONICAL_CONTRACTS.tokenPaymasterV08.toLowerCase(),
]);

/**
 * Extended policy denylist combining `BLOCKED_PAYMENT_TARGETS` (`constants.ts`) with
 * DEX routers, AA entrypoints, NARA V5 core contracts, and public low-entropy keys (`V-02`).
 */
export const POLICY_BLOCKED_DESTINATIONS: ReadonlySet<string> = new Set([
  ...BLOCKED_PAYMENT_TARGETS,
  ...[
    zeroAddress,
    '0x000000000000000000000000000000000000dEaD',
    '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE',
    '0x3232323232323232323232323232323232323232',
    '0x7213232323232323232323232323232323232323',
    '0x1111111111111111111111111111111111111132',
    POLICY_CANONICAL_CONTRACTS.naraLiquidityHookV5,
    POLICY_CANONICAL_CONTRACTS.universalRouter,
    POLICY_CANONICAL_CONTRACTS.tokenPaymasterV08,
    POLICY_CANONICAL_CONTRACTS.entryPointV08,
    POLICY_CANONICAL_CONTRACTS.simple7702Account,
    POLICY_CANONICAL_CONTRACTS.multicall3,
    POLICY_CANONICAL_CONTRACTS.permit2,
    POLICY_CANONICAL_CONTRACTS.poolManagerV4,
    '0xd93FbEbFb33FAc9288125074625D4750573B1a53', // NARAEngineModularV5
    '0xf932178F24b0813C82093985F0Af6Db27Ae25930', // NARAReserveV5
    '0x7F866a9fbe41D54F0d9C35b6892fcf27Ea766DB2', // NARAPrincipalLedgerV5
    '0xC72671D9438388638547444524F6542b650C9264', // NARARewardLedgerV5
    '0x8C5F088D9d09dBB90aB6F3aaA049a8FD5D5FfFDA', // NARAPositionNFTV5
    '0x04Ac83045d26259D46400Ce6beb9bBd0641df225', // NARAPositionSaleV5
    '0x201fBD2839bEc513040024b37dAe97B401E96acC', // NARALiquidityHookV5 (prior)
    '0xF1f361F803895BF5cf67eC6C506dbFEf2f6E88Cf', // NARAFeeVaultV5
    '0xBCF29E9E37E62FBB996D5FF890FEd5280fC02e1A', // NARAPoolOracleV5
    '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf', // public key 0x01
    '0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF', // public key 0x02
    '0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69', // public key 0x03
  ].map((addr) => addr.toLowerCase()),
]);

/** Default USD-micro (6-decimal) reference valuations matching `shared/relayCore.mjs`. */
export const DEFAULT_ASSET_PRICES_USD_MICRO = {
  USDC: 1_000_000n,
  cbBTC: 50_000_000_000n,
  BTC: 50_000_000_000n,
  ETH: 2_500_000_000n,
  NARA: 1_000_000n,
} as const satisfies Record<PolicyAssetSymbol, bigint>;

const ASSET_DECIMALS: Record<PolicyAssetSymbol, bigint> = {
  USDC: 6n,
  cbBTC: 8n,
  BTC: 8n,
  ETH: 18n,
  NARA: 18n,
};

const BIDI_OR_INVISIBLE_RE = /[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/;

export type DestinationCheckResult =
  | { ok: true; address: Address }
  | { ok: false; error: string; code: PolicyErrorCode };

export interface AssertSafeDestinationOptions {
  ownAddress?: string;
  extraBlockedAddresses?: readonly string[];
}

/**
 * Non-throwing destination check matching `client/src/components/Modals/withdrawHelpers.ts`
 * and `client/src/lib/onChainService.ts`.
 */
export function checkDestination(
  raw: string,
  options?: AssertSafeDestinationOptions,
): DestinationCheckResult {
  if (typeof raw !== 'string' || BIDI_OR_INVISIBLE_RE.test(raw)) {
    return {
      ok: false,
      code: 'INVALID_DESTINATION',
      error: 'Destination address contains hidden or invalid characters.',
    };
  }
  const value = raw.replace(/\s+/g, '');
  if (!value) {
    return {
      ok: false,
      code: 'INVALID_DESTINATION',
      error: 'Destination wallet address is required.',
    };
  }
  if (/\.eth$/i.test(value)) {
    return {
      ok: false,
      code: 'INVALID_DESTINATION',
      error: 'Unresolved ENS names are not accepted; pass a 42-character 0x address.',
    };
  }
  if (!/^0x[0-9a-fA-F]{40}$/.test(value) || !isAddress(value)) {
    return {
      ok: false,
      code: 'INVALID_DESTINATION',
      error: 'Invalid Base wallet address or EIP-55 checksum mismatch.',
    };
  }
  const checksummed = getAddress(value);
  const lower = checksummed.toLowerCase();
  if (lower === zeroAddress) {
    return {
      ok: false,
      code: 'BLOCKED_DESTINATION',
      error: 'Zero address cannot receive funds.',
    };
  }
  if (options?.ownAddress && isAddress(options.ownAddress)) {
    if (getAddress(options.ownAddress).toLowerCase() === lower) {
      return {
        ok: false,
        code: 'BLOCKED_DESTINATION',
        error: 'Destination matches the sender wallet address.',
      };
    }
  }
  if (POLICY_BLOCKED_DESTINATIONS.has(lower)) {
    return {
      ok: false,
      code: 'BLOCKED_DESTINATION',
      error: `Destination ${checksummed} is a blocked protocol contract, burn address, or compromised public key.`,
    };
  }
  if (options?.extraBlockedAddresses) {
    for (const extra of options.extraBlockedAddresses) {
      if (extra && extra.toLowerCase() === lower) {
        return {
          ok: false,
          code: 'BLOCKED_DESTINATION',
          error: `Destination ${checksummed} is blocked by policy.`,
        };
      }
    }
  }
  return { ok: true, address: checksummed };
}

/**
 * Throws `PolicyViolationError` if `to` is malformed, zero/dead, a token/vault/router contract,
 * or a publicly known test key. Returns checksummed `Address` when safe.
 */
export function assertSafeDestination(
  to: string,
  options?: AssertSafeDestinationOptions,
): Address {
  const res = checkDestination(to, options);
  if (!res.ok) {
    throw new PolicyViolationError(res.code, res.error);
  }
  return res.address;
}

export function resolvePolicyAsset(assetOrAddress?: string | null): PolicyAssetSymbol {
  if (!assetOrAddress) return 'USDC';
  const trimmed = assetOrAddress.trim();
  const upper = trimmed.toUpperCase();
  if (upper === 'USDC') return 'USDC';
  if (upper === 'CBBTC' || upper === 'BTC') return 'cbBTC';
  if (upper === 'ETH') return 'ETH';
  if (upper === 'NARA') return 'NARA';

  const lower = trimmed.toLowerCase();
  if (lower === zeroAddress || lower === '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee') {
    return 'ETH';
  }
  if (lower === POLICY_TOKEN_ADDRESSES.cbBTC.toLowerCase()) return 'cbBTC';
  if (lower === POLICY_TOKEN_ADDRESSES.NARA.toLowerCase()) return 'NARA';
  return 'USDC';
}

/**
 * Converts a raw token unit amount into 6-decimal micro-USD using ceiling division
 * so sub-micro fractions never round down to 0 and bypass spend caps.
 */
export function estimateUsdMicro(
  amount: bigint,
  asset: PolicyAssetSymbol | string = 'USDC',
  priceOverridesUsdMicro?: Partial<Record<PolicyAssetSymbol, bigint>>,
): bigint {
  if (amount <= 0n) return 0n;
  const symbol = resolvePolicyAsset(asset);
  const price =
    priceOverridesUsdMicro?.[symbol] ??
    (symbol === 'cbBTC' ? priceOverridesUsdMicro?.BTC : undefined) ??
    DEFAULT_ASSET_PRICES_USD_MICRO[symbol];
  const scale = 10n ** ASSET_DECIMALS[symbol];
  return (amount * price + scale - 1n) / scale;
}

const UNIVERSAL_ROUTER_ABI = parseAbi([
  'function execute(bytes commands, bytes[] inputs, uint256 deadline)',
  'function execute(bytes commands, bytes[] inputs)',
]);

const V4_SWAP_INPUT_PARAMS = parseAbiParameters('bytes actions, bytes[] params');
const V4_EXACT_IN_SINGLE_PARAMS = parseAbiParameters(
  '((address currency0, address currency1, uint24 fee, int24 tickSpacing, address hooks) poolKey, bool zeroForOne, uint128 amountIn, uint128 amountOutMinimum, bytes hookData)',
);
const V3_SWAP_INPUT_PARAMS = parseAbiParameters(
  'address recipient, uint256 amountIn, uint256 amountOutMin, bytes path, bool payerIsUser',
);

const ALLOWED_UR_COMMANDS = new Set([0x00, 0x04, 0x0b, 0x0c, 0x10]);
const ALLOWED_V4_ACTIONS = new Set([0x06, 0x0b, 0x0c, 0x0e, 0x0f]);

export interface SwapPolicyCheckInput {
  inAsset?: string;
  outAsset?: string;
  midAsset?: string;
  swapTarget: string;
  swapData?: Hex;
}

/**
 * Hard Invariant #1 (`V-02`): Enforces that any swap touching `NARA` routes 100% exclusively
 * through canonical Uniswap `UniversalRouter` + `NARALiquidityHookV5` (`0x07d8F2Dfd121B10dE3176DeAb6A8C0eaa2646aCC`),
 * rejecting secondary Uniswap V3 (`0xEEd718...`), retired hooks, Aerodrome, or external aggregators.
 */
export function assertCanonicalNaraSwapPolicy(input: SwapPolicyCheckInput): void {
  if (!input.swapTarget || !isAddress(input.swapTarget)) {
    throw new PolicyViolationError('FORBIDDEN_SWAP_ROUTE', 'Invalid swapTarget address.');
  }
  const targetLower = input.swapTarget.toLowerCase();
  const naraAddressLower = POLICY_TOKEN_ADDRESSES.NARA.toLowerCase();
  const naraHexNoPrefix = naraAddressLower.slice(2);
  const usdcLower = POLICY_TOKEN_ADDRESSES.USDC.toLowerCase();
  const expectedHookLower = POLICY_CANONICAL_CONTRACTS.naraLiquidityHookV5.toLowerCase();

  const assetTouchesNara = [input.inAsset, input.outAsset, input.midAsset].some(
    (a) => a !== undefined && resolvePolicyAsset(a) === 'NARA',
  );
  const dataLower = input.swapData?.toLowerCase() ?? '';
  const calldataTouchesNara = dataLower.includes(naraHexNoPrefix);
  const touchesNara = assetTouchesNara || calldataTouchesNara;

  if (!ALLOWED_SWAP_ROUTERS_NON_NARA.has(targetLower)) {
    throw new PolicyViolationError(
      'FORBIDDEN_SWAP_ROUTE',
      `Swap router ${input.swapTarget} is not on the canonical router allowlist.`,
    );
  }

  if (
    dataLower.includes(SECONDARY_V3_NARA_POOL_LOWER.slice(2)) ||
    dataLower.includes(RETIRED_NARA_V4_HOOK_LOWER.slice(2))
  ) {
    throw new PolicyViolationError(
      'FORBIDDEN_SWAP_ROUTE',
      'Secondary Uniswap V3 NARA pool and retired V4 hooks are permanently forbidden.',
    );
  }

  if (!touchesNara) {
    return;
  }

  if (targetLower !== POLICY_CANONICAL_CONTRACTS.universalRouter.toLowerCase()) {
    throw new PolicyViolationError(
      'FORBIDDEN_SWAP_ROUTE',
      'NARA swaps must target canonical Uniswap UniversalRouter exclusively.',
    );
  }

  if (!input.swapData) {
    return;
  }

  let commandsHex: string;
  let commandInputs: readonly Hex[];
  try {
    const decoded = decodeFunctionData({
      abi: UNIVERSAL_ROUTER_ABI,
      data: input.swapData,
    });
    if (decoded.functionName !== 'execute') {
      throw new Error('Unexpected selector');
    }
    commandsHex = decoded.args[0].slice(2).toLowerCase();
    commandInputs = decoded.args[1];
  } catch {
    throw new PolicyViolationError(
      'FORBIDDEN_SWAP_ROUTE',
      'NARA swapData must be valid UniversalRouter.execute calldata.',
    );
  }

  if (!commandsHex || commandsHex.length % 2 !== 0 || commandInputs.length !== commandsHex.length / 2) {
    throw new PolicyViolationError(
      'FORBIDDEN_SWAP_ROUTE',
      'Malformed UniversalRouter commands/inputs length in NARA swapData.',
    );
  }

  let verifiedCanonicalV4Hook = false;

  for (let i = 0; i < commandsHex.length; i += 2) {
    const rawCmd = Number.parseInt(commandsHex.slice(i, i + 2), 16);
    if ((rawCmd & 0x80) !== 0) {
      throw new PolicyViolationError(
        'FORBIDDEN_SWAP_ROUTE',
        'UniversalRouter FLAG_ALLOW_REVERT is forbidden on NARA swaps.',
      );
    }
    const cmd = rawCmd & 0x3f;
    if (!ALLOWED_UR_COMMANDS.has(cmd)) {
      throw new PolicyViolationError(
        'FORBIDDEN_SWAP_ROUTE',
        `Disallowed UniversalRouter command 0x${cmd.toString(16)} in NARA swapData.`,
      );
    }
    const cmdInput = commandInputs[i / 2];
    if (!cmdInput) {
      throw new PolicyViolationError('FORBIDDEN_SWAP_ROUTE', 'Missing UniversalRouter command input.');
    }

    if (cmd === 0x00) {
      let pathHex: Hex;
      try {
        const [, , , path] = decodeAbiParameters(V3_SWAP_INPUT_PARAMS, cmdInput);
        pathHex = path;
      } catch {
        throw new PolicyViolationError('FORBIDDEN_SWAP_ROUTE', 'Invalid V3 bridge leg in UniversalRouter calldata.');
      }
      if (
        pathHex.toLowerCase().includes(naraHexNoPrefix) ||
        cmdInput.toLowerCase().includes(naraHexNoPrefix)
      ) {
        throw new PolicyViolationError(
          'FORBIDDEN_SWAP_ROUTE',
          'Uniswap V3 NARA routing is strictly forbidden; NARA must use NARALiquidityHookV5.',
        );
      }
    } else if (cmd === 0x10) {
      let actions: Hex;
      let actionParams: readonly Hex[];
      try {
        [actions, actionParams] = decodeAbiParameters(V4_SWAP_INPUT_PARAMS, cmdInput);
      } catch {
        throw new PolicyViolationError('FORBIDDEN_SWAP_ROUTE', 'Invalid V4 swap encoding in swapData.');
      }
      const actionsHex = actions.slice(2).toLowerCase();
      if (actionsHex.length < 4 || actionsHex.length % 2 !== 0) {
        throw new PolicyViolationError('FORBIDDEN_SWAP_ROUTE', 'Invalid V4 action sequence.');
      }
      const actionBytes: number[] = [];
      for (let j = 0; j < actionsHex.length; j += 2) {
        const ab = Number.parseInt(actionsHex.slice(j, j + 2), 16);
        if (!ALLOWED_V4_ACTIONS.has(ab)) {
          throw new PolicyViolationError('FORBIDDEN_SWAP_ROUTE', `Disallowed V4 action 0x${ab.toString(16)}.`);
        }
        actionBytes.push(ab);
      }
      if (actionParams.length !== actionBytes.length) {
        throw new PolicyViolationError('FORBIDDEN_SWAP_ROUTE', 'V4 action params count mismatch.');
      }
      const lastAction = actionBytes[actionBytes.length - 1];
      const hasSubsequentCmd = i + 2 < commandsHex.length;
      if (lastAction !== 0x0f && !(lastAction === 0x0e && hasSubsequentCmd)) {
        throw new PolicyViolationError(
          'FORBIDDEN_SWAP_ROUTE',
          'V4 swap actions must terminate with TAKE_ALL or chained TAKE.',
        );
      }

      let sawExactInSingle = false;
      for (let j = 0; j < actionBytes.length; j++) {
        if (actionBytes[j] === 0x06) {
          const singleParam = actionParams[j];
          if (!singleParam) {
            throw new PolicyViolationError('FORBIDDEN_SWAP_ROUTE', 'Missing V4 swap single param.');
          }
          let single: {
            poolKey: {
              currency0: Address;
              currency1: Address;
              fee: number;
              tickSpacing: number;
              hooks: Address;
            };
          };
          try {
            [single] = decodeAbiParameters(V4_EXACT_IN_SINGLE_PARAMS, singleParam);
          } catch {
            throw new PolicyViolationError('FORBIDDEN_SWAP_ROUTE', 'Malformed V4 SWAP_EXACT_IN_SINGLE params.');
          }
          const pk = single.poolKey;
          if (
            pk.currency0.toLowerCase() !== usdcLower ||
            pk.currency1.toLowerCase() !== naraAddressLower ||
            pk.fee !== 3000 ||
            pk.tickSpacing !== 60 ||
            pk.hooks.toLowerCase() !== expectedHookLower
          ) {
            throw new PolicyViolationError(
              'FORBIDDEN_SWAP_ROUTE',
              'V4 PoolKey must match canonical USDC/NARA pool with NARALiquidityHookV5 (0x07d8F2Dfd121B10dE3176DeAb6A8C0eaa2646aCC).',
            );
          }
          sawExactInSingle = true;
        }
      }
      if (!sawExactInSingle) {
        throw new PolicyViolationError(
          'FORBIDDEN_SWAP_ROUTE',
          'V4 swap must contain SWAP_EXACT_IN_SINGLE on canonical NARALiquidityHookV5.',
        );
      }
      verifiedCanonicalV4Hook = true;
    }
  }

  if (!verifiedCanonicalV4Hook) {
    throw new PolicyViolationError(
      'FORBIDDEN_SWAP_ROUTE',
      'NARA swapData did not execute via canonical NARALiquidityHookV5.',
    );
  }
}

export interface RedactToolOutputOptions {
  /**
   * Set true ONLY for explicit outbound human payout tools (`cryptoslip_pay_human` / `cryptoslip_batch_payout`)
   * when permitted by operator policy, preserving `outboundSlipUrl` / `outboundLinks` while still scrubbing internal keys.
   */
  allowOutboundSlipLink?: boolean;
  /** Property names holding outbound links when `allowOutboundSlipLink` is true. */
  outboundFields?: readonly string[];
  /** Property names holding public on-chain transaction/order digests (`0x` + 64 hex) that are safe to display. */
  allowedPublicHashFields?: readonly string[];
}

const SENSITIVE_FIELD_NAME_RE =
  /^(?:private[_-]?key|secret[_-]?key|claim[_-]?key|ephemeral[_-]?key|local[_-]?key|change[_-]?key|voice[_-]?key|seed|mnemonic|raw[_-]?secret)$/i;

const DEFAULT_OUTBOUND_LINK_FIELDS = new Set([
  'outboundSlipUrl',
  'outboundLinks',
  'outboundCsv',
  'url',
  'sovereignUrl',
]);

const CLAIM_KEY_IN_LINK_RE = /(_k)(?:0x)?[0-9a-fA-F]{64}/g;
const SEALED_PREFIX_IN_LINK_RE = /(_s)[0-9a-fA-F]{48}/g;
const FRAGMENT_SECRET_PARAM_RE = /([&#?])(vk|en|code|seal)=[A-Za-z0-9_-]{4,}/g;
const RAW_64_HEX_RE = /(^|[^0-9a-fA-F])((?:0x)?[0-9a-fA-F]{64})(?![0-9a-fA-F])/g;

function redactStringSecrets(input: string): string {
  return input
    .replace(CLAIM_KEY_IN_LINK_RE, '$1[REDACTED_CLAIM_KEY]')
    .replace(SEALED_PREFIX_IN_LINK_RE, '$1[REDACTED_SEAL]')
    .replace(FRAGMENT_SECRET_PARAM_RE, '$1$2=[REDACTED]')
    .replace(RAW_64_HEX_RE, '$1[REDACTED_SECRET]');
}

/**
 * `V-01` Defense: Recursively strips any `_k<64-hex>`, `_s<48-hex>`, voice/note fragment secret,
 * or raw 64-hex private key material from strings, Errors, Arrays, Maps, Sets, and plain objects
 * before returning tool results to an LLM context window.
 */
export function redactSecretsFromToolOutput<T>(
  value: T,
  options?: RedactToolOutputOptions,
): T {
  const seen = new WeakSet<object>();
  const allowOutbound = Boolean(options?.allowOutboundSlipLink);
  const outboundFields = new Set<string>(
    options?.outboundFields ?? [...DEFAULT_OUTBOUND_LINK_FIELDS],
  );
  const publicHashFields = new Set<string>(options?.allowedPublicHashFields ?? []);

  const visit = (node: unknown, fieldName?: string): unknown => {
    if (node === null || node === undefined) return node;

    if (typeof node === 'string') {
      if (fieldName && SENSITIVE_FIELD_NAME_RE.test(fieldName)) {
        return '[REDACTED_SECRET]';
      }
      if (allowOutbound && fieldName && outboundFields.has(fieldName)) {
        return node;
      }
      if (
        fieldName &&
        publicHashFields.has(fieldName) &&
        /^0x[0-9a-fA-F]{64}$/.test(node)
      ) {
        return node;
      }
      return redactStringSecrets(node);
    }

    if (typeof node === 'bigint' || typeof node === 'number' || typeof node === 'boolean') {
      return node;
    }

    if (typeof node !== 'object') {
      return node;
    }

    if (seen.has(node)) {
      return '[CIRCULAR]';
    }
    seen.add(node);

    if (node instanceof Error) {
      const cleanErr = new Error(redactStringSecrets(node.message));
      cleanErr.name = node.name;
      delete cleanErr.stack;
      return cleanErr;
    }

    if (node instanceof Uint8Array) {
      return `[REDACTED_BYTES:${node.byteLength}]`;
    }

    if (Array.isArray(node)) {
      const preserveOutboundItems = Boolean(allowOutbound && fieldName && outboundFields.has(fieldName));
      const preserveHashItems = Boolean(fieldName && publicHashFields.has(fieldName));
      return node.map((item) => {
        if (preserveOutboundItems && typeof item === 'string') return item;
        return visit(item, preserveOutboundItems || preserveHashItems ? fieldName : undefined);
      });
    }

    if (node instanceof Map) {
      const nextMap = new Map<unknown, unknown>();
      for (const [k, v] of node.entries()) {
        const cleanKey = typeof k === 'string' ? redactStringSecrets(k) : visit(k);
        nextMap.set(cleanKey, visit(v, typeof k === 'string' ? k : undefined));
      }
      return nextMap;
    }

    if (node instanceof Set) {
      const nextSet = new Set<unknown>();
      for (const item of node.values()) {
        nextSet.add(visit(item));
      }
      return nextSet;
    }

    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      if (SENSITIVE_FIELD_NAME_RE.test(k)) {
        out[k] = '[REDACTED_SECRET]';
      } else {
        out[k] = visit(v, k);
      }
    }
    return out;
  };

  return visit(value) as T;
}

export interface BoundedAgentPolicyConfig {
  /** Maximum USD-equivalent per spend (6 decimals). Defaults to `500_000n` ($0.50). */
  maxPerCallUsdMicro?: bigint;
  /** Optional raw token unit cap per spend (uniform bigint or per-asset map). */
  maxPerCallAmount?: bigint | Partial<Record<PolicyAssetSymbol, bigint>>;
  /** Maximum spends allowed in any rolling 60-second window. Defaults to `3`. */
  maxSpendsPerMinute?: number;
  /** Maximum USD-equivalent allowed in any rolling 24-hour window (6 decimals). Defaults to `5_000_000n` ($5.00). */
  maxDailyUsdMicro?: bigint;
  /** Optional allowlist of checksummed/hex recipient wallet addresses. */
  allowedRecipients?: readonly string[];
  /** Optional allowlist of HTTPS hostnames (e.g. `["api.example.com", "*.trusted.io"]`). */
  allowedDomains?: readonly string[];
  /** Extra destination addresses to block in addition to `BLOCKED_PAYMENT_TARGETS`. */
  extraBlockedAddresses?: readonly string[];
  /** Optional asset USD-micro valuation overrides. */
  assetPricesUsdMicro?: Partial<Record<PolicyAssetSymbol, bigint>>;
  /** Default asset used when inspecting slip-id-only permits (`SplitPermit`, `RearrangePermit`, `Swap*`). Defaults to `'USDC'`. */
  defaultSlipAsset?: PolicyAssetSymbol;
  /** Whether `cryptoslip_pay_human` / `cryptoslip_batch_payout` may emit outbound `#` claim links. Defaults to `true`. */
  allowOutboundSlipLinks?: boolean;
  /** Blocks arbitrary `signMessage` unless explicitly enabled (e.g. receipt issuer signing). Defaults to `false`. */
  allowRawMessageSigning?: boolean;
  /** Injectable clock for deterministic sliding-window tests. */
  nowMs?: () => number;
}

export interface SpendRecord {
  timestampMs: number;
  usdMicro: bigint;
  dedupKey?: string;
}

export interface PolicySnapshot {
  maxPerCallUsdMicro: string;
  maxDailyUsdMicro: string;
  maxSpendsPerMinute: number;
  spendsInLastMinute: number;
  spentDailyUsdMicro: string;
  remainingDailyUsdMicro: string;
  allowedRecipientsCount: number;
  allowedDomainsCount: number;
  allowOutboundSlipLinks: boolean;
}

export interface EvaluateSpendInput {
  amount: bigint;
  asset?: PolicyAssetSymbol | string;
  recipient?: string;
  ownAddress?: string;
  /** Internal self-hop address (e.g. `PocketSlipVault` operatorAddress) still validated by `assertSafeDestination` while bypassing `allowedRecipients`. */
  allowInternalRecipient?: Address;
  domainOrUrl?: string;
  /** Optional permit nonce key so paired `ReceiveWithAuthorization` + `MintPermit` count once. */
  dedupKey?: string;
}

const ONE_MINUTE_MS = 60_000;
const ONE_DAY_MS = 86_400_000;
const DEDUP_WINDOW_MS = 30_000;

export class BoundedAgentPolicy {
  readonly maxPerCallUsdMicro: bigint;
  readonly maxPerCallAmount?: bigint | Partial<Record<PolicyAssetSymbol, bigint>>;
  readonly maxSpendsPerMinute: number;
  readonly maxDailyUsdMicro: bigint;
  readonly defaultSlipAsset: PolicyAssetSymbol;
  readonly allowOutboundSlipLinks: boolean;
  readonly allowRawMessageSigning: boolean;

  private readonly allowedRecipientsLower: ReadonlySet<string> | null;
  private readonly allowedDomainsLower: readonly string[] | null;
  private readonly extraBlockedAddresses: readonly string[];
  private readonly assetPricesUsdMicro?: Partial<Record<PolicyAssetSymbol, bigint>>;
  private readonly nowMs: () => number;
  private spends: SpendRecord[] = [];

  constructor(config: BoundedAgentPolicyConfig = {}) {
    this.maxPerCallUsdMicro = config.maxPerCallUsdMicro ?? 500_000n;
    this.maxPerCallAmount = config.maxPerCallAmount;
    this.maxSpendsPerMinute = config.maxSpendsPerMinute ?? 3;
    this.maxDailyUsdMicro = config.maxDailyUsdMicro ?? 5_000_000n;
    this.defaultSlipAsset = resolvePolicyAsset(config.defaultSlipAsset ?? 'USDC');
    this.allowOutboundSlipLinks = config.allowOutboundSlipLinks ?? true;
    this.allowRawMessageSigning = config.allowRawMessageSigning ?? false;
    this.extraBlockedAddresses = config.extraBlockedAddresses ?? [];
    this.assetPricesUsdMicro = config.assetPricesUsdMicro;
    this.nowMs = config.nowMs ?? (() => Date.now());

    if (this.maxPerCallUsdMicro <= 0n) {
      throw new PolicyViolationError('SPEND_CAP_EXCEEDED', 'maxPerCallUsdMicro must be positive.');
    }
    if (this.maxDailyUsdMicro < this.maxPerCallUsdMicro) {
      throw new PolicyViolationError(
        'DAILY_CAP_EXCEEDED',
        'maxDailyUsdMicro must be greater than or equal to maxPerCallUsdMicro.',
      );
    }
    if (!Number.isInteger(this.maxSpendsPerMinute) || this.maxSpendsPerMinute < 1) {
      throw new PolicyViolationError(
        'RATE_LIMIT_EXCEEDED',
        'maxSpendsPerMinute must be an integer >= 1.',
      );
    }

    if (config.allowedRecipients && config.allowedRecipients.length > 0) {
      const normalized = new Set<string>();
      for (const r of config.allowedRecipients) {
        const checked = assertSafeDestination(r, {
          extraBlockedAddresses: this.extraBlockedAddresses,
        });
        normalized.add(checked.toLowerCase());
      }
      this.allowedRecipientsLower = normalized;
    } else {
      this.allowedRecipientsLower = null;
    }

    if (config.allowedDomains && config.allowedDomains.length > 0) {
      this.allowedDomainsLower = config.allowedDomains.map((d) =>
        d.trim().toLowerCase().replace(/\.+$/, ''),
      );
    } else {
      this.allowedDomainsLower = null;
    }
  }

  private pruneHistory(now: number): void {
    const cutoff = now - ONE_DAY_MS;
    this.spends = this.spends.filter((s) => s.timestampMs > cutoff);
  }

  assertSafeDestination(to: string, ownAddress?: string): Address {
    const checksummed = assertSafeDestination(to, {
      ownAddress,
      extraBlockedAddresses: this.extraBlockedAddresses,
    });
    if (
      this.allowedRecipientsLower &&
      !this.allowedRecipientsLower.has(checksummed.toLowerCase())
    ) {
      throw new PolicyViolationError(
        'RECIPIENT_NOT_ALLOWLISTED',
        `Recipient ${checksummed} is not in the BoundedAgentPolicy allowedRecipients list.`,
      );
    }
    return checksummed;
  }

  assertAllowedDomain(urlOrDomain: string): string {
    const trimmed = urlOrDomain.trim();
    let hostname: string;
    let protocol = 'https:';
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
      let parsed: URL;
      try {
        parsed = new URL(trimmed);
      } catch {
        throw new PolicyViolationError('DOMAIN_NOT_ALLOWLISTED', `Invalid URL: ${trimmed}`);
      }
      protocol = parsed.protocol;
      hostname = parsed.hostname.toLowerCase().replace(/\.+$/, '');
    } else {
      hostname = (trimmed.split('/')[0] ?? '').toLowerCase().replace(/\.+$/, '');
    }

    if (!hostname) {
      throw new PolicyViolationError('DOMAIN_NOT_ALLOWLISTED', 'Missing target hostname.');
    }
    if (protocol !== 'https:' && hostname !== 'localhost' && hostname !== '127.0.0.1') {
      throw new PolicyViolationError(
        'DOMAIN_NOT_ALLOWLISTED',
        `Non-HTTPS payment endpoint ${protocol}//${hostname} is refused by policy.`,
      );
    }

    if (this.allowedDomainsLower) {
      const matched = this.allowedDomainsLower.some((pattern) => {
        if (pattern.startsWith('*.')) {
          const suffix = pattern.slice(1); // ".example.com"
          return hostname.endsWith(suffix) && hostname.length > suffix.length;
        }
        return hostname === pattern;
      });
      if (!matched) {
        throw new PolicyViolationError(
          'DOMAIN_NOT_ALLOWLISTED',
          `Domain ${hostname} is not in BoundedAgentPolicy allowedDomains.`,
        );
      }
    }
    return hostname;
  }

  assertValidSwap(input: SwapPolicyCheckInput): void {
    assertCanonicalNaraSwapPolicy(input);
  }

  assertCanEmitOutboundSlipLink(): void {
    if (!this.allowOutboundSlipLinks) {
      throw new PolicyViolationError(
        'OUTBOUND_SLIP_LINK_DISABLED',
        'Outbound slip link emission is disabled by BoundedAgentPolicy.',
      );
    }
  }

  /**
   * Validates destination, domain, per-call cap, sliding 60s rate limit, and rolling 24h cap,
   * then atomically records the spend if all checks pass.
   */
  authorizeAndRecordSpend(input: EvaluateSpendInput): { usdMicro: bigint } {
    if (input.recipient !== undefined) {
      const isInternalHop =
        input.allowInternalRecipient &&
        isAddress(input.recipient) &&
        getAddress(input.recipient).toLowerCase() ===
          getAddress(input.allowInternalRecipient).toLowerCase();
      if (isInternalHop) {
        assertSafeDestination(input.recipient, {
          ownAddress: input.ownAddress,
          extraBlockedAddresses: this.extraBlockedAddresses,
        });
      } else {
        this.assertSafeDestination(input.recipient, input.ownAddress);
      }
    }
    if (input.domainOrUrl !== undefined) {
      this.assertAllowedDomain(input.domainOrUrl);
    }
    if (input.amount < 0n) {
      throw new PolicyViolationError('SPEND_CAP_EXCEEDED', 'Spend amount cannot be negative.');
    }

    const assetSymbol = resolvePolicyAsset(input.asset);
    if (this.maxPerCallAmount !== undefined) {
      const rawCap =
        typeof this.maxPerCallAmount === 'bigint'
          ? this.maxPerCallAmount
          : (this.maxPerCallAmount[assetSymbol] ??
            (assetSymbol === 'cbBTC' ? this.maxPerCallAmount.BTC : undefined));
      if (rawCap !== undefined && input.amount > rawCap) {
        throw new PolicyViolationError(
          'SPEND_CAP_EXCEEDED',
          `Spend amount ${input.amount.toString()} ${assetSymbol} exceeds per-call token cap ${rawCap.toString()}.`,
        );
      }
    }

    const usdMicro = estimateUsdMicro(input.amount, assetSymbol, this.assetPricesUsdMicro);
    if (usdMicro > this.maxPerCallUsdMicro) {
      throw new PolicyViolationError(
        'SPEND_CAP_EXCEEDED',
        `Spend ($${formatMicroUsd(usdMicro)}) exceeds maxPerCallUsdMicro ($${formatMicroUsd(this.maxPerCallUsdMicro)}).`,
      );
    }

    const now = this.nowMs();
    this.pruneHistory(now);

    if (input.dedupKey) {
      const recentDuplicate = this.spends.find(
        (s) => s.dedupKey === input.dedupKey && now - s.timestampMs <= DEDUP_WINDOW_MS,
      );
      if (recentDuplicate) {
        return { usdMicro };
      }
    }

    const minuteCutoff = now - ONE_MINUTE_MS;
    const spendsLastMinute = this.spends.filter((s) => s.timestampMs > minuteCutoff).length;
    if (spendsLastMinute >= this.maxSpendsPerMinute) {
      throw new PolicyViolationError(
        'RATE_LIMIT_EXCEEDED',
        `Rate limit exceeded: ${spendsLastMinute}/${this.maxSpendsPerMinute} spends in the last 60 seconds.`,
      );
    }

    const spentToday = this.spends.reduce((acc, s) => acc + s.usdMicro, 0n);
    if (spentToday + usdMicro > this.maxDailyUsdMicro) {
      throw new PolicyViolationError(
        'DAILY_CAP_EXCEEDED',
        `Daily budget exceeded: $${formatMicroUsd(spentToday + usdMicro)} > $${formatMicroUsd(this.maxDailyUsdMicro)}.`,
      );
    }

    this.spends.push({
      timestampMs: now,
      usdMicro,
      dedupKey: input.dedupKey,
    });

    return { usdMicro };
  }

  redactOutput<T>(value: T, options?: RedactToolOutputOptions): T {
    if (options?.allowOutboundSlipLink) {
      this.assertCanEmitOutboundSlipLink();
    }
    return redactSecretsFromToolOutput(value, options);
  }

  getSnapshot(): PolicySnapshot {
    const now = this.nowMs();
    this.pruneHistory(now);
    const minuteCutoff = now - ONE_MINUTE_MS;
    const spendsInLastMinute = this.spends.filter((s) => s.timestampMs > minuteCutoff).length;
    const spentDaily = this.spends.reduce((acc, s) => acc + s.usdMicro, 0n);
    const remaining =
      this.maxDailyUsdMicro > spentDaily ? this.maxDailyUsdMicro - spentDaily : 0n;

    return {
      maxPerCallUsdMicro: this.maxPerCallUsdMicro.toString(),
      maxDailyUsdMicro: this.maxDailyUsdMicro.toString(),
      maxSpendsPerMinute: this.maxSpendsPerMinute,
      spendsInLastMinute,
      spentDailyUsdMicro: spentDaily.toString(),
      remainingDailyUsdMicro: remaining.toString(),
      allowedRecipientsCount: this.allowedRecipientsLower?.size ?? 0,
      allowedDomainsCount: this.allowedDomainsLower?.length ?? 0,
      allowOutboundSlipLinks: this.allowOutboundSlipLinks,
    };
  }
}

function formatMicroUsd(micro: bigint): string {
  const whole = micro / 1_000_000n;
  const frac = (micro % 1_000_000n).toString().padStart(6, '0').replace(/0+$/, '');
  return frac ? `${whole.toString()}.${frac.padEnd(2, '0')}` : `${whole.toString()}.00`;
}

export interface TypedDataSignPayload {
  domain?: {
    name?: string;
    version?: string;
    chainId?: number | bigint;
    verifyingContract?: string;
  };
  types: Record<string, readonly { name: string; type: string }[]>;
  primaryType: string;
  message: Record<string, unknown>;
}

export interface PolicyGuardableSigner {
  readonly address: Address;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  signTypedData: (payload: any) => Promise<Hex>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  signMessage?: (message: any) => Promise<Hex>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  signTransaction?: (tx: any) => Promise<Hex>;
}

export type PolicyGuardedSigner<TSigner extends PolicyGuardableSigner = PolicyGuardableSigner> =
  TSigner & {
    readonly kind: 'policyGuarded';
    readonly policy: BoundedAgentPolicy;
    getAddress(): Promise<Address>;
    toString(): string;
    toJSON(): { address: Address; kind: 'policyGuarded' };
  };

function toBigIntField(raw: unknown, fieldName: string): bigint {
  if (typeof raw === 'bigint') return raw;
  if (typeof raw === 'number' && Number.isSafeInteger(raw) && raw >= 0) return BigInt(raw);
  if (typeof raw === 'string' && /^(?:0x[0-9a-fA-F]+|\d+)$/.test(raw)) return BigInt(raw);
  throw new PolicyViolationError('SPEND_CAP_EXCEEDED', `Invalid numeric field ${fieldName} in permit.`);
}

function toStringField(raw: unknown): string {
  return typeof raw === 'string' ? raw : '';
}

export interface CreatePolicyGuardedSignerOptions {
  /** Asset backing the guarded slip (`'USDC' | 'cbBTC' | 'BTC' | 'ETH' | 'NARA'`). */
  slipAsset?: PolicyAssetSymbol | string;
  /** Optional internal operator wallet allowed on `SplitPermit` / `RearrangePermit` self-hops even when `allowedRecipients` is set. */
  allowInternalRecipient?: Address;
}

function assertSafeChangeFields(
  changeReceiver: string,
  newChangeSigner: string,
  signerAddress: Address,
): void {
  const receiverLower = changeReceiver.toLowerCase();
  if (
    changeReceiver !== '' &&
    receiverLower !== zeroAddress &&
    !TRUSTED_V32_VAULTS_LOWER.has(receiverLower)
  ) {
    throw new PolicyViolationError(
      'BLOCKED_DESTINATION',
      `Split/Rearrange changeReceiver (${changeReceiver}) must be zero address or a canonical V3.2/V3.3 vault to prevent remainder theft.`,
    );
  }
  if (newChangeSigner !== '' && newChangeSigner.toLowerCase() !== zeroAddress) {
    assertSafeDestination(newChangeSigner, { ownAddress: signerAddress });
  }
}

function inspectAndAuthorizeTypedData(
  policy: BoundedAgentPolicy,
  signerAddress: Address,
  payload: TypedDataSignPayload,
  options?: CreatePolicyGuardedSignerOptions,
): void {
  const { primaryType, message, domain } = payload;
  const verifyingContract = toStringField(domain?.verifyingContract);
  const slipAsset = resolvePolicyAsset(options?.slipAsset ?? policy.defaultSlipAsset);

  switch (primaryType) {
    case 'AcceptPermit': {
      const keepEscrowed = Boolean(message.keepEscrowedInVault);
      const newClaimSigner = toStringField(message.newClaimSigner);
      const newHolder = toStringField(message.newHolder);
      // Boot Auto-Keep (`V-01`) rotates claimSigner inside the vault at 0% fee (not an external spend).
      assertSafeDestination(newClaimSigner, { ownAddress: signerAddress });
      if (!keepEscrowed) {
        policy.assertSafeDestination(newHolder, signerAddress);
      }
      return;
    }

    case 'CashPermit': {
      const recipient = toStringField(message.recipient);
      policy.assertSafeDestination(recipient, signerAddress);
      return;
    }

    case 'SplitPermit': {
      const merchant = toStringField(message.merchant);
      const changeReceiver = toStringField(message.changeReceiver);
      const newChangeSigner = toStringField(message.newChangeSigner);
      const paymentAmount = toBigIntField(message.paymentAmount, 'paymentAmount');
      assertSafeChangeFields(changeReceiver, newChangeSigner, signerAddress);
      policy.authorizeAndRecordSpend({
        amount: paymentAmount,
        asset: slipAsset,
        recipient: merchant,
        ownAddress: signerAddress,
        allowInternalRecipient: options?.allowInternalRecipient,
      });
      return;
    }

    case 'RearrangePermit': {
      const merchant = toStringField(message.merchant);
      const changeReceiver = toStringField(message.changeReceiver);
      const newChangeSigner = toStringField(message.newChangeSigner);
      const paymentAmount = toBigIntField(message.paymentAmount, 'paymentAmount');
      const slipIdsHash = toStringField(message.slipIdsHash);
      assertSafeChangeFields(changeReceiver, newChangeSigner, signerAddress);
      // Pure vault consolidation (`V-05` combineSlips with paymentAmount === 0n and merchant === 0x0)
      // keeps 100% of value inside the canonical vault under a safe newChangeSigner.
      if (
        paymentAmount === 0n &&
        merchant.toLowerCase() === zeroAddress &&
        TRUSTED_V32_VAULTS_LOWER.has(changeReceiver.toLowerCase())
      ) {
        assertSafeDestination(newChangeSigner, { ownAddress: signerAddress });
        return;
      }
      policy.authorizeAndRecordSpend({
        amount: paymentAmount,
        asset: slipAsset,
        recipient: merchant,
        ownAddress: signerAddress,
        allowInternalRecipient: options?.allowInternalRecipient,
        dedupKey: slipIdsHash ? `rearrange:${slipIdsHash}` : undefined,
      });
      return;
    }

    case 'MintPermit': {
      const token = toStringField(message.token);
      const amount = toBigIntField(message.amount, 'amount');
      const claimSigner = toStringField(message.claimSigner);
      const nonce = toStringField(message.nonce);
      assertSafeDestination(claimSigner);
      policy.authorizeAndRecordSpend({
        amount,
        asset: token || 'USDC',
        dedupKey: nonce ? `mint:${nonce.toLowerCase()}` : undefined,
      });
      return;
    }

    case 'ReceiveWithAuthorization': {
      const to = toStringField(message.to);
      const value = toBigIntField(message.value, 'value');
      const nonce = toStringField(message.nonce);
      if (!TRUSTED_V32_VAULTS_LOWER.has(to.toLowerCase())) {
        policy.assertSafeDestination(to, signerAddress);
      }
      policy.authorizeAndRecordSpend({
        amount: value,
        asset: verifyingContract || 'USDC',
        dedupKey: nonce ? `mint:${nonce.toLowerCase()}` : undefined,
      });
      return;
    }

    case 'TransferWithAuthorization': {
      const to = toStringField(message.to);
      const value = toBigIntField(message.value, 'value');
      policy.authorizeAndRecordSpend({
        amount: value,
        asset: verifyingContract || 'USDC',
        recipient: to,
        ownAddress: signerAddress,
        allowInternalRecipient: options?.allowInternalRecipient,
      });
      return;
    }

    case 'Permit': {
      const spender = toStringField(message.spender);
      const value = toBigIntField(message.value, 'value');
      if (!TRUSTED_PERMIT_SPENDERS_LOWER.has(spender.toLowerCase())) {
        throw new PolicyViolationError(
          'UNTRUSTED_PERMIT_SPENDER',
          `ERC-2612 Permit spender ${spender} is not a canonical CryptoSLIP vault or TokenPaymasterV08.`,
        );
      }
      policy.authorizeAndRecordSpend({
        amount: value,
        asset: verifyingContract || 'USDC',
      });
      return;
    }

    case 'SwapOfferPermit': {
      const swapAmount = toBigIntField(message.swapAmount, 'swapAmount');
      const outAsset = toStringField(message.outAsset);
      const newOutputSigner = toStringField(message.newOutputSigner);
      const swapTarget = toStringField(message.swapTarget);
      assertSafeDestination(newOutputSigner);
      policy.assertValidSwap({ inAsset: slipAsset, outAsset, swapTarget });
      policy.authorizeAndRecordSpend({
        amount: swapAmount,
        asset: slipAsset,
      });
      return;
    }

    case 'CompositeSwapOfferPermit': {
      const swapAmount = toBigIntField(message.swapAmount, 'swapAmount');
      const midAsset = toStringField(message.midAsset);
      const outAsset = toStringField(message.outAsset);
      const newOutputSigner = toStringField(message.newOutputSigner);
      const swapTarget1 = toStringField(message.swapTarget1);
      const swapTarget2 = toStringField(message.swapTarget2);
      assertSafeDestination(newOutputSigner);
      policy.assertValidSwap({ inAsset: slipAsset, outAsset: midAsset, swapTarget: swapTarget1 });
      policy.assertValidSwap({ inAsset: midAsset, outAsset, swapTarget: swapTarget2 });
      policy.authorizeAndRecordSpend({
        amount: swapAmount,
        asset: slipAsset,
      });
      return;
    }

    case 'SwapAndPayPermit': {
      const swapAmount = toBigIntField(message.swapAmount, 'swapAmount');
      const merchant = toStringField(message.merchant);
      const outAsset = toStringField(message.outAsset);
      const swapTarget = toStringField(message.swapTarget);
      policy.assertValidSwap({ inAsset: slipAsset, outAsset, swapTarget });
      policy.authorizeAndRecordSpend({
        amount: swapAmount,
        asset: slipAsset,
        recipient: merchant,
        ownAddress: signerAddress,
        allowInternalRecipient: options?.allowInternalRecipient,
      });
      return;
    }

    case 'RefundPermit': {
      const destination = toStringField(message.destination);
      assertSafeDestination(destination);
      return;
    }

    case 'ReferralConsent':
    case 'PaymentReceiptV1': {
      return;
    }

    default: {
      // Unknown EIP-712 payloads with a recipient/to/merchant field still undergo destination validation.
      const maybeDest =
        toStringField(message.recipient) ||
        toStringField(message.merchant) ||
        toStringField(message.to);
      if (maybeDest) {
        policy.assertSafeDestination(maybeDest, signerAddress);
      }
      if (message.amount !== undefined || message.value !== undefined) {
        const rawAmt = message.amount ?? message.value;
        const amt = toBigIntField(rawAmt, 'amount');
        policy.authorizeAndRecordSpend({ amount: amt });
      }
    }
  }
}

/**
 * Wraps any `SlipSigner` / `viem` `LocalAccount` with `BoundedAgentPolicy` so every
 * EIP-712 permit, swap, or spend is validated out-of-context BEFORE a signature is produced.
 */
export function createPolicyGuardedSigner<TSigner extends PolicyGuardableSigner>(
  signer: TSigner,
  policyOrConfig: BoundedAgentPolicy | BoundedAgentPolicyConfig = {},
  options?: CreatePolicyGuardedSignerOptions,
): PolicyGuardedSigner<TSigner> {
  const policy =
    policyOrConfig instanceof BoundedAgentPolicy
      ? policyOrConfig
      : new BoundedAgentPolicy(policyOrConfig);

  const checksumAddress = getAddress(signer.address);

  const guarded = Object.create(Object.getPrototypeOf(signer) as object) as PolicyGuardedSigner<TSigner>;
  Object.assign(guarded, signer);

  Object.defineProperty(guarded, 'address', {
    value: checksumAddress,
    enumerable: true,
    writable: false,
  });

  Object.defineProperty(guarded, 'kind', {
    value: 'policyGuarded',
    enumerable: true,
    writable: false,
  });

  Object.defineProperty(guarded, 'policy', {
    value: policy,
    enumerable: true,
    writable: false,
  });

  guarded.getAddress = async (): Promise<Address> => checksumAddress;
  guarded.toString = (): string => `SlipSigner(policyGuarded:${checksumAddress})`;
  guarded.toJSON = () => ({ address: checksumAddress, kind: 'policyGuarded' as const });

  Object.defineProperty(guarded, Symbol.for('nodejs.util.inspect.custom'), {
    value: () => `SlipSigner(policyGuarded:${checksumAddress})`,
    enumerable: false,
    configurable: true,
  });

  guarded.signTypedData = async (payload: TypedDataSignPayload): Promise<Hex> => {
    inspectAndAuthorizeTypedData(policy, checksumAddress, payload, options);
    return signer.signTypedData(payload);
  };

  if (typeof signer.signMessage === 'function') {
    const origSignMessage = signer.signMessage.bind(signer);
    guarded.signMessage = async (msg: unknown): Promise<Hex> => {
      if (!policy.allowRawMessageSigning) {
        throw new PolicyViolationError(
          'RAW_SIGNING_BLOCKED',
          'Blind signMessage is blocked by BoundedAgentPolicy (set allowRawMessageSigning: true only for receipt issuers).',
        );
      }
      return origSignMessage(msg);
    };
  }

  if (typeof signer.signTransaction === 'function') {
    const origSignTx = signer.signTransaction.bind(signer);
    guarded.signTransaction = async (tx: Record<string, unknown>): Promise<Hex> => {
      const to = toStringField(tx?.to);
      const value = tx?.value !== undefined ? toBigIntField(tx.value, 'value') : 0n;
      if (to && !TRUSTED_V32_VAULTS_LOWER.has(to.toLowerCase()) && to.toLowerCase() !== POLICY_CANONICAL_CONTRACTS.multicall3.toLowerCase()) {
        policy.assertSafeDestination(to, getAddress(signer.address));
      }
      if (value > 0n) {
        policy.authorizeAndRecordSpend({
          amount: value,
          asset: 'ETH',
        });
      }
      return origSignTx(tx);
    };
  }

  return guarded;
}
