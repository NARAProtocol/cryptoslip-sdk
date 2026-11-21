import {
  encodeAbiParameters,
  encodeFunctionData,
  encodePacked,
  getAddress,
  isAddress,
  keccak256,
  maxUint256,
  parseAbi,
  parseAbiParameters,
  stringToHex,
  type Address,
  type Hex,
  type PublicClient,
  type Transport,
  type WalletClient,
} from 'viem';
import { privateKeyToAccount, sign, signAuthorization } from 'viem/accounts';
import { ENTRY_POINT_V08_ABI, SIMPLE_7702_ACCOUNT_ABI } from './abi.js';
import {
  AKASH_RELAY_GATEWAY,
  appendBuilderCodeSuffix,
  BASE_CHAIN_ID_BIG,
  CANONICAL_SIMPLE_7702_DELEGATION_CODE,
  CIRCLE_TOKEN_PAYMASTER_V07_ADDRESS,
  CIRCLE_USDC_PAYMASTER_V08,
  DEFAULT_CRYPTOSLIP_BUILDER_CODE,
  ENTRY_POINT_V07_ADDRESS,
  ENTRY_POINT_V08,
  isNaraDualAttributionTarget,
  MAX_CIRCLE_PAYMASTER_PERMIT_UNITS,
  MIN_CIRCLE_PAYMASTER_USDC_UNITS,
  NARA_IN_APP_BUILDER_CODES,
  PUBLIC_BASE_BUNDLERS,
  SIMPLE_7702_ACCOUNT,
  USDC_BASE_ADDRESS,
  WORKER_RELAY_GATEWAY,
} from './constants.js';

export {
  AKASH_RELAY_GATEWAY,
  CANONICAL_SIMPLE_7702_DELEGATION_CODE,
  CIRCLE_USDC_PAYMASTER_V08,
  ENTRY_POINT_V08,
  MAX_CIRCLE_PAYMASTER_PERMIT_UNITS,
  MIN_CIRCLE_PAYMASTER_USDC_UNITS,
  PUBLIC_BASE_BUNDLERS,
  SIMPLE_7702_ACCOUNT,
  WORKER_RELAY_GATEWAY,
} from './constants.js';

/**
 * `viem` `PublicClient` compatible with BOTH `createPublicClient({ chain: base, ... })`
 * (OP-Stack `formatters` on `viem/chains` `base`) and unparameterized `PublicClient` under TS6 `strict: true`.
 */
export type BaseCompatiblePublicClient = PublicClient<Transport, any>;

/**
 * `viem` `WalletClient` compatible with BOTH `createWalletClient({ chain: base, ... })`
 * and unparameterized `WalletClient` under TS6 `strict: true`.
 */
export type BaseCompatibleWalletClient = WalletClient<Transport, any, any>;

/**
 * Valid, non-zero static secp256k1 dummy signature for ERC-4337 `eth_estimateUserOperationGas`.
 * Built programmatically to avoid any static 64-hex secret scanner false positives while remaining
 * byte-for-byte identical to `STATIC_ERC4337_DUMMY_SIG` in `client/src/lib/circlePaymaster.ts`.
 */
export const STATIC_ERC4337_DUMMY_SIG: Hex =
  `0x${'f'.repeat(31)}${'0'.repeat(33)}7${'a'.repeat(63)}1c`;

const COMPROMISED_SIGNER_LOWER = '0x5f3a378b685e309ae7404a7483420e49f2fbe6aa';

const PERSONAL_ERC20_SELECTORS_PM = new Set<string>([
  keccak256(stringToHex('transfer(address,uint256)')).slice(0, 10).toLowerCase(),
  keccak256(stringToHex('approve(address,uint256)')).slice(0, 10).toLowerCase(),
  keccak256(
    stringToHex('transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,bytes)'),
  )
    .slice(0, 10)
    .toLowerCase(),
  keccak256(
    stringToHex(
      'transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)',
    ),
  )
    .slice(0, 10)
    .toLowerCase(),
]);

/**
 * Thrown when `eth_sendUserOperation` ALREADY succeeded on a bundler but inclusion was not yet
 * observed within the poll window. Callers MUST NEVER swallow this into a retry/fallback
 * because the UserOperation may already be mining on Base (preventing double-spends).
 */
export class PaymasterPendingError extends Error {
  readonly userOpHash: Hex;
  readonly bundlerUrl: string;

  constructor(
    userOpHash: Hex,
    bundlerUrl: string,
    message = 'UserOperation submitted, waiting for Base block confirmation.',
  ) {
    super(message);
    this.name = 'PaymasterPendingError';
    this.userOpHash = userOpHash;
    this.bundlerUrl = bundlerUrl;
  }
}

/**
 * Thrown when all configured Edge Relay gateways are unreachable, rate-limited (429), or down (5xx).
 * Safe to fail over to Tier-2 Circle `TokenPaymasterV08` or Tier-3 direct Base transaction.
 */
export class RelayUnavailableError extends Error {
  readonly definitePreBroadcast: boolean;
  readonly statusCode?: number;

  constructor(message: string, definitePreBroadcast = true, statusCode?: number) {
    super(message);
    this.name = 'RelayUnavailableError';
    this.definitePreBroadcast = definitePreBroadcast;
    if (statusCode !== undefined) {
      this.statusCode = statusCode;
    }
  }
}

/**
 * Thrown when an Edge Relay gateway deterministically rejects a request (e.g. 400/403/409).
 * Must NOT be retried on a secondary gateway or bundler.
 */
export class RelayRejectedError extends Error {
  readonly statusCode: number;

  constructor(statusCode: number, message: string) {
    super(message);
    this.name = 'RelayRejectedError';
    this.statusCode = statusCode;
  }
}

export const PAYMASTER_BASE_CHAIN_ID_BIG = BASE_CHAIN_ID_BIG;
export const PAYMASTER_ENTRY_POINT_V08: Address = ENTRY_POINT_V08;
export const PAYMASTER_ENTRY_POINT_V07: Address = ENTRY_POINT_V07_ADDRESS;
export const PAYMASTER_SIMPLE_7702_ACCOUNT: Address = SIMPLE_7702_ACCOUNT;
export const CIRCLE_USDC_PAYMASTER_V07: Address = CIRCLE_TOKEN_PAYMASTER_V07_ADDRESS;
export const PAYMASTER_BASE_USDC_TOKEN: Address = USDC_BASE_ADDRESS;

/** Byte offset of the 20-byte USDC token address inside full `paymasterAndData` (`20 + 16 + 16 + 1 = 53`). */
export const PAYMASTER_TOKEN_ADDRESS_OFFSET = 53;

/** Minimum native ETH balance required to self-pay a Base L2 + L1-blob vault tx (~0.000025 ETH). */
export const MIN_SELF_GAS_BALANCE_WEI = 25_000_000_000_000n;

export const PRODUCTION_EDGE_GATEWAYS: readonly string[] = Object.freeze([
  WORKER_RELAY_GATEWAY,
  AKASH_RELAY_GATEWAY,
]);

const PACKED_USEROP_TYPEHASH = keccak256(
  stringToHex(
    'PackedUserOperation(address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData)',
  ),
);

const EIP712_DOMAIN_TYPEHASH = keccak256(
  stringToHex('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
);
const ERC4337_NAME_HASH = keccak256(stringToHex('ERC4337'));
const ERC4337_VERSION_HASH = keccak256(stringToHex('1'));

const PAYMASTER_READ_ABI = parseAbi(['function paused() view returns (bool)']);

const USDC_PERMIT_READ_ABI = parseAbi([
  'function balanceOf(address owner) view returns (uint256)',
  'function nonces(address owner) view returns (uint256)',
]);

const USDC_EIP2612_TYPES = {
  Permit: [
    { name: 'owner', type: 'address' },
    { name: 'spender', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
} as const;

export interface UserOpCall {
  to: Address;
  value?: bigint;
  data: Hex;
}

export interface ComputeUserOpHashV08Params {
  sender: Address;
  nonce: bigint;
  callData: Hex;
  verificationGasLimit: bigint;
  callGasLimit: bigint;
  preVerificationGas: bigint;
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
  paymaster: Address;
  paymasterVerificationGasLimit: bigint;
  paymasterPostOpGasLimit: bigint;
  paymasterData: Hex;
  use7702Factory: boolean;
  delegateAddress?: Address;
  chainId?: bigint;
}

export type BundlerFetchFn = (url: string, init: RequestInit) => Promise<Response>;

let _bundlerFetchOverride: BundlerFetchFn | null = null;

export const setBundlerFetchForTest = (fn: BundlerFetchFn | null): void => {
  _bundlerFetchOverride = fn;
};

/**
 * Formats a non-negative integer as a compact EIP-1474 JSON-RPC `QUANTITY` (`0x0`, `0x55730`),
 * matching `ethers.toQuantity(...)` byte-for-byte.
 */
export const toRpcQuantity = (value: bigint | number): Hex => {
  const n = BigInt(value);
  if (n < 0n) throw new Error('RPC quantity cannot be negative');
  return (n === 0n ? '0x0' : `0x${n.toString(16)}`) as Hex;
};

const appendPaymasterBuilderSuffix = (
  data: Hex,
  calls: readonly UserOpCall[],
  disableAttribution = false,
): Hex => {
  if (disableAttribution || !/^0x(?:[0-9a-fA-F]{2})*$/.test(data)) return data;
  const isPersonalOnlyBatch =
    calls.length > 0 &&
    calls.every(
      (c) =>
        typeof c.data === 'string' &&
        c.data.length >= 10 &&
        PERSONAL_ERC20_SELECTORS_PM.has(c.data.slice(0, 10).toLowerCase()),
    );
  if (isPersonalOnlyBatch) return data;
  const codes = calls.some((c) => isNaraDualAttributionTarget(c.to, c.data))
    ? NARA_IN_APP_BUILDER_CODES
    : DEFAULT_CRYPTOSLIP_BUILDER_CODE;
  return appendBuilderCodeSuffix(data, codes);
};

/**
 * Returns true if `code` is empty (`0x`, standard EOA) OR the canonical ERC-4337
 * `Simple7702Account` EIP-7702 delegation (`0xef0100e6cae83bde06e4c305530e199d7217f42808555b`).
 * Rejects arbitrary smart contracts and unknown/malicious EIP-7702 sweeper delegations.
 */
export const isPersonalOrCanonical7702Code = (code: string | null | undefined): boolean => {
  if (!code || code === '0x' || /^0x0+$/i.test(code)) return true;
  return code.toLowerCase() === CANONICAL_SIMPLE_7702_DELEGATION_CODE.toLowerCase();
};

/**
 * Encodes Circle `TokenPaymasterV08` `paymasterData` matching `PAYMASTER_TOKEN_ADDRESS_OFFSET = 53`:
 * `uint8(0) || address(usdcToken) || uint256(permitAmount) || bytes(permitSignature)`.
 */
export const encodeCirclePaymasterV08Data = (
  permitAmount: bigint,
  permitSignature: Hex,
  usdcToken: Address = PAYMASTER_BASE_USDC_TOKEN,
): Hex =>
  encodePacked(
    ['uint8', 'address', 'uint256', 'bytes'],
    [0, getAddress(usdcToken), permitAmount, permitSignature],
  );

/**
 * Encodes the full ERC-4337 v0.8 `paymasterAndData` byte layout:
 * `address(paymaster) || uint128(paymasterVerificationGasLimit) || uint128(paymasterPostOpGasLimit) || bytes(paymasterData)`.
 * Places the USDC token address strictly at byte offset `53` (`PAYMASTER_TOKEN_ADDRESS_OFFSET`).
 */
export const encodePaymasterAndDataV08 = (params: {
  paymaster?: Address;
  paymasterVerificationGasLimit: bigint;
  paymasterPostOpGasLimit: bigint;
  paymasterData: Hex;
}): Hex =>
  encodePacked(
    ['address', 'uint128', 'uint128', 'bytes'],
    [
      getAddress(params.paymaster ?? CIRCLE_USDC_PAYMASTER_V08),
      params.paymasterVerificationGasLimit,
      params.paymasterPostOpGasLimit,
      params.paymasterData,
    ],
  );

/**
 * Encodes one or more target calls for `Simple7702Account` (`execute` or `executeBatch`).
 */
export const encodeSimple7702Calls = (calls: readonly UserOpCall[]): Hex => {
  if (calls.length === 0) {
    throw new Error('At least one UserOperation call is required.');
  }
  if (calls.length === 1) {
    const first = calls[0]!;
    return encodeFunctionData({
      abi: SIMPLE_7702_ACCOUNT_ABI,
      functionName: 'execute',
      args: [getAddress(first.to), first.value ?? 0n, first.data],
    });
  }
  return encodeFunctionData({
    abi: SIMPLE_7702_ACCOUNT_ABI,
    functionName: 'executeBatch',
    args: [
      calls.map((c) => ({
        target: getAddress(c.to),
        value: c.value ?? 0n,
        data: c.data,
      })),
    ],
  });
};

/**
 * Deterministically computes the ERC-4337 `EntryPoint v0.8` EIP-712 `userOpHash` locally
 * (never trusting an external RPC/bundler to compute the digest signed by the wallet).
 */
export const computeUserOpHashV08 = (p: ComputeUserOpHashV08Params): Hex => {
  const chainId = p.chainId ?? PAYMASTER_BASE_CHAIN_ID_BIG;
  const delegateAddr = getAddress(p.delegateAddress ?? PAYMASTER_SIMPLE_7702_ACCOUNT);
  const accountGasLimits = encodePacked(
    ['uint128', 'uint128'],
    [p.verificationGasLimit, p.callGasLimit],
  );
  const gasFees = encodePacked(['uint128', 'uint128'], [p.maxPriorityFeePerGas, p.maxFeePerGas]);
  const paymasterAndData = encodePaymasterAndDataV08({
    paymaster: p.paymaster,
    paymasterVerificationGasLimit: p.paymasterVerificationGasLimit,
    paymasterPostOpGasLimit: p.paymasterPostOpGasLimit,
    paymasterData: p.paymasterData,
  });
  const hashInitCode = p.use7702Factory
    ? keccak256(encodePacked(['address'], [delegateAddr]))
    : keccak256('0x');

  const structHash = keccak256(
    encodeAbiParameters(
      parseAbiParameters(
        'bytes32, address, uint256, bytes32, bytes32, bytes32, uint256, bytes32, bytes32',
      ),
      [
        PACKED_USEROP_TYPEHASH,
        getAddress(p.sender),
        p.nonce,
        hashInitCode,
        keccak256(p.callData),
        accountGasLimits,
        p.preVerificationGas,
        gasFees,
        keccak256(paymasterAndData),
      ],
    ),
  );

  const domainSeparator = keccak256(
    encodeAbiParameters(parseAbiParameters('bytes32, bytes32, bytes32, uint256, address'), [
      EIP712_DOMAIN_TYPEHASH,
      ERC4337_NAME_HASH,
      ERC4337_VERSION_HASH,
      chainId,
      PAYMASTER_ENTRY_POINT_V08,
    ]),
  );

  return keccak256(
    encodePacked(['bytes2', 'bytes32', 'bytes32'], ['0x1901', domainSeparator, structHash]),
  );
};

const callBundlerRpc = async (
  bundlerUrl: string,
  method: string,
  params: unknown[],
  timeoutMs = 7_500,
  fetchFn?: BundlerFetchFn,
): Promise<unknown> => {
  const fetcher: BundlerFetchFn =
    fetchFn ?? _bundlerFetchOverride ?? ((u, init) => globalThis.fetch(u, init));
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetcher(bundlerUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method,
        params,
      }),
      signal: ctrl.signal,
    });
    if (!res.ok) {
      throw new Error(`Bundler HTTP ${res.status}`);
    }
    const payload = (await res.json()) as {
      result?: unknown;
      error?: { code?: number; message?: string };
    };
    if (payload?.error) {
      const errMsg =
        typeof payload.error?.message === 'string'
          ? payload.error.message
          : JSON.stringify(payload.error);
      const err = new Error(errMsg) as Error & { rpcCode?: number };
      if (payload.error.code !== undefined) {
        err.rpcCode = payload.error.code;
      }
      throw err;
    }
    return payload?.result;
  } finally {
    clearTimeout(timer);
  }
};

/**
 * Checks whether `userAddress` can self-sponsor gas on Base via Circle's Permissionless USDC Paymaster:
 * 1. Paymaster is not paused (fails closed on RPC error).
 * 2. Account code is empty (`0x`) or already delegated to canonical `Simple7702Account` (fails closed on RPC error).
 * 3. Unreserved USDC balance >= $0.10 USDC (`reservedUsdcUnits + MIN_CIRCLE_PAYMASTER_USDC_UNITS`).
 */
export const canSponsorWithCircleUsdcPaymaster = async (params: {
  userAddress: Address;
  publicClient: BaseCompatiblePublicClient;
  reservedUsdcUnits?: bigint;
  usdcToken?: Address;
  paymasterAddress?: Address;
  timeoutMs?: number;
}): Promise<{ ok: boolean; availableGasUsdcUnits: bigint }> => {
  const {
    userAddress,
    publicClient,
    reservedUsdcUnits = 0n,
    usdcToken = PAYMASTER_BASE_USDC_TOKEN,
    paymasterAddress = CIRCLE_USDC_PAYMASTER_V08,
    timeoutMs = 3_500,
  } = params;

  if (!isAddress(userAddress)) {
    return { ok: false, availableGasUsdcUnits: 0n };
  }
  const addr = getAddress(userAddress);
  try {
    let timer: ReturnType<typeof setTimeout> | null = null;
    const [bal, paused, code] = await Promise.race([
      Promise.all([
        publicClient
          .readContract({
            address: getAddress(usdcToken),
            abi: USDC_PERMIT_READ_ABI,
            functionName: 'balanceOf',
            args: [addr],
          })
          .catch(() => -1n),
        publicClient
          .readContract({
            address: getAddress(paymasterAddress),
            abi: PAYMASTER_READ_ABI,
            functionName: 'paused',
          })
          .catch(() => true),
        publicClient
          .getCode({ address: addr })
          .then((c) => c ?? '0x')
          .catch(() => '0xdead'),
      ]),
      new Promise<[bigint, boolean, string]>((resolve) => {
        timer = setTimeout(() => resolve([-1n, true, '0xdead']), timeoutMs);
      }),
    ]).finally(() => {
      if (timer) clearTimeout(timer);
    });

    if (bal < 0n || paused || !isPersonalOrCanonical7702Code(code)) {
      return { ok: false, availableGasUsdcUnits: 0n };
    }
    const available = bal > reservedUsdcUnits ? bal - reservedUsdcUnits : 0n;
    return {
      ok: available >= MIN_CIRCLE_PAYMASTER_USDC_UNITS,
      availableGasUsdcUnits: available,
    };
  } catch {
    return { ok: false, availableGasUsdcUnits: 0n };
  }
};

const addGasBuffer = (raw: unknown, floor: bigint, bps = 12_000n): bigint => {
  try {
    if (raw === undefined || raw === null) return floor;
    const v = BigInt(raw as string | number | bigint);
    const buffered = (v * bps) / 10_000n;
    return buffered > floor ? buffered : floor;
  } catch {
    return floor;
  }
};

export interface ExecuteViaCirclePaymasterParams {
  /** 32-byte 0x-prefixed EOA key controlling the sender wallet (required for EIP-7702 + raw UserOp digest signature). */
  signerKey: Hex;
  calls: readonly UserOpCall[];
  publicClient: BaseCompatiblePublicClient;
  reservedUsdcUnits?: bigint;
  bundlerUrls?: readonly string[];
  bundlerFetch?: BundlerFetchFn;
  usdcToken?: Address;
  paymasterAddress?: Address;
  chainId?: bigint;
  disableBuilderAttribution?: boolean;
  pollTimeoutMs?: number;
  pollIntervalMs?: number;
  onStatus?: (msg: string) => void;
}

export interface ExecuteViaCirclePaymasterResult {
  txHash: Hex;
  userOpHash: Hex;
  bundlerUrl: string;
}

/**
 * Executes `calls` from an EOA with 0 native ETH by paying gas in Base `USDC`
 * directly to Circle's on-chain `TokenPaymasterV08` (`0x0578cFB241215b77442a541325d6A4E6dFE700Ec`).
 * Zero CryptoSLIP servers or DOM APIs required.
 */
export const executeViaCircleUsdcPaymaster = async (
  params: ExecuteViaCirclePaymasterParams,
): Promise<ExecuteViaCirclePaymasterResult> => {
  const {
    signerKey,
    calls,
    publicClient,
    reservedUsdcUnits = 0n,
    bundlerUrls = PUBLIC_BASE_BUNDLERS,
    bundlerFetch,
    usdcToken = PAYMASTER_BASE_USDC_TOKEN,
    paymasterAddress = CIRCLE_USDC_PAYMASTER_V08,
    chainId = PAYMASTER_BASE_CHAIN_ID_BIG,
    disableBuilderAttribution = false,
    pollTimeoutMs = 25_000,
    pollIntervalMs = 1_500,
    onStatus,
  } = params;

  const pkNorm = (signerKey.startsWith('0x') ? signerKey : `0x${signerKey}`) as Hex;
  const account = privateKeyToAccount(pkNorm);
  const sender = getAddress(account.address);
  if (sender.toLowerCase() === COMPROMISED_SIGNER_LOWER) {
    throw new Error('Compromised signer key is permanently refused.');
  }
  if (bundlerUrls.length === 0) {
    throw new Error('At least one ERC-4337 bundler URL is required.');
  }

  const usdcAddr = getAddress(usdcToken);
  const pmAddr = getAddress(paymasterAddress);

  const [usdcBal, usdcNonce, uoNonce, senderCodeRaw, eoaTxCount, pmPaused, fees] = await Promise.all([
    publicClient.readContract({
      address: usdcAddr,
      abi: USDC_PERMIT_READ_ABI,
      functionName: 'balanceOf',
      args: [sender],
    }),
    publicClient.readContract({
      address: usdcAddr,
      abi: USDC_PERMIT_READ_ABI,
      functionName: 'nonces',
      args: [sender],
    }),
    publicClient.readContract({
      address: PAYMASTER_ENTRY_POINT_V08,
      abi: ENTRY_POINT_V08_ABI,
      functionName: 'getNonce',
      args: [sender, 0n],
    }),
    publicClient.getCode({ address: sender }),
    publicClient.getTransactionCount({ address: sender, blockTag: 'pending' }),
    publicClient.readContract({
      address: pmAddr,
      abi: PAYMASTER_READ_ABI,
      functionName: 'paused',
    }),
    publicClient.estimateFeesPerGas().catch(() => null),
  ]);

  const senderCode = senderCodeRaw ?? '0x';
  if (pmPaused) {
    throw new Error('Circle USDC Paymaster is temporarily paused on Base.');
  }
  if (!isPersonalOrCanonical7702Code(senderCode)) {
    throw new Error('Wallet has non-standard contract delegation; skipping Circle Paymaster.');
  }
  const availableGasUsdc = usdcBal > reservedUsdcUnits ? usdcBal - reservedUsdcUnits : 0n;
  if (availableGasUsdc < MIN_CIRCLE_PAYMASTER_USDC_UNITS) {
    throw new Error('Not enough unreserved USDC in wallet to cover the ~$0.01 Base network fee.');
  }

  const permitAmount =
    availableGasUsdc < MAX_CIRCLE_PAYMASTER_PERMIT_UNITS
      ? availableGasUsdc
      : MAX_CIRCLE_PAYMASTER_PERMIT_UNITS;

  const rawCallData = encodeSimple7702Calls(calls);
  const callData = appendPaymasterBuilderSuffix(rawCallData, calls, disableBuilderAttribution);

  const alreadyDelegated = senderCode.toLowerCase() === CANONICAL_SIMPLE_7702_DELEGATION_CODE;

  let eip7702AuthPayload: Record<string, string> | undefined;
  let signedPermitData: Hex | null = null;
  const dummyPaymasterData = encodeCirclePaymasterV08Data(
    permitAmount,
    STATIC_ERC4337_DUMMY_SIG,
    usdcAddr,
  );

  const sign7702IfNeeded = async (): Promise<void> => {
    if (alreadyDelegated || eip7702AuthPayload) return;
    const auth = await signAuthorization({
      contractAddress: PAYMASTER_SIMPLE_7702_ACCOUNT,
      chainId: Number(chainId),
      nonce: eoaTxCount,
      privateKey: pkNorm,
    });
    const yParityNum =
      auth.yParity !== undefined
        ? Number(auth.yParity)
        : auth.v !== undefined
          ? Number(auth.v) >= 27
            ? Number(auth.v) - 27
            : Number(auth.v)
          : 0;
    eip7702AuthPayload = {
      address: getAddress(auth.address),
      chainId: toRpcQuantity(auth.chainId),
      nonce: toRpcQuantity(auth.nonce),
      r: auth.r,
      s: auth.s,
      yParity: toRpcQuantity(yParityNum),
    };
  };

  const signUsdcPermitIfNeeded = async (): Promise<Hex> => {
    if (signedPermitData) return signedPermitData;
    onStatus?.('Signing permissionless USDC gas permit…');
    const permitSignature = await account.signTypedData({
      domain: {
        name: 'USD Coin',
        version: '2',
        chainId: Number(chainId),
        verifyingContract: usdcAddr,
      },
      types: USDC_EIP2612_TYPES,
      primaryType: 'Permit',
      message: {
        owner: sender,
        spender: pmAddr,
        value: permitAmount,
        nonce: usdcNonce,
        deadline: maxUint256,
      },
    });
    signedPermitData = encodeCirclePaymasterV08Data(permitAmount, permitSignature, usdcAddr);
    return signedPermitData;
  };

  let lastError: unknown = null;

  for (const bundlerUrl of bundlerUrls) {
    let submittedToBundler = false;
    try {
      let maxPriorityFeePerGas =
        fees?.maxPriorityFeePerGas && fees.maxPriorityFeePerGas * 2n > 1_100_000n
          ? fees.maxPriorityFeePerGas * 2n
          : 1_100_000n;
      let maxFeePerGas =
        fees?.maxFeePerGas && fees.maxFeePerGas * 2n > 15_000_000n
          ? fees.maxFeePerGas * 2n
          : 15_000_000n;

      try {
        const pimlicoFee = (await callBundlerRpc(
          bundlerUrl,
          'pimlico_getUserOperationGasPrice',
          [],
          3_500,
          bundlerFetch,
        )) as
          | {
              fast?: { maxFeePerGas?: string; maxPriorityFeePerGas?: string };
              standard?: { maxFeePerGas?: string; maxPriorityFeePerGas?: string };
            }
          | undefined;
        const fast = pimlicoFee?.fast ?? pimlicoFee?.standard;
        if (fast?.maxFeePerGas && fast?.maxPriorityFeePerGas) {
          const bMax = BigInt(fast.maxFeePerGas);
          const bPrio = BigInt(fast.maxPriorityFeePerGas);
          if (bMax > 0n) maxFeePerGas = bMax;
          if (bPrio > 0n) maxPriorityFeePerGas = bPrio;
        }
      } catch {
        // Non-Pimlico bundlers (e.g. Candide) do not expose pimlico_getUserOperationGasPrice
      }
      if (maxFeePerGas < maxPriorityFeePerGas) {
        maxFeePerGas = maxPriorityFeePerGas * 2n;
      }

      const buildDraftOp = (
        pmData: Hex,
        authPayload?: Record<string, string>,
      ): Record<string, unknown> => ({
        sender,
        nonce: toRpcQuantity(uoNonce),
        ...(!alreadyDelegated ? { factory: '0x7702', factoryData: '0x' } : {}),
        callData,
        callGasLimit: toRpcQuantity(350_000n),
        verificationGasLimit: toRpcQuantity(180_000n),
        preVerificationGas: toRpcQuantity(100_000n),
        maxFeePerGas: toRpcQuantity(maxFeePerGas),
        maxPriorityFeePerGas: toRpcQuantity(maxPriorityFeePerGas),
        paymaster: pmAddr,
        paymasterVerificationGasLimit: toRpcQuantity(180_000n),
        paymasterPostOpGasLimit: toRpcQuantity(65_000n),
        paymasterData: pmData,
        signature: STATIC_ERC4337_DUMMY_SIG,
        ...(authPayload ? { eip7702Auth: authPayload } : {}),
      });

      type BundlerGasEstimate = {
        callGasLimit?: string | number | bigint;
        verificationGasLimit?: string | number | bigint;
        preVerificationGas?: string | number | bigint;
        paymasterVerificationGasLimit?: string | number | bigint;
        paymasterPostOpGasLimit?: string | number | bigint;
      };
      let estimated: BundlerGasEstimate | null = null;

      try {
        estimated = (await callBundlerRpc(
          bundlerUrl,
          'eth_estimateUserOperationGas',
          [
            buildDraftOp(dummyPaymasterData, alreadyDelegated ? undefined : eip7702AuthPayload),
            PAYMASTER_ENTRY_POINT_V08,
          ],
          6_500,
          bundlerFetch,
        )) as BundlerGasEstimate | null;
      } catch {
        await sign7702IfNeeded();
        const livePmData = await signUsdcPermitIfNeeded();
        estimated = (await callBundlerRpc(
          bundlerUrl,
          'eth_estimateUserOperationGas',
          [buildDraftOp(livePmData, eip7702AuthPayload), PAYMASTER_ENTRY_POINT_V08],
          6_500,
          bundlerFetch,
        )) as BundlerGasEstimate | null;
      }

      await sign7702IfNeeded();
      const paymasterData = await signUsdcPermitIfNeeded();

      const callGasLimit = addGasBuffer(estimated?.callGasLimit, 220_000n);
      const verificationGasLimit = addGasBuffer(estimated?.verificationGasLimit, 130_000n);
      const preVerificationGas = addGasBuffer(estimated?.preVerificationGas, 65_000n);
      const paymasterVerificationGasLimit = addGasBuffer(
        estimated?.paymasterVerificationGasLimit,
        130_000n,
      );
      const paymasterPostOpGasLimit = addGasBuffer(
        estimated?.paymasterPostOpGasLimit,
        60_000n,
        11_500n,
      );

      const userOpHash = computeUserOpHashV08({
        sender,
        nonce: uoNonce,
        callData,
        verificationGasLimit,
        callGasLimit,
        preVerificationGas,
        maxPriorityFeePerGas,
        maxFeePerGas,
        paymaster: pmAddr,
        paymasterVerificationGasLimit,
        paymasterPostOpGasLimit,
        paymasterData,
        use7702Factory: !alreadyDelegated,
        delegateAddress: PAYMASTER_SIMPLE_7702_ACCOUNT,
        chainId,
      });

      // Raw secp256k1 signature over the 32-byte EIP-712 userOpHash (zero EIP-191 prefix, matching Simple7702Account)
      const signature = await sign({ hash: userOpHash, privateKey: pkNorm, to: 'hex' });

      const signedOp: Record<string, unknown> = {
        sender,
        nonce: toRpcQuantity(uoNonce),
        ...(!alreadyDelegated ? { factory: '0x7702', factoryData: '0x' } : {}),
        callData,
        callGasLimit: toRpcQuantity(callGasLimit),
        verificationGasLimit: toRpcQuantity(verificationGasLimit),
        preVerificationGas: toRpcQuantity(preVerificationGas),
        maxFeePerGas: toRpcQuantity(maxFeePerGas),
        maxPriorityFeePerGas: toRpcQuantity(maxPriorityFeePerGas),
        paymaster: pmAddr,
        paymasterVerificationGasLimit: toRpcQuantity(paymasterVerificationGasLimit),
        paymasterPostOpGasLimit: toRpcQuantity(paymasterPostOpGasLimit),
        paymasterData,
        signature,
        ...(eip7702AuthPayload ? { eip7702Auth: eip7702AuthPayload } : {}),
      };

      onStatus?.('Submitting via permissionless USDC paymaster…');
      const submittedHash = await callBundlerRpc(
        bundlerUrl,
        'eth_sendUserOperation',
        [signedOp, PAYMASTER_ENTRY_POINT_V08],
        8_000,
        bundlerFetch,
      );
      submittedToBundler = true;
      const effectiveUoHash: Hex =
        typeof submittedHash === 'string' && /^0x[0-9a-fA-F]{64}$/.test(submittedHash)
          ? (submittedHash as Hex)
          : userOpHash;

      const deadlineMs = Date.now() + pollTimeoutMs;
      while (Date.now() < deadlineMs) {
        const uoReceipt = (await callBundlerRpc(
          bundlerUrl,
          'eth_getUserOperationReceipt',
          [effectiveUoHash],
          4_000,
          bundlerFetch,
        ).catch(() => null)) as {
          success?: boolean;
          receipt?: { transactionHash?: string };
        } | null;

        if (uoReceipt?.receipt?.transactionHash) {
          if (uoReceipt.success === false) {
            throw new Error('It did not go through. Nothing was moved. Please try again.');
          }
          return {
            txHash: uoReceipt.receipt.transactionHash as Hex,
            userOpHash: effectiveUoHash,
            bundlerUrl,
          };
        }
        await new Promise((r) => setTimeout(r, pollIntervalMs));
      }
      throw new PaymasterPendingError(effectiveUoHash, bundlerUrl);
    } catch (err: unknown) {
      lastError = err;
      const msg = err instanceof Error ? err.message : String(err ?? '');
      if (
        submittedToBundler ||
        err instanceof PaymasterPendingError ||
        msg.includes('Nothing was moved') ||
        msg.includes('UserOperation submitted') ||
        /AA23|AA24|InvalidSlipStatus|CancelLocked|InvalidSignature/i.test(msg)
      ) {
        throw err;
      }
    }
  }

  throw lastError instanceof Error
    ? lastError
    : new Error('Permissionless USDC paymaster bundlers could not be reached.');
};

// ============================================================================
// Tier-1 Edge Relay Client + V-04 3-Tier Gasless Transport Router
// ============================================================================

const isPrivateOrLoopbackHost = (hostname: string): boolean => {
  const h = hostname.toLowerCase();
  if (
    h === 'localhost' ||
    h === '127.0.0.1' ||
    h === '[::1]' ||
    h === '0.0.0.0' ||
    h.endsWith('.local') ||
    h.endsWith('.internal')
  ) {
    return true;
  }
  if (
    h.startsWith('127.') ||
    h.startsWith('10.') ||
    h.startsWith('192.168.') ||
    h.startsWith('169.254.')
  ) {
    return true;
  }
  const m172 = /^172\.(\d{1,3})\./.exec(h);
  if (m172) {
    const second = Number(m172[1]);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
};

const containsLeakedSlipKeyMarker = (raw: string): boolean =>
  /(?:^|[^0-9a-zA-Z])(?:k(?:0x)?[0-9a-f]{64}|s[0-9a-f]{48})(?:[^0-9a-f]|$)/i.test(raw) ||
  /(?:^|[#&?])seal=[A-Za-z0-9_-]{40,120}(?:[&#]|$)/i.test(raw);

export const sanitizeRelayGatewayUrl = (raw: string, allowLocalhost = false): string => {
  const parsed = new URL(raw.trim());
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname.toLowerCase());
  if (
    (parsed.protocol !== 'https:' && !(allowLocalhost && loopback && parsed.protocol === 'http:')) ||
    (!allowLocalhost && isPrivateOrLoopbackHost(parsed.hostname)) ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error('Relay gateway URL must use HTTPS without credentials, query, or fragment.');
  }
  return parsed.toString().replace(/\/$/, '');
};

export interface RelayGatewayClientConfig {
  gatewayUrls?: readonly string[];
  partnerKey?: string;
  telegramInitData?: string;
  allowLocalhost?: boolean;
  timeoutMs?: number;
  fetchFn?: typeof fetch;
}

export interface RelayPostResult {
  txHash: Hex;
  gatewayUrl: string;
  duplicate?: boolean;
}

/**
 * Multi-origin Edge Relay client (`https://cryptoslip-edge.naraprotocol.workers.dev` -> `https://relay1.cryptoslip.tech`)
 * supporting `X-CryptoSLIP-Partner-Key`, verified `X-Telegram-Init-Data`, SSRF validation, and claim-key leak guards.
 */
export class RelayGatewayClient {
  readonly gatewayUrls: readonly string[];
  readonly partnerKey?: string;
  readonly telegramInitData?: string;
  readonly timeoutMs: number;
  private readonly fetchFn: typeof fetch;
  private readonly recentGatewayFailures = new Map<string, number>();

  constructor(config: RelayGatewayClientConfig = {}) {
    const rawUrls =
      config.gatewayUrls && config.gatewayUrls.length > 0
        ? config.gatewayUrls
        : PRODUCTION_EDGE_GATEWAYS;
    const seen = new Set<string>();
    const validated: string[] = [];
    for (const u of rawUrls) {
      const clean = sanitizeRelayGatewayUrl(u, Boolean(config.allowLocalhost));
      if (!seen.has(clean.toLowerCase())) {
        seen.add(clean.toLowerCase());
        validated.push(clean);
      }
    }
    if (validated.length === 0) {
      throw new Error('At least one valid relay gateway URL is required.');
    }
    this.gatewayUrls = Object.freeze(validated);

    if (config.partnerKey && config.partnerKey.trim()) {
      this.partnerKey = config.partnerKey.trim();
    }
    if (config.telegramInitData && config.telegramInitData.trim()) {
      if (containsLeakedSlipKeyMarker(config.telegramInitData)) {
        throw new Error('Refusing Telegram initData containing an unredacted slip secret.');
      }
      this.telegramInitData = config.telegramInitData.trim();
    }
    this.timeoutMs = config.timeoutMs ?? 18_000;
    this.fetchFn = config.fetchFn ?? ((input, init) => globalThis.fetch(input, init));
  }

  private orderedGateways(nowMs = Date.now()): string[] {
    const healthy: string[] = [];
    const cooling: string[] = [];
    for (const g of this.gatewayUrls) {
      const failedAt = this.recentGatewayFailures.get(g) ?? 0;
      if (failedAt + 60_000 <= nowMs) healthy.push(g);
      else cooling.push(g);
    }
    return [...healthy, ...cooling];
  }

  async postRelay(
    path: string,
    body: Record<string, unknown>,
    options?: { partnerKey?: string; telegramInitData?: string; timeoutMs?: number },
  ): Promise<RelayPostResult> {
    const cleanPath = path.startsWith('/') ? path : `/${path}`;
    const serialized = JSON.stringify(body);
    if (containsLeakedSlipKeyMarker(serialized)) {
      throw new Error('Security violation: relay request body must never contain a slip claim key.');
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    const effectivePartnerKey = options?.partnerKey?.trim() || this.partnerKey;
    if (effectivePartnerKey) {
      headers['X-CryptoSLIP-Partner-Key'] = effectivePartnerKey;
    }
    const effectiveTgData = options?.telegramInitData?.trim() || this.telegramInitData;
    if (effectiveTgData) {
      if (containsLeakedSlipKeyMarker(effectiveTgData)) {
        throw new Error('Refusing Telegram initData containing an unredacted slip secret.');
      }
      headers['X-Telegram-Init-Data'] = effectiveTgData;
    }

    const candidates = this.orderedGateways();
    let lastUnavailable: RelayUnavailableError | null = null;

    for (const gatewayUrl of candidates) {
      const ctrl = new AbortController();
      const timeoutMs = options?.timeoutMs ?? this.timeoutMs;
      const timer = setTimeout(() => ctrl.abort(), timeoutMs);
      try {
        const resp = await this.fetchFn(`${gatewayUrl}${cleanPath}`, {
          method: 'POST',
          headers,
          body: serialized,
          redirect: 'error',
          signal: ctrl.signal,
        });
        const contentType = (resp.headers.get('content-type') ?? '').toLowerCase();
        if (!contentType.includes('application/json')) {
          this.recentGatewayFailures.set(gatewayUrl, Date.now());
          lastUnavailable = new RelayUnavailableError(
            `Gateway ${gatewayUrl} returned non-JSON response`,
            true,
            resp.status,
          );
          continue;
        }
        const data = (await resp.json().catch(() => ({}))) as {
          ok?: boolean;
          txHash?: string;
          duplicate?: boolean;
          error?: string;
        };

        if (
          resp.status === 404 ||
          resp.status === 405 ||
          resp.status === 408 ||
          resp.status === 429 ||
          resp.status === 451 ||
          (resp.status === 503 && !/pending/i.test(String(data?.error ?? '')))
        ) {
          this.recentGatewayFailures.set(gatewayUrl, Date.now());
          lastUnavailable = new RelayUnavailableError(
            data?.error || `Relay gateway unavailable (HTTP ${resp.status})`,
            true,
            resp.status,
          );
          continue;
        }

        if (resp.status >= 500) {
          this.recentGatewayFailures.set(gatewayUrl, Date.now());
          lastUnavailable = new RelayUnavailableError(
            data?.error || `Relay gateway error (HTTP ${resp.status})`,
            false,
            resp.status,
          );
          continue;
        }

        if (!resp.ok || !data?.ok || !data?.txHash || !/^0x[0-9a-fA-F]{64}$/.test(data.txHash)) {
          throw new RelayRejectedError(
            resp.status,
            data?.error || `Relay rejected request with HTTP ${resp.status}`,
          );
        }

        this.recentGatewayFailures.delete(gatewayUrl);
        return {
          txHash: data.txHash as Hex,
          gatewayUrl,
          ...(data.duplicate !== undefined ? { duplicate: data.duplicate } : {}),
        };
      } catch (err) {
        if (err instanceof RelayRejectedError) {
          throw err;
        }
        this.recentGatewayFailures.set(gatewayUrl, Date.now());
        lastUnavailable =
          err instanceof RelayUnavailableError
            ? err
            : new RelayUnavailableError(
                err instanceof Error ? err.message : 'Relay network request failed',
                false,
              );
      } finally {
        clearTimeout(timer);
      }
    }

    throw (
      lastUnavailable ??
      new RelayUnavailableError('All configured CryptoSLIP Edge Relay gateways are unreachable.')
    );
  }
}

export type GaslessTransportMode = 'human' | 'agent' | 'partner';
export type GaslessTransportTier = 'relay' | 'circle_paymaster' | 'direct_eoa';
export type GaslessOperationKind =
  | 'boot_keep'
  | 'keep'
  | 'claim'
  | 'split'
  | 'combine'
  | 'mint'
  | 'refund'
  | 'swap';

export interface V04TransportPolicyInput {
  mode?: GaslessTransportMode;
  telegramInitData?: string;
  partnerKey?: string;
  operationKind?: GaslessOperationKind;
  /** Estimated operation value in 6-decimal micro-USD (`100_000n` == `$0.10`). Defaults to `100_000n`. */
  estimatedUsdMicro?: bigint;
  /** Testing/override escape hatch; never enabled by default in `agent` mode (`V-04`). */
  allowHumanRelayInAgentMode?: boolean;
}

export interface V04TransportPlan {
  effectiveMode: GaslessTransportMode;
  allowEdgeRelay: boolean;
  tiers: readonly GaslessTransportTier[];
  reason: string;
}

/**
 * Deterministic `V-04` transport planner:
 * - When `mode === 'agent'` (or headless with neither `telegramInitData` nor `partnerKey`),
 *   operations `>= $0.10 USDC` (`100_000n` micro-USD) NEVER consume free human Edge Relay ETH quotas
 *   (except 1st-boot `boot_keep` rotation per Roadmap `V-01`/`V-04`), defaulting strictly to
 *   Circle `TokenPaymasterV08` (`USDC` gas) or direct Base EOA submission.
 * - Authenticated `partner` (`X-CryptoSLIP-Partner-Key`) and `human` flows use the full 3-tier
 *   cascade: `relay` -> `circle_paymaster` -> `direct_eoa`.
 */
export const resolveV04TransportPlan = (input: V04TransportPolicyInput = {}): V04TransportPlan => {
  const hasPartnerKey = Boolean(input.partnerKey && input.partnerKey.trim().length > 0);
  const hasTgInit = Boolean(input.telegramInitData && input.telegramInitData.trim().length > 0);

  const effectiveMode: GaslessTransportMode =
    input.mode === 'partner' || (input.mode === undefined && hasPartnerKey)
      ? 'partner'
      : input.mode === 'agent'
        ? 'agent'
        : input.mode === 'human'
          ? hasTgInit || hasPartnerKey
            ? 'human'
            : 'human'
          : hasTgInit
            ? 'human'
            : 'agent';

  // V-04 enforcement: if mode === 'agent' and no telegramInitData and no partnerKey, block free relay on >= $0.10 ops
  if (effectiveMode === 'agent' && !hasTgInit && !hasPartnerKey) {
    if (input.operationKind === 'boot_keep') {
      return {
        effectiveMode: 'agent',
        allowEdgeRelay: true,
        tiers: ['relay', 'circle_paymaster', 'direct_eoa'],
        reason: 'V-01/V-04: initial boot_keep rotation is permitted to use Edge Relay before local USDC/ETH exists.',
      };
    }
    const usdMicro = input.estimatedUsdMicro ?? MIN_CIRCLE_PAYMASTER_USDC_UNITS;
    if (usdMicro >= MIN_CIRCLE_PAYMASTER_USDC_UNITS && !input.allowHumanRelayInAgentMode) {
      return {
        effectiveMode: 'agent',
        allowEdgeRelay: false,
        tiers: ['circle_paymaster', 'direct_eoa'],
        reason:
          'V-04: headless agent >= $0.10 operation defaults to Circle TokenPaymasterV08 or direct Base tx so bots never drain human relay ETH quotas.',
      };
    }
    if (usdMicro < MIN_CIRCLE_PAYMASTER_USDC_UNITS && !input.allowHumanRelayInAgentMode) {
      return {
        effectiveMode: 'agent',
        allowEdgeRelay: false,
        tiers: ['circle_paymaster', 'direct_eoa'],
        reason:
          'V-04: sub-$0.10 agent operation uses Circle TokenPaymasterV08 (if wallet holds >= $0.10 USDC) or direct Base tx.',
      };
    }
  }

  return {
    effectiveMode,
    allowEdgeRelay: true,
    tiers: ['relay', 'circle_paymaster', 'direct_eoa'],
    reason:
      effectiveMode === 'partner'
        ? 'Authenticated partner key uses Partner Relay -> Circle Paymaster -> Direct EOA failover.'
        : 'Human flow uses Sponsored Edge Relay -> Circle Paymaster -> Direct EOA failover.',
  };
};

export interface ExecuteGaslessTransportParams extends V04TransportPolicyInput {
  relayClient?: RelayGatewayClient;
  relayPath?: string;
  relayBody?: Record<string, unknown>;
  calls: readonly UserOpCall[];
  publicClient: BaseCompatiblePublicClient;
  /** Optional 32-byte EOA key for Tier-2 Circle `TokenPaymasterV08` self-sponsored USDC UserOps. */
  paymasterSignerKey?: Hex;
  reservedUsdcUnits?: bigint;
  bundlerUrls?: readonly string[];
  bundlerFetch?: BundlerFetchFn;
  /** Optional `viem` WalletClient or custom sender callback for Tier-3 direct Base EOA broadcast. */
  walletClient?: BaseCompatibleWalletClient;
  directBroadcast?: (attributedCall: UserOpCall) => Promise<Hex>;
  disableBuilderAttribution?: boolean;
  onStatus?: (msg: string) => void;
}

export interface ExecuteGaslessTransportResult {
  txHash: Hex;
  tier: GaslessTransportTier;
  gatewayUrl?: string;
  bundlerUrl?: string;
  userOpHash?: Hex;
}

/**
 * Executes an on-chain Slip call across the 3-Tier Gasless Transport cascade while strictly enforcing `V-04`:
 * - Tier 1: Edge Relay (`cryptoslip-edge` -> `relay1.cryptoslip.tech`) when allowed by `resolveV04TransportPlan`
 * - Tier 2: Serverless Circle `TokenPaymasterV08` (`USDC` gas via ERC-4337 v0.8 + `Simple7702Account`)
 * - Tier 3: Direct Base EOA transaction (with `bc_ea68lz8s` ERC-8021 attribution suffix)
 */
export const executeGaslessTransport = async (
  params: ExecuteGaslessTransportParams,
): Promise<ExecuteGaslessTransportResult> => {
  const plan = resolveV04TransportPlan(params);
  let lastError: unknown = null;

  for (const tier of plan.tiers) {
    if (tier === 'relay') {
      if (!params.relayPath || !params.relayBody) continue;
      const client =
        params.relayClient ??
        new RelayGatewayClient({
          partnerKey: params.partnerKey,
          telegramInitData: params.telegramInitData,
        });
      try {
        params.onStatus?.('Submitting via CryptoSLIP Edge Relay…');
        const res = await client.postRelay(params.relayPath, params.relayBody, {
          partnerKey: params.partnerKey,
          telegramInitData: params.telegramInitData,
        });
        return {
          txHash: res.txHash,
          tier: 'relay',
          gatewayUrl: res.gatewayUrl,
        };
      } catch (err) {
        if (err instanceof RelayRejectedError) {
          throw err;
        }
        lastError = err;
      }
    } else if (tier === 'circle_paymaster') {
      if (!params.paymasterSignerKey || params.calls.length === 0) continue;
      const pkNorm = (
        params.paymasterSignerKey.startsWith('0x')
          ? params.paymasterSignerKey
          : `0x${params.paymasterSignerKey}`
      ) as Hex;
      const sender = privateKeyToAccount(pkNorm).address;
      const eligibility = await canSponsorWithCircleUsdcPaymaster({
        userAddress: sender,
        publicClient: params.publicClient,
        reservedUsdcUnits: params.reservedUsdcUnits ?? 0n,
      });
      if (!eligibility.ok) {
        lastError =
          lastError ??
          new Error('Wallet lacks >= $0.10 unreserved USDC for Circle TokenPaymasterV08.');
        continue;
      }
      try {
        const pmRes = await executeViaCircleUsdcPaymaster({
          signerKey: pkNorm,
          calls: params.calls,
          publicClient: params.publicClient,
          reservedUsdcUnits: params.reservedUsdcUnits ?? 0n,
          bundlerUrls: params.bundlerUrls,
          bundlerFetch: params.bundlerFetch,
          disableBuilderAttribution: params.disableBuilderAttribution,
          onStatus: params.onStatus,
        });
        return {
          txHash: pmRes.txHash,
          tier: 'circle_paymaster',
          bundlerUrl: pmRes.bundlerUrl,
          userOpHash: pmRes.userOpHash,
        };
      } catch (err) {
        if (err instanceof PaymasterPendingError) {
          throw err;
        }
        lastError = err;
      }
    } else if (tier === 'direct_eoa') {
      if (params.calls.length === 0) continue;
      if (params.directBroadcast) {
        if (params.calls.length !== 1) {
          lastError = new Error('directBroadcast callback supports single-target calls; use Multicall3 or Simple7702Account for multi-call.');
          continue;
        }
        const single = params.calls[0]!;
        const attributedData = appendPaymasterBuilderSuffix(
          single.data,
          [single],
          Boolean(params.disableBuilderAttribution),
        );
        const txHash = await params.directBroadcast({
          to: single.to,
          value: single.value,
          data: attributedData,
        });
        return { txHash, tier: 'direct_eoa' };
      }

      const wc = params.walletClient;
      const account =
        wc?.account ??
        (params.paymasterSignerKey
          ? privateKeyToAccount(
              (params.paymasterSignerKey.startsWith('0x')
                ? params.paymasterSignerKey
                : `0x${params.paymasterSignerKey}`) as Hex,
            )
          : undefined);
      if (!wc || !account) continue;

      const ethBal = await params.publicClient
        .getBalance({ address: account.address })
        .catch(() => 0n);
      if (ethBal < MIN_SELF_GAS_BALANCE_WEI) {
        lastError =
          lastError ??
          new Error('Wallet lacks ETH (>= 0.000025 ETH) and USDC paymaster eligibility for direct Base submission.');
        continue;
      }
      if (params.calls.length !== 1) {
        lastError = new Error('Direct non-7702 EOA submission supports a single call; pack ERC-20 calls via Multicall3 first.');
        continue;
      }
      const call = params.calls[0]!;
      const attributedData = appendPaymasterBuilderSuffix(
        call.data,
        [call],
        Boolean(params.disableBuilderAttribution),
      );
      params.onStatus?.('Submitting directly on Base…');
      const txHash = await wc.sendTransaction({
        account,
        chain: wc.chain ?? null,
        to: getAddress(call.to),
        value: call.value ?? 0n,
        data: attributedData,
      });
      return { txHash, tier: 'direct_eoa' };
    }
  }

  throw lastError instanceof Error
    ? lastError
    : new Error(`No eligible transport succeeded (${plan.reason})`);
};
