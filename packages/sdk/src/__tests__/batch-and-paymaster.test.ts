import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Wallet } from 'ethers';
import {
  createPublicClient,
  createWalletClient,
  decodeAbiParameters,
  decodeFunctionData,
  encodeAbiParameters,
  encodeEventTopics,
  encodeFunctionData,
  fallback,
  getAddress,
  http,
  keccak256,
  parseAbi,
  parseAbiParameters,
  stringToHex,
  type Address,
  type Hex,
  type PublicClient,
} from 'viem';
import { privateKeyToAccount, sign } from 'viem/accounts';
import { base } from 'viem/chains';
import { describe, expect, it } from 'vitest';
import { CRYPTO_SLIP_VAULT_V32_ABI, MULTICALL3_ABI } from '../abi.js';
import {
  assertCreatorBindingPreserved,
  BatchValidationError,
  CreatorBindingViolationError,
  exportMintedSlipsCsv,
  exportMintedSlipsJson,
  generateBatchClaimCredentials,
  parseMintedSlipsFromReceipt,
  prepareBatchPayoutSlips,
  preparePayoutSlip,
  type ExecuteBatchPayoutOptions,
} from '../batch.js';
import {
  appendBuilderCodeSuffix,
  CANONICAL_VAULT_V33_ADDRESS,
  CIRCLE_USDC_PAYMASTER_V08,
  computeProtocolFeeCeiling,
  DEFAULT_BASE_RPC_URLS,
  DEFAULT_CRYPTOSLIP_BUILDER_CODE,
  ENTRY_POINT_V08,
  ERC8021_MARKER_HEX,
  MULTICALL3_ADDRESS,
  NARA_BASE_ADDRESS,
  NARA_IN_APP_BUILDER_CODES,
  NARA_LIQUIDITY_HOOK_V5_ADDRESS,
  NO_TAKE_BACK_LOCK,
  SIMPLE_7702_ACCOUNT,
  SlipStatus,
  toErc8021DataSuffix,
  UNIVERSAL_ROUTER_ADDRESS,
  USDC_BASE_ADDRESS,
  V33_VAULT_DOMAIN_SEPARATOR,
  ZERO_ADDRESS,
} from '../constants.js';
import { deriveCodeWallet, parseSlipUrl } from '../link.js';
import {
  assertCanonicalNaraV4SwapCalldata,
  claimSlip,
  combineSlips,
  DustCliffError,
  keepSlip,
  NonCanonicalNaraSwapError,
  planCombineSlipBuckets,
  readOnChainSlip,
  refundSlipDirect,
  resolveSplitPaymentWithDustCheck,
  scanReclaimableSlips,
  SlipMutex,
  splitAndPay,
  withdrawReferralCredits,
  type KeepSlipOptions,
  type SplitAndPayOptions,
} from '../operations.js';
import {
  canSponsorWithCircleUsdcPaymaster,
  computeUserOpHashV08,
  encodeCirclePaymasterV08Data,
  encodePaymasterAndDataV08,
  encodeSimple7702Calls,
  executeGaslessTransport,
  executeViaCircleUsdcPaymaster,
  PAYMASTER_TOKEN_ADDRESS_OFFSET,
  PaymasterPendingError,
  RelayGatewayClient,
  RelayRejectedError,
  resolveV04TransportPlan,
  STATIC_ERC4337_DUMMY_SIG,
  type BaseCompatiblePublicClient,
  type BaseCompatibleWalletClient,
} from '../paymaster.js';
import { createPolicyGuardedSigner, PolicyViolationError } from '../policy.js';

// Runtime-derived deterministic test keys (ZERO hardcoded 64-hex private key literals in source!)
const deriveTestKey = (seed: string): Hex => keccak256(stringToHex(seed));

const PARTNER_KEY = deriveTestKey('batch-test-key-1');
const CREATOR_B_KEY = deriveTestKey('batch-test-key-2');
const CREATOR_C_KEY = deriveTestKey('batch-test-key-3');
const RECIPIENT_KEY = deriveTestKey('batch-test-key-recipient');
const MERCHANT_KEY = deriveTestKey('batch-test-key-merchant');
const EPHEMERAL_SLIP_KEY_1 = deriveTestKey('batch-test-ephemeral-1');
const EPHEMERAL_SLIP_KEY_2 = deriveTestKey('batch-test-ephemeral-2');
const EPHEMERAL_SLIP_KEY_3 = deriveTestKey('batch-test-ephemeral-3');

const PARTNER_ACCOUNT = privateKeyToAccount(PARTNER_KEY);
const CREATOR_B_ACCOUNT = privateKeyToAccount(CREATOR_B_KEY);
const CREATOR_C_ACCOUNT = privateKeyToAccount(CREATOR_C_KEY);
const RECIPIENT_ACCOUNT = privateKeyToAccount(RECIPIENT_KEY);
const MERCHANT_ACCOUNT = privateKeyToAccount(MERCHANT_KEY);
const EPHEMERAL_1 = privateKeyToAccount(EPHEMERAL_SLIP_KEY_1);
const EPHEMERAL_2 = privateKeyToAccount(EPHEMERAL_SLIP_KEY_2);
const EPHEMERAL_3 = privateKeyToAccount(EPHEMERAL_SLIP_KEY_3);

const stripErc8021Suffix = (data: Hex, codes: string | readonly string[]): Hex => {
  const suffix = toErc8021DataSuffix(codes);
  if (!suffix) return data;
  const suffixNoPrefix = suffix.slice(2).toLowerCase();
  expect(data.toLowerCase().endsWith(suffixNoPrefix)).toBe(true);
  return data.slice(0, data.length - suffixNoPrefix.length) as Hex;
};

function buildCanonicalNaraV4SwapCalldata(options?: {
  hookAddress?: Address;
  zeroForOne?: boolean;
  amountIn?: bigint;
  minOut?: bigint;
  allowRevertFlag?: boolean;
  useV3CommandForNara?: boolean;
}): Hex {
  const urAbi = parseAbi([
    'function execute(bytes commands, bytes[] inputs, uint256 deadline)',
  ]);
  const hook = options?.hookAddress ?? NARA_LIQUIDITY_HOOK_V5_ADDRESS;
  const zeroForOne = options?.zeroForOne ?? true;
  const amountIn = options?.amountIn ?? 10_000_000n;
  const minOut = options?.minOut ?? 9_000_000_000_000_000_000n;

  if (options?.useV3CommandForNara) {
    const v3Path =
      `${USDC_BASE_ADDRESS.toLowerCase()}000bb8${NARA_BASE_ADDRESS.slice(2).toLowerCase()}` as Hex;
    const v3Input = encodeAbiParameters(
      parseAbiParameters(
        'address recipient, uint256 amountIn, uint256 amountOutMin, bytes path, bool payerIsUser',
      ),
      ['0x0000000000000000000000000000000000000001', amountIn, minOut, v3Path, false],
    );
    return encodeFunctionData({
      abi: urAbi,
      functionName: 'execute',
      args: ['0x00', [v3Input], 1_900_000_000n],
    });
  }

  const singleParam = encodeAbiParameters(
    parseAbiParameters(
      '((address currency0, address currency1, uint24 fee, int24 tickSpacing, address hooks) poolKey, bool zeroForOne, uint128 amountIn, uint128 amountOutMinimum, bytes hookData)',
    ),
    [
      {
        poolKey: {
          currency0: USDC_BASE_ADDRESS,
          currency1: NARA_BASE_ADDRESS,
          fee: 3000,
          tickSpacing: 60,
          hooks: hook,
        },
        zeroForOne,
        amountIn,
        amountOutMinimum: minOut,
        hookData: '0x',
      },
    ],
  );
  const settleAllParam = encodeAbiParameters(parseAbiParameters('address, uint256'), [
    zeroForOne ? USDC_BASE_ADDRESS : NARA_BASE_ADDRESS,
    amountIn,
  ]);
  const takeAllParam = encodeAbiParameters(parseAbiParameters('address, uint256'), [
    zeroForOne ? NARA_BASE_ADDRESS : USDC_BASE_ADDRESS,
    minOut,
  ]);

  const v4Input = encodeAbiParameters(parseAbiParameters('bytes actions, bytes[] params'), [
    '0x060c0f',
    [singleParam, settleAllParam, takeAllParam],
  ]);

  const commandByte: Hex = options?.allowRevertFlag ? '0x90' : '0x10';
  return encodeFunctionData({
    abi: urAbi,
    functionName: 'execute',
    args: [commandByte, [v4Input], 1_900_000_000n],
  });
}

describe('1. 1-Tx 500-Slip Multicall3 Batch Dispenser (`batch.ts`)', () => {
  it('encodes 50 USDC slips into 1 Multicall3.aggregate3 tx with bc_ea68lz8s suffix and signs in <50ms', async () => {
    // Warm up V8 JIT once before timed 50-slip benchmark (using distinct warmup credentials!)
    const warmupCreds = generateBatchClaimCredentials(10);
    await prepareBatchPayoutSlips({
      signer: PARTNER_KEY,
      items: warmupCreds.map((credential) => ({
        amount: 100_000n,
        asset: 'USDC' as const,
        credential,
      })),
      chainTimestampSec: 1_795_000_000,
    });

    const preallocatedCreds = generateBatchClaimCredentials(50);
    const items = preallocatedCreds.map((credential, idx) => ({
      amount: BigInt(100_000 + idx * 10_000),
      asset: 'USDC' as const,
      noTakeBack: idx % 2 === 0,
      grossUpForExitFee: idx % 3 === 0,
      credential,
      recipientRef: `user_${idx}`,
    }));

    const t0 = performance.now();
    const prepared = await prepareBatchPayoutSlips({
      signer: PARTNER_KEY,
      items,
      chainTimestampSec: 1_795_000_000,
    });
    const elapsedMs = performance.now() - t0;

    expect(elapsedMs).toBeLessThan(50);

    // Also verify PolicyGuardedSigner (V-01) intercepts every EIP-712 message (never bypassed!)
    const guardedPartner = createPolicyGuardedSigner(PARTNER_ACCOUNT, {
      maxPerCallUsdMicro: 500_000n,
    });
    await expect(
      preparePayoutSlip({
        signer: guardedPartner,
        item: { amount: 1_000_000n, asset: 'USDC' },
        chainTimestampSec: 1_795_000_000,
      }),
    ).rejects.toThrow(PolicyViolationError);
    expect(prepared.slips).toHaveLength(50);
    expect(prepared.transactions).toHaveLength(1);

    const tx = prepared.transactions[0]!;
    expect(tx.strategy).toBe('multicall3_erc20');
    expect(tx.to).toBe(MULTICALL3_ADDRESS);
    expect(tx.value).toBe(0n);
    expect(tx.data.toLowerCase().endsWith(ERC8021_MARKER_HEX)).toBe(true);

    const cleanMulticall = stripErc8021Suffix(tx.data, DEFAULT_CRYPTOSLIP_BUILDER_CODE);
    const decodedMc = decodeFunctionData({
      abi: MULTICALL3_ABI,
      data: cleanMulticall,
    });
    expect(decodedMc.functionName).toBe('aggregate3');
    const calls = decodedMc.args[0] as readonly {
      target: Address;
      allowFailure: boolean;
      callData: Hex;
    }[];
    expect(calls).toHaveLength(50);

    for (let i = 0; i < 50; i++) {
      const c = calls[i]!;
      const s = prepared.slips[i]!;
      expect(c.target).toBe(CANONICAL_VAULT_V33_ADDRESS);
      expect(c.allowFailure).toBe(false);

      const inner = decodeFunctionData({
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        data: c.callData,
      });
      expect(inner.functionName).toBe('mintSlipERC20WithAuthorization');
      const permit = inner.args[0] as {
        creator: Address;
        token: Address;
        amount: bigint;
        claimSigner: Address;
        cancelLockedUntil: number;
        relayer: Address;
      };
      expect(permit.creator).toBe(PARTNER_ACCOUNT.address);
      expect(permit.token).toBe(USDC_BASE_ADDRESS);
      expect(permit.relayer).toBe(ZERO_ADDRESS);
      expect(permit.claimSigner).toBe(s.claimSigner);
      expect(BigInt(permit.cancelLockedUntil)).toBe(i % 2 === 0 ? NO_TAKE_BACK_LOCK : 0n);

      if (i % 3 === 0) {
        const net = s.grossAmountUnits - computeProtocolFeeCeiling(s.grossAmountUnits);
        expect(net).toBeGreaterThanOrEqual(s.requestedAmountUnits);
      }
    }
  });

  it('chunks 300 slips into [250, 50] Multicall3 txs, supports NARA sequential EIP-2612 permits & scrypt codes, and rejects >500', async () => {
    const tooMany = Array.from({ length: 501 }, () => ({ amount: 100_000n, asset: 'USDC' as const }));
    await expect(
      prepareBatchPayoutSlips({
        signer: PARTNER_ACCOUNT,
        items: tooMany,
        chainTimestampSec: 1_795_000_000,
      }),
    ).rejects.toThrow(BatchValidationError);

    // 300 USDC slips -> 2 Multicall3 txs (250 + 50)
    const batch300 = await prepareBatchPayoutSlips({
      signer: PARTNER_ACCOUNT,
      items: Array.from({ length: 300 }, (_, i) => ({
        amount: 100_000n,
        asset: 'USDC' as const,
        claimPrivateKey: deriveTestKey(`chunk-300-${i}`),
      })),
      chainTimestampSec: 1_795_000_000,
    });
    expect(batch300.transactions).toHaveLength(2);
    expect(batch300.transactions[0]!.slipIndices).toHaveLength(250);
    expect(batch300.transactions[1]!.slipIndices).toHaveLength(50);

    // NARA sequential EIP-2612 nonces + cbBTC + 12-char scrypt code slip
    const mixedErc20 = await prepareBatchPayoutSlips({
      signer: PARTNER_ACCOUNT,
      items: [
        { amount: '1.5', asset: 'NARA', noTakeBack: true },
        { amount: '2.5', asset: 'NARA', noTakeBack: false },
        { amount: 500n, asset: 'cbBTC', mode: 'code', note: 'Prize payout', merchantLabel: '=EvilMacroCorp' },
      ],
      naraStartingNonce: 42n,
      chainTimestampSec: 1_795_000_000,
    });

    expect(mixedErc20.transactions).toHaveLength(1);
    // Dual builder attribution when NARA is present
    stripErc8021Suffix(mixedErc20.transactions[0]!.data, NARA_IN_APP_BUILDER_CODES);

    const codeSlip = mixedErc20.slips[2]!;
    expect(codeSlip.mode).toBe('code');
    expect(codeSlip.cancelLockedUntil).toBe(NO_TAKE_BACK_LOCK);
    expect(codeSlip.claimCode).toMatch(/^[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/);
    const redrived = await deriveCodeWallet(codeSlip.claimCode!, codeSlip.codeSalt!);
    expect(redrived.address).toBe(codeSlip.claimSigner);

    // Parse receipt logs -> URLs + CSV + JSON
    const fakeLogs = mixedErc20.slips.map((s, idx) => {
      const slipId = BigInt(9001 + idx);
      const topics = encodeEventTopics({
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        eventName: 'SlipMinted',
        args: {
          slipId,
          creator: PARTNER_ACCOUNT.address,
          asset: s.tokenAddress,
        },
      });
      const data = encodeAbiParameters(
        parseAbiParameters('uint256 amount, address claimSigner, uint48 expiresAt'),
        [s.grossAmountUnits, s.claimSigner, Number(s.cancelLockedUntil)],
      );
      return {
        address: CANONICAL_VAULT_V33_ADDRESS,
        topics: topics as Hex[],
        data,
      };
    });

    const parsedRecords = parseMintedSlipsFromReceipt(
      {
        transactionHash: keccak256(stringToHex('mock-batch-tx-hash')),
        blockNumber: 28_000_000n,
        status: 'success',
        logs: fakeLogs,
      },
      mixedErc20.slips,
    );

    expect(parsedRecords).toHaveLength(3);
    expect(parsedRecords[0]!.slipId).toBe('9001');
    expect(parsedRecords[0]!.url).toContain('https://slip.naraprotocol.io/#startapp=slip_9001_');
    expect(parsedRecords[0]!.telegramUrl).toBeNull(); // Open bearer links NEVER emit t.me URLs!

    const parsedBack = parseSlipUrl(parsedRecords[0]!.url);
    expect(parsedBack?.claimAddress).toBe(mixedErc20.slips[0]!.claimSigner);
    expect(parsedBack?.cancelLockedUntil).toBe(9_999_999_999);

    const csv = exportMintedSlipsCsv(parsedRecords);
    // Formula-injection leading '=' is neutralized with a single quote
    expect(csv).toContain("'=EvilMacroCorp");
    const json = JSON.parse(exportMintedSlipsJson(parsedRecords)) as unknown[];
    expect(json).toHaveLength(3);
  });

  it('enforces Solidity Law #2: blocks ETH Multicall3 & third-party mintSlipFor (`bindCreator` trap)', async () => {
    await expect(
      prepareBatchPayoutSlips({
        signer: PARTNER_ACCOUNT,
        items: [{ amount: 1_000_000_000_000_000n, asset: 'ETH' }],
        ethExecutionMode: 'multicall3',
        chainTimestampSec: 1_795_000_000,
      }),
    ).rejects.toThrow(CreatorBindingViolationError);

    expect(() =>
      assertCreatorBindingPreserved({
        txCaller: MULTICALL3_ADDRESS,
        partnerWallet: PARTNER_ACCOUNT.address,
        targetContract: CANONICAL_VAULT_V33_ADDRESS,
        vaultFunctionName: 'mintSlipFor',
      }),
    ).toThrow(CreatorBindingViolationError);

    // 1 ETH slip -> direct EOA call to vault (msg.sender == partnerWallet)
    const singleEth = await preparePayoutSlip({
      signer: PARTNER_ACCOUNT,
      item: { amount: 5_000_000_000_000n, asset: 'ETH', noTakeBack: true },
      chainTimestampSec: 1_795_000_000,
    });
    expect(singleEth.transaction.strategy).toBe('direct_eoa_eth');
    expect(singleEth.transaction.to).toBe(CANONICAL_VAULT_V33_ADDRESS);
    expect(singleEth.transaction.value).toBe(5_000_000_000_000n);

    // 3 ETH slips -> Simple7702Account self-batch executeBatch (to == partnerWallet -> msg.sender == partnerWallet)
    const multiEth = await prepareBatchPayoutSlips({
      signer: PARTNER_ACCOUNT,
      items: [
        { amount: 2_000_000_000_000n, asset: 'ETH' },
        { amount: 3_000_000_000_000n, asset: 'ETH' },
        { amount: 4_000_000_000_000n, asset: 'ETH' },
      ],
      ethExecutionMode: 'eip7702_self_batch',
      chainTimestampSec: 1_795_000_000,
    });
    expect(multiEth.transactions).toHaveLength(1);
    expect(multiEth.transactions[0]!.strategy).toBe('simple7702_eth_self_batch');
    expect(multiEth.transactions[0]!.to).toBe(PARTNER_ACCOUNT.address);
  });
});

describe('2. Lifecycle Operations & Frontier Defenses (`V-03`, `V-05`, Hard Invariant #1)', () => {
  it('enforces V-03: rejects $0.05 dust cliff ($0.20 from $0.25 USDC) unless allowFullCashOnDust is set', () => {
    expect(() =>
      resolveSplitPaymentWithDustCheck({
        slipAmount: 250_000n, // $0.25 USDC
        paymentAmount: 200_000n, // $0.20 USDC -> leaves $0.05 < $0.10 min!
        asset: 'USDC',
        vault: 'v33',
      }),
    ).toThrow(DustCliffError);

    try {
      resolveSplitPaymentWithDustCheck({
        slipAmount: 250_000n,
        paymentAmount: 200_000n,
        asset: 'USDC',
        vault: 'v33',
      });
    } catch (err) {
      expect(err).toBeInstanceOf(DustCliffError);
      const dErr = err as DustCliffError;
      expect(dErr.remainder).toBe(50_000n);
      expect(dErr.minRequiredChange).toBe(100_000n);
      expect(dErr.maxValidPartialPayment).toBe(150_000n);
      expect(dErr.suggestion).toContain('150000');
    }

    const dustSwept = resolveSplitPaymentWithDustCheck({
      slipAmount: 250_000n,
      paymentAmount: 200_000n,
      asset: 'USDC',
      vault: 'v33',
      allowFullCashOnDust: true,
    });
    expect(dustSwept.routedFullCashOnDust).toBe(true);
    expect(dustSwept.effectivePaymentAmount).toBe(250_000n);
    expect(dustSwept.expectedChangeAmount).toBe(0n);
  });

  it('enforces V-03: SlipMutex serializes concurrent spends on same slipId and prevents multi-slip deadlocks', async () => {
    const mutex = new SlipMutex();
    const key = SlipMutex.keyFor('v33', 777n);
    const trace: string[] = [];

    const tasks = [0, 1, 2, 3].map((idx) =>
      mutex.runExclusive(key, async () => {
        trace.push(`enter-${idx}`);
        await new Promise((r) => setTimeout(r, 15 - idx * 3));
        trace.push(`exit-${idx}`);
        return idx;
      }),
    );

    expect(mutex.isLocked(key)).toBe(true);
    expect(mutex.pendingCount(key)).toBe(4);
    const results = await Promise.all(tasks);
    expect(results).toEqual([0, 1, 2, 3]);
    expect(trace).toEqual([
      'enter-0',
      'exit-0',
      'enter-1',
      'exit-1',
      'enter-2',
      'exit-2',
      'enter-3',
      'exit-3',
    ]);
    expect(mutex.isLocked(key)).toBe(false);

    // Opposite lock order [10, 20] vs [20, 10] never deadlocks
    const k10 = SlipMutex.keyFor('v33', 10n);
    const k20 = SlipMutex.keyFor('v33', 20n);
    const [r1, r2] = await Promise.all([
      mutex.runExclusiveMulti([k10, k20], async () => {
        await new Promise((r) => setTimeout(r, 5));
        return 'batch-A';
      }),
      mutex.runExclusiveMulti([k20, k10], async () => {
        await new Promise((r) => setTimeout(r, 5));
        return 'batch-B';
      }),
    ]);
    expect([r1, r2]).toEqual(['batch-A', 'batch-B']);
  });

  it('enforces V-05: buckets No take-back slips strictly by slip.creator and chunks <= 10 without trailing singletons', () => {
    const mixedInput = [
      // Creator A: 2 locked No take-back slips
      {
        slipId: 1n,
        asset: 'USDC' as const,
        amount: 500_000n,
        creator: PARTNER_ACCOUNT.address,
        cancelLockedUntil: NO_TAKE_BACK_LOCK,
      },
      {
        slipId: 2n,
        asset: 'USDC' as const,
        amount: 600_000n,
        creator: PARTNER_ACCOUNT.address,
        cancelLockedUntil: NO_TAKE_BACK_LOCK,
      },
      // Creator B: 2 locked No take-back slips
      {
        slipId: 3n,
        asset: 'USDC' as const,
        amount: 700_000n,
        creator: CREATOR_B_ACCOUNT.address,
        cancelLockedUntil: NO_TAKE_BACK_LOCK,
      },
      {
        slipId: 4n,
        asset: 'USDC' as const,
        amount: 800_000n,
        creator: CREATOR_B_ACCOUNT.address,
        cancelLockedUntil: NO_TAKE_BACK_LOCK,
      },
      // Creator C: 1 locked slip + 1 unlocked slip -> rescued into Creator C's 2-slip bucket!
      {
        slipId: 5n,
        asset: 'USDC' as const,
        amount: 300_000n,
        creator: CREATOR_C_ACCOUNT.address,
        cancelLockedUntil: NO_TAKE_BACK_LOCK,
      },
      {
        slipId: 6n,
        asset: 'USDC' as const,
        amount: 300_000n,
        creator: CREATOR_C_ACCOUNT.address,
        cancelLockedUntil: 0n,
      },
      // 11 unlocked slips across mixed creators -> chunked into [9, 2] (both <= 10 and >= 2)
      ...Array.from({ length: 11 }, (_, idx) => ({
        slipId: BigInt(100 + idx),
        asset: 'USDC' as const,
        amount: 200_000n,
        creator: idx % 2 === 0 ? PARTNER_ACCOUNT.address : CREATOR_B_ACCOUNT.address,
        cancelLockedUntil: 0n,
      })),
    ];

    const plan = planCombineSlipBuckets(mixedInput, { currentTimestampSec: 1_795_000_000 });
    expect(plan.uncombinableSingletons).toHaveLength(0);
    expect(plan.batches).toHaveLength(5);

    for (const batch of plan.batches) {
      expect(batch.slips.length).toBeGreaterThanOrEqual(2);
      expect(batch.slips.length).toBeLessThanOrEqual(10);

      const hasLocked = batch.slips.some((s) => BigInt(s.cancelLockedUntil) > 1_795_000_000n);
      if (hasLocked) {
        // Every slip in a locked batch MUST share the exact same creator!
        const creators = new Set(batch.slips.map((s) => s.creator.toLowerCase()));
        expect(creators.size).toBe(1);
      }
    }

    const unlockedBatches = plan.batches.filter((b) => b.bucketKey === 'unlocked');
    expect(unlockedBatches.map((b) => b.slips.length)).toEqual([9, 2]);
  });

  it('executes keepSlip (0% 1st keep), claimSlip (130-byte ReferralConsent), splitAndPay, combineSlips, refund & referrals', async () => {
    const broadcastedCalls: Array<{ to: Address; data: Hex }> = [];
    const mockTxHash = keccak256(stringToHex('ops-mock-tx'));

    const mockPublicClient = {
      getBlock: async () => ({ timestamp: 1_795_000_000n }),
      getBalance: async () => 100_000_000_000_000_000n,
      getCode: async () => '0x',
      waitForTransactionReceipt: async () => ({
        transactionHash: mockTxHash,
        blockNumber: 28_000_100n,
        status: 'success',
        logs: [],
      }),
      readContract: async ({
        functionName,
        args,
      }: {
        functionName: string;
        args?: readonly unknown[];
      }) => {
        if (functionName === 'slips') {
          const id = BigInt((args?.[0] as bigint) ?? 1n);
          const signerAddr =
            id === 2n
              ? EPHEMERAL_2.address
              : id === 3n
                ? EPHEMERAL_3.address
                : EPHEMERAL_1.address;
          return [
            USDC_BASE_ADDRESS,
            1_000_000n, // $1.00 USDC
            1_794_900_000,
            0, // revocable
            PARTNER_ACCOUNT.address,
            signerAddr,
            SlipStatus.ACTIVE,
          ] as const;
        }
        if (functionName === 'nonces') return 0n;
        if (functionName === 'refundBeneficiary') return PARTNER_ACCOUNT.address;
        if (functionName === 'refundFeeRequired') return false;
        if (functionName === 'totalSlips') return 3n;
        if (functionName === 'referralCredits') {
          const token = String(args?.[1] ?? '').toLowerCase();
          return token === USDC_BASE_ADDRESS.toLowerCase() ? 250_000n : 0n;
        }
        throw new Error(`Unexpected readContract: ${functionName}`);
      },
    } as unknown as PublicClient;

    // 1. keepSlip: 0% 1st-keep fee + rotates to fresh non-colliding key
    const kept = await keepSlip({
      publicClient: mockPublicClient,
      slipId: 1n,
      claimSigner: EPHEMERAL_SLIP_KEY_1,
      recoveryMasterKey: RECIPIENT_KEY,
      userMainWallet: RECIPIENT_ACCOUNT.address,
      mode: 'agent',
      directBroadcast: async (call) => {
        broadcastedCalls.push(call);
        return mockTxHash;
      },
    });
    expect(kept.isFirstKeepZeroFee).toBe(true);
    expect(kept.feeUnits).toBe(0n);
    expect(kept.netAmountUnits).toBe(1_000_000n);
    expect(kept.newClaimSigner.toLowerCase()).not.toBe(PARTNER_ACCOUNT.address.toLowerCase());
    expect(kept.newClaimSigner.toLowerCase()).not.toBe(EPHEMERAL_1.address.toLowerCase());
    expect(kept.newClaimSigner.toLowerCase()).not.toBe(RECIPIENT_ACCOUNT.address.toLowerCase());

    // 2. claimSlip: builds 130-byte (CashPermit || ReferralConsent) signature
    const claimed = await claimSlip({
      publicClient: mockPublicClient,
      slipId: 1n,
      claimSigner: EPHEMERAL_SLIP_KEY_1,
      recipient: RECIPIENT_ACCOUNT.address,
      recipientSigner: RECIPIENT_KEY,
      mode: 'agent',
      directBroadcast: async (call) => {
        broadcastedCalls.push(call);
        return mockTxHash;
      },
    });
    expect(claimed.attachedReferralConsent).toBe(true);
    expect(claimed.signature.length).toBe(2 + 260); // 130 bytes
    expect(claimed.feeUnits).toBe(5_000n); // 0.50% of $1.00 = $0.005
    expect(claimed.netAmountUnits).toBe(995_000n);

    // 3. splitAndPay: partial spend ($0.40 from $1.00 -> $0.60 shielded vault change)
    const splitRes = await splitAndPay({
      publicClient: mockPublicClient,
      slipId: 1n,
      claimSigner: EPHEMERAL_SLIP_KEY_1,
      paymentAmount: 400_000n,
      merchant: MERCHANT_ACCOUNT.address,
      mode: 'agent',
      directBroadcast: async (call) => {
        broadcastedCalls.push(call);
        return mockTxHash;
      },
    });
    expect(splitRes.grossPaymentAmount).toBe(400_000n);
    expect(splitRes.feeUnits).toBe(2_000n);
    expect(splitRes.netMerchantAmount).toBe(398_000n);
    expect(splitRes.changeAmount).toBe(600_000n);

    // 4. combineSlips: consolidates slips [1, 2]
    const combined = await combineSlips({
      publicClient: mockPublicClient,
      slips: [
        { slipId: 1n, claimSigner: EPHEMERAL_SLIP_KEY_1 },
        { slipId: 2n, claimSigner: EPHEMERAL_SLIP_KEY_2 },
      ],
      mode: 'agent',
      directBroadcast: async (call) => {
        broadcastedCalls.push(call);
        return mockTxHash;
      },
    });
    expect(combined.executedBatches).toHaveLength(1);
    expect(combined.executedBatches[0]!.expectedChangeAmount).toBe(1_990_000n); // $2.00 - 0.50% ($0.01)

    // 5. scanReclaimableSlips + refundSlipDirect + withdrawReferralCredits
    const reclaimable = await scanReclaimableSlips({
      publicClient: mockPublicClient,
      creator: PARTNER_ACCOUNT.address,
      candidateSlipIds: [1n, 2n],
      minAgeSeconds: 3_600,
    });
    expect(reclaimable).toHaveLength(2);

    const mockWalletClient = {
      account: PARTNER_ACCOUNT,
      chain: base,
      sendTransaction: async ({ to, data }: { to: Address; data: Hex }) => {
        broadcastedCalls.push({ to, data });
        return mockTxHash;
      },
    };

    const refunded = await refundSlipDirect({
      publicClient: mockPublicClient,
      slipId: 1n,
      walletClient: mockWalletClient as never,
    });
    expect(refunded.feeUnits).toBe(0n);
    expect(refunded.refundedAmountUnits).toBe(1_000_000n);

    const refWithdrawn = await withdrawReferralCredits({
      publicClient: mockPublicClient,
      walletClient: mockWalletClient as never,
    });
    expect(refWithdrawn.withdrawnByAsset.USDC).toBe(250_000n);
    expect(refWithdrawn.txHashes).toHaveLength(1);
    expect(broadcastedCalls.length).toBeGreaterThanOrEqual(6);
  });

  it('enforces Hard Invariant #1: accepts canonical NARALiquidityHookV5 V4 swaps and rejects V3 / Aerodrome / rogue hooks', () => {
    const validCalldata = buildCanonicalNaraV4SwapCalldata();
    expect(() =>
      assertCanonicalNaraV4SwapCalldata({
        swapTarget: UNIVERSAL_ROUTER_ADDRESS,
        swapData: validCalldata,
        expectZeroForOne: true,
        minAmountOut: 9_000_000_000_000_000_000n,
      }),
    ).not.toThrow();

    // Also passes when ERC-8021 dual attribution suffix is appended
    const attributedValid = appendBuilderCodeSuffix(validCalldata, NARA_IN_APP_BUILDER_CODES);
    expect(() =>
      assertCanonicalNaraV4SwapCalldata({
        swapTarget: UNIVERSAL_ROUTER_ADDRESS,
        swapData: attributedValid,
        expectZeroForOne: true,
      }),
    ).not.toThrow();

    // Rejects Aerodrome Classic & Slipstream routers
    expect(() =>
      assertCanonicalNaraV4SwapCalldata({
        swapTarget: '0xcF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43',
        swapData: validCalldata,
      }),
    ).toThrow(NonCanonicalNaraSwapError);

    expect(() =>
      assertCanonicalNaraV4SwapCalldata({
        swapTarget: '0xbe6D8f0d05cC4be24d5167a3eF062215bE6D18a5',
        swapData: validCalldata,
      }),
    ).toThrow(NonCanonicalNaraSwapError);

    // Rejects Uniswap V3 SwapRouter02
    expect(() =>
      assertCanonicalNaraV4SwapCalldata({
        swapTarget: '0x2626664c2603336E57B271c5C0b26F421741e481',
        swapData: validCalldata,
      }),
    ).toThrow(NonCanonicalNaraSwapError);

    // Rejects UniversalRouter V3_SWAP_EXACT_IN (0x00) touching NARA
    const v3NaraData = buildCanonicalNaraV4SwapCalldata({ useV3CommandForNara: true });
    expect(() =>
      assertCanonicalNaraV4SwapCalldata({
        swapTarget: UNIVERSAL_ROUTER_ADDRESS,
        swapData: v3NaraData,
      }),
    ).toThrow(NonCanonicalNaraSwapError);

    // Rejects retired V4 hook (0x59AEf979...)
    const retiredHookData = buildCanonicalNaraV4SwapCalldata({
      hookAddress: getAddress('0x59aef9799dea01a7fb7da73bea10dfb08858a088'),
    });
    expect(() =>
      assertCanonicalNaraV4SwapCalldata({
        swapTarget: UNIVERSAL_ROUTER_ADDRESS,
        swapData: retiredHookData,
      }),
    ).toThrow(NonCanonicalNaraSwapError);

    // Rejects FLAG_ALLOW_REVERT (0x80)
    const allowRevertData = buildCanonicalNaraV4SwapCalldata({ allowRevertFlag: true });
    expect(() =>
      assertCanonicalNaraV4SwapCalldata({
        swapTarget: UNIVERSAL_ROUTER_ADDRESS,
        swapData: allowRevertData,
      }),
    ).toThrow(NonCanonicalNaraSwapError);
  });
});

describe('3. Serverless Circle TokenPaymasterV08 Parity & V-04 Transport (`paymaster.ts`)', () => {
  it('matches client/src/lib/circlePaymaster.ts byte-for-byte on paymasterAndData (offset 53), Simple7702Calls, and userOpHash', async () => {
    const thisDir = path.dirname(fileURLToPath(import.meta.url));
    const clientPmUrl = pathToFileURL(
      path.resolve(thisDir, '../../../../client/src/lib/circlePaymaster.ts'),
    ).href;
    const clientPm = (await import(/* @vite-ignore */ clientPmUrl)) as {
      encodeCirclePaymasterV08Data: (amt: bigint, sig: string, token?: string) => string;
      encodeSimple7702Calls: (
        calls: readonly { to: string; value?: bigint; data: string }[],
      ) => string;
      computeUserOpHashV08: (p: Record<string, unknown>) => string;
    };

    const sdkPmData = encodeCirclePaymasterV08Data(1_000_000n, STATIC_ERC4337_DUMMY_SIG);
    const clientPmData = clientPm.encodeCirclePaymasterV08Data(
      1_000_000n,
      STATIC_ERC4337_DUMMY_SIG,
    );
    expect(sdkPmData).toBe(clientPmData);
    expect((sdkPmData.length - 2) / 2).toBe(118); // 1 + 20 + 32 + 65 bytes

    // Verify PAYMASTER_TOKEN_ADDRESS_OFFSET == 53 inside full paymasterAndData
    const fullPmAndData = encodePaymasterAndDataV08({
      paymaster: CIRCLE_USDC_PAYMASTER_V08,
      paymasterVerificationGasLimit: 130_000n,
      paymasterPostOpGasLimit: 60_000n,
      paymasterData: sdkPmData,
    });
    const tokenSliceAtOffset53 = `0x${fullPmAndData.slice(
      2 + PAYMASTER_TOKEN_ADDRESS_OFFSET * 2,
      2 + (PAYMASTER_TOKEN_ADDRESS_OFFSET + 20) * 2,
    )}`;
    expect(tokenSliceAtOffset53.toLowerCase()).toBe(USDC_BASE_ADDRESS.toLowerCase());

    // Simple7702Calls single & batch parity
    const singleCalls = [
      { to: CANONICAL_VAULT_V33_ADDRESS, value: 0n, data: '0x12345678' as Hex },
    ];
    const batchCalls = [
      { to: CANONICAL_VAULT_V33_ADDRESS, value: 0n, data: '0x12345678' as Hex },
      { to: MULTICALL3_ADDRESS, value: 500n, data: '0xabcdef01' as Hex },
    ];
    expect(encodeSimple7702Calls(singleCalls)).toBe(clientPm.encodeSimple7702Calls(singleCalls));
    expect(encodeSimple7702Calls(batchCalls)).toBe(clientPm.encodeSimple7702Calls(batchCalls));

    // UserOpHash parity across both 7702 factory and already-delegated modes
    for (const use7702Factory of [true, false]) {
      const uoParams = {
        sender: PARTNER_ACCOUNT.address,
        nonce: 7n,
        callData: appendBuilderCodeSuffix(
          encodeSimple7702Calls(singleCalls),
          DEFAULT_CRYPTOSLIP_BUILDER_CODE,
        ),
        verificationGasLimit: 130_000n,
        callGasLimit: 220_000n,
        preVerificationGas: 65_000n,
        maxPriorityFeePerGas: 1_500_000n,
        maxFeePerGas: 20_000_000n,
        paymaster: CIRCLE_USDC_PAYMASTER_V08,
        paymasterVerificationGasLimit: 130_000n,
        paymasterPostOpGasLimit: 60_000n,
        paymasterData: sdkPmData,
        use7702Factory,
        delegateAddress: SIMPLE_7702_ACCOUNT,
        chainId: 8453n,
      };
      const sdkHash = computeUserOpHashV08(uoParams);
      const clientHash = clientPm.computeUserOpHashV08(uoParams);
      expect(sdkHash).toBe(clientHash);

      // Raw digest ECDSA signature parity vs ethers Wallet.signingKey.sign(hash).serialized
      const sdkSig = await sign({ hash: sdkHash, privateKey: PARTNER_KEY, to: 'hex' });
      const ethersSig = new Wallet(PARTNER_KEY).signingKey.sign(sdkHash).serialized;
      expect(sdkSig.toLowerCase()).toBe(ethersSig.toLowerCase());
    }
  });

  it('executes UserOp end-to-end via Circle TokenPaymasterV08 bundler & enforces PaymasterPendingError non-retry', async () => {
    const rpcLog: string[] = [];
    const capturedSignedOps: Array<Record<string, unknown>> = [];
    const expectedTxHash = keccak256(stringToHex('paymaster-confirmed-tx'));

    const mockPublicClient = {
      readContract: async ({ functionName }: { functionName: string }) => {
        if (functionName === 'balanceOf') return 5_000_000n; // $5.00 USDC
        if (functionName === 'nonces') return 3n;
        if (functionName === 'getNonce') return 0n;
        if (functionName === 'paused') return false;
        throw new Error(`Unexpected: ${functionName}`);
      },
      getCode: async () => '0x',
      getTransactionCount: async () => 12,
      estimateFeesPerGas: async () => ({
        maxFeePerGas: 10_000_000n,
        maxPriorityFeePerGas: 1_000_000n,
      }),
    } as unknown as PublicClient;

    const res = await executeViaCircleUsdcPaymaster({
      signerKey: PARTNER_KEY,
      calls: [{ to: CANONICAL_VAULT_V33_ADDRESS, data: '0xdeadbeef' }],
      publicClient: mockPublicClient,
      bundlerUrls: ['https://bundler-a.example.com/rpc', 'https://bundler-b.example.com/rpc'],
      pollTimeoutMs: 2_000,
      pollIntervalMs: 10,
      bundlerFetch: async (_url, init) => {
        const body = JSON.parse(String(init.body)) as { method: string; params: unknown[] };
        rpcLog.push(body.method);
        if (body.method === 'pimlico_getUserOperationGasPrice') {
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id: 1,
              result: {
                fast: { maxFeePerGas: '0x1dcd6500', maxPriorityFeePerGas: '0x1e8480' },
              },
            }),
          );
        }
        if (body.method === 'eth_estimateUserOperationGas') {
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id: 1,
              result: {
                callGasLimit: '0x35b60',
                verificationGasLimit: '0x1fbd0',
                preVerificationGas: '0xfde8',
                paymasterVerificationGasLimit: '0x1fbd0',
                paymasterPostOpGasLimit: '0xea60',
              },
            }),
          );
        }
        if (body.method === 'eth_sendUserOperation') {
          capturedSignedOps.push(body.params[0] as Record<string, unknown>);
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id: 1,
              result: keccak256(stringToHex('submitted-uo-hash')),
            }),
          );
        }
        if (body.method === 'eth_getUserOperationReceipt') {
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id: 1,
              result: {
                success: true,
                receipt: { transactionHash: expectedTxHash },
              },
            }),
          );
        }
        throw new Error(`Unhandled bundler method ${body.method}`);
      },
    });

    expect(res.txHash).toBe(expectedTxHash);
    const firstSignedOp = capturedSignedOps[0];
    expect(firstSignedOp?.paymaster).toBe(CIRCLE_USDC_PAYMASTER_V08);
    expect(firstSignedOp?.factory).toBe('0x7702');
    expect(String(firstSignedOp?.callData).toLowerCase().endsWith(ERC8021_MARKER_HEX)).toBe(true);

    // PaymasterPendingError MUST NOT retry on bundler #2 once eth_sendUserOperation succeeded on bundler #1
    const hitBundlers: string[] = [];
    await expect(
      executeViaCircleUsdcPaymaster({
        signerKey: PARTNER_KEY,
        calls: [{ to: CANONICAL_VAULT_V33_ADDRESS, data: '0xdeadbeef' }],
        publicClient: mockPublicClient,
        bundlerUrls: ['https://bundler-1.example.com/rpc', 'https://bundler-2.example.com/rpc'],
        pollTimeoutMs: 30,
        pollIntervalMs: 10,
        bundlerFetch: async (url, init) => {
          hitBundlers.push(url);
          const body = JSON.parse(String(init.body)) as { method: string };
          if (body.method === 'eth_estimateUserOperationGas') {
            return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: {} }));
          }
          if (body.method === 'eth_sendUserOperation') {
            return new Response(
              JSON.stringify({
                jsonrpc: '2.0',
                id: 1,
                result: keccak256(stringToHex('pending-uo')),
              }),
            );
          }
          return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: null }));
        },
      }),
    ).rejects.toThrow(PaymasterPendingError);
    expect(hitBundlers.every((u) => u.includes('bundler-1.example.com'))).toBe(true);
  });

  it('enforces V-04 transport routing & RelayGatewayClient failover + X-CryptoSLIP-Partner-Key', async () => {
    // Headless agent (>= $0.10, no telegramInitData, no partnerKey) -> blocks free Edge Relay!
    const agentPlan = resolveV04TransportPlan({
      mode: 'agent',
      estimatedUsdMicro: 250_000n,
      operationKind: 'split',
    });
    expect(agentPlan.allowEdgeRelay).toBe(false);
    expect(agentPlan.tiers).toEqual(['circle_paymaster', 'direct_eoa']);

    // 1st-boot Keep ('boot_keep') IS allowed on Edge Relay per V-01 / V-04
    const bootKeepPlan = resolveV04TransportPlan({
      mode: 'agent',
      operationKind: 'boot_keep',
    });
    expect(bootKeepPlan.allowEdgeRelay).toBe(true);
    expect(bootKeepPlan.tiers[0]).toBe('relay');

    // Partner key -> enables partner relay quota + failover
    const partnerPlan = resolveV04TransportPlan({
      partnerKey: 'cspk_live_test_partner',
      estimatedUsdMicro: 5_000_000n,
    });
    expect(partnerPlan.effectiveMode).toBe('partner');
    expect(partnerPlan.allowEdgeRelay).toBe(true);

    // RelayGatewayClient: primary 503 -> fails over to Akash secondary + attaches X-CryptoSLIP-Partner-Key
    const seenRequests: Array<{ url: string; partnerHeader: string | null }> = [];
    const expectedRelayHash = keccak256(stringToHex('akash-failover-tx'));
    const relayClient = new RelayGatewayClient({
      partnerKey: 'cspk_partner_99',
      fetchFn: async (input, init) => {
        const url = String(input);
        const hdrs = new Headers(init?.headers);
        seenRequests.push({
          url,
          partnerHeader: hdrs.get('X-CryptoSLIP-Partner-Key'),
        });
        if (url.includes('cryptoslip-edge.naraprotocol.workers.dev')) {
          return new Response(JSON.stringify({ ok: false, error: 'Temporarily busy' }), {
            status: 503,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        return new Response(JSON.stringify({ ok: true, txHash: expectedRelayHash }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      },
    });

    const postRes = await relayClient.postRelay('/api/relay/cash', { slipId: '42' });
    expect(postRes.txHash).toBe(expectedRelayHash);
    expect(postRes.gatewayUrl).toBe('https://relay1.cryptoslip.tech');
    expect(seenRequests).toHaveLength(2);
    expect(seenRequests[0]!.partnerHeader).toBe('cspk_partner_99');
    expect(seenRequests[1]!.partnerHeader).toBe('cspk_partner_99');

    // Refuses accidental claim-key leak in relay JSON body before any HTTP request
    await expect(
      relayClient.postRelay('/api/relay/cash', {
        leaked: `slip_1_10_open_v33_k${'a'.repeat(64)}`,
      }),
    ).rejects.toThrow(/never contain a slip claim key/);

    // Deterministic 400 RelayRejectedError does NOT retry on secondary gateway
    let count400 = 0;
    const rejectClient = new RelayGatewayClient({
      fetchFn: async () => {
        count400 += 1;
        return new Response(JSON.stringify({ ok: false, error: 'Invalid deadline' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      },
    });
    await expect(rejectClient.postRelay('/api/relay/cash', { slipId: '1' })).rejects.toThrow(
      RelayRejectedError,
    );
    expect(count400).toBe(1);

    // executeGaslessTransport in agent mode skips relayClient entirely and uses Circle Paymaster / direct
    let relayTouched = false;
    const directHash = keccak256(stringToHex('agent-direct-tx'));
    const transportOut = await executeGaslessTransport({
      mode: 'agent',
      estimatedUsdMicro: 500_000n,
      operationKind: 'split',
      relayPath: '/api/relay/split',
      relayBody: { slipId: '1' },
      relayClient: new RelayGatewayClient({
        fetchFn: async () => {
          relayTouched = true;
          throw new Error('Should never be called in headless agent mode');
        },
      }),
      calls: [{ to: CANONICAL_VAULT_V33_ADDRESS, data: '0x12345678' }],
      publicClient: { getBalance: async () => 10n ** 16n } as unknown as PublicClient,
      directBroadcast: async () => directHash,
    });
    expect(relayTouched).toBe(false);
    expect(transportOut.tier).toBe('direct_eoa');
    expect(transportOut.txHash).toBe(directHash);
  });
});

describe('4. Live Base Mainnet (8453) Read-Only `eth_call` Simulation', () => {
  it('verifies Multicall3 + MintPermit + USDC EIP-3009 signature acceptance on live Base Mainnet v33 Vault', async () => {
    const publicClient = createPublicClient({
      chain: base,
      transport: fallback(DEFAULT_BASE_RPC_URLS.map((url) => http(url, { timeout: 8_000 }))),
    });

    const headBlock = await publicClient.getBlock({ blockTag: 'latest' });
    expect(headBlock.number).toBeGreaterThan(20_000_000n);

    // Prepare 2 unfunded test slips and simulate via Multicall3.aggregate3(allowFailure: true) on live Base Mainnet!
    // Live CryptoSlipVaultV32 (v33) verifies MintPermit EIP-712 signature FIRST, then calls live Circle USDC
    // receiveWithAuthorization which verifies EIP-3009 (v,r,s) signature BEFORE reverting on 0 USDC balance!
    const prepared = await prepareBatchPayoutSlips({
      signer: PARTNER_ACCOUNT,
      items: [
        { amount: 100_000n, asset: 'USDC', noTakeBack: true },
        { amount: 250_000n, asset: 'USDC', noTakeBack: false },
      ],
      chainTimestampSec: headBlock.timestamp,
    });

    const multicallViewAbi = parseAbi([
      'function aggregate3((address target, bool allowFailure, bytes callData)[] calls) view returns ((bool success, bytes returnData)[])',
    ]);

    const simCalls = [
      {
        target: CANONICAL_VAULT_V33_ADDRESS,
        allowFailure: false,
        callData: encodeFunctionData({
          abi: CRYPTO_SLIP_VAULT_V32_ABI,
          functionName: 'DOMAIN_SEPARATOR',
        }),
      },
      {
        target: CIRCLE_USDC_PAYMASTER_V08,
        allowFailure: false,
        callData: encodeFunctionData({
          abi: parseAbi(['function paused() view returns (bool)']),
          functionName: 'paused',
        }),
      },
      {
        target: ENTRY_POINT_V08,
        allowFailure: false,
        callData: encodeFunctionData({
          abi: parseAbi(['function getNonce(address sender, uint192 key) view returns (uint256)']),
          functionName: 'getNonce',
          args: [PARTNER_ACCOUNT.address, 0n],
        }),
      },
      ...prepared.slips.map((s) => ({
        target: CANONICAL_VAULT_V33_ADDRESS,
        allowFailure: true,
        callData: s.vaultCallData,
      })),
    ];

    const results = await publicClient.readContract({
      address: MULTICALL3_ADDRESS,
      abi: multicallViewAbi,
      functionName: 'aggregate3',
      args: [simCalls],
    });

    expect(results).toHaveLength(5);
    expect(results[0]!.success).toBe(true);
    expect(results[0]!.returnData.toLowerCase()).toBe(V33_VAULT_DOMAIN_SEPARATOR.toLowerCase());

    // Circle TokenPaymasterV08 live paused() == false
    expect(results[1]!.success).toBe(true);
    const [pmPaused] = decodeAbiParameters(parseAbiParameters('bool'), results[1]!.returnData);
    expect(pmPaused).toBe(false);

    // EntryPoint v0.8 live getNonce
    expect(results[2]!.success).toBe(true);

    // Both mintSlipERC20WithAuthorization calls passed Vault MintPermit + Circle USDC EIP-3009 sig checks
    // and reverted strictly on unfunded balance ("ERC20: transfer amount exceeds balance"), NEVER InvalidSignature!
    for (const simRes of [results[3]!, results[4]!]) {
      expect(simRes.success).toBe(false);
      // Error(string) selector 0x08c379a0 (NOT Vault InvalidSignature() 0x8baa579f!)
      expect(simRes.returnData.slice(0, 10).toLowerCase()).toBe('0x08c379a0');
      const [reason] = decodeAbiParameters(
        parseAbiParameters('string'),
        `0x${simRes.returnData.slice(10)}` as Hex,
      );
      expect(reason).toContain('transfer amount exceeds balance');
    }
  });

  it('accepts uncast createPublicClient({ chain: base, ... }) & createWalletClient({ chain: base, ... }) under TS6 strict: true', async () => {
    const basePublicClient = createPublicClient({
      chain: base,
      transport: fallback(DEFAULT_BASE_RPC_URLS.map((url) => http(url, { timeout: 8_000 }))),
    });
    const baseWalletClient = createWalletClient({
      account: PARTNER_ACCOUNT,
      chain: base,
      transport: http(DEFAULT_BASE_RPC_URLS[0]!),
    });

    // Strict TS6 assignability assertions without any type casts (`TS2719` OP-Stack `base` chain regression check)
    const checkedPublic: BaseCompatiblePublicClient = basePublicClient;
    const checkedWallet: BaseCompatibleWalletClient = baseWalletClient;
    const execOptsCheck: ExecuteBatchPayoutOptions = {
      signer: PARTNER_ACCOUNT,
      items: [{ amount: 100_000n, asset: 'USDC' }],
      publicClient: basePublicClient,
      walletClient: baseWalletClient,
    };
    const keepOptsCheck: KeepSlipOptions = {
      publicClient: basePublicClient,
      walletClient: baseWalletClient,
      slipId: 1n,
      claimSigner: EPHEMERAL_SLIP_KEY_1,
    };
    const splitOptsCheck: SplitAndPayOptions = {
      publicClient: basePublicClient,
      walletClient: baseWalletClient,
      slipId: 1n,
      claimSigner: EPHEMERAL_SLIP_KEY_1,
      paymentAmount: 100_000n,
      merchant: MERCHANT_ACCOUNT.address,
    };
    expect(checkedPublic).toBe(basePublicClient);
    expect(checkedWallet).toBe(baseWalletClient);
    expect(execOptsCheck.publicClient).toBe(basePublicClient);
    expect(keepOptsCheck.publicClient).toBe(basePublicClient);
    expect(splitOptsCheck.publicClient).toBe(basePublicClient);

    // Live runtime execution passing uncast `basePublicClient` into `prepareBatchPayoutSlips`, `canSponsorWithCircleUsdcPaymaster`, and `readOnChainSlip`
    const [preparedViaBaseClient, sponsorCheck, slip1] = await Promise.all([
      prepareBatchPayoutSlips({
        signer: PARTNER_ACCOUNT,
        items: [{ amount: 100_000n, asset: 'USDC' }],
        publicClient: basePublicClient,
      }),
      canSponsorWithCircleUsdcPaymaster({
        userAddress: PARTNER_ACCOUNT.address,
        publicClient: basePublicClient,
      }),
      readOnChainSlip({
        publicClient: basePublicClient,
        slipId: 1n,
      }),
    ]);

    expect(preparedViaBaseClient.slips).toHaveLength(1);
    expect(sponsorCheck.ok).toBe(false);
    expect(slip1.vault).toBe('v33');
  });
});
