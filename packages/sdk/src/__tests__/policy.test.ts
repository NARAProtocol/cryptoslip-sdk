import { describe, expect, it, vi } from 'vitest';
import {
  encodeAbiParameters,
  encodeFunctionData,
  keccak256,
  parseAbi,
  parseAbiParameters,
  stringToHex,
  zeroAddress,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import {
  BoundedAgentPolicy,
  PolicyViolationError,
  POLICY_CANONICAL_CONTRACTS,
  POLICY_TOKEN_ADDRESSES,
  assertCanonicalNaraSwapPolicy,
  assertSafeDestination,
  checkDestination,
  createPolicyGuardedSigner,
  redactSecretsFromToolOutput,
} from '../policy.js';

const deriveTestKey = (label: string) => keccak256(stringToHex(label));

describe('BoundedAgentPolicy & Out-of-Context Firewall (V-01 / V-02)', () => {
  const agentAccount = privateKeyToAccount(deriveTestKey('mcp-test-key-1'));
  const safeRecipient = privateKeyToAccount(deriveTestKey('mcp-safe-recipient-1')).address;
  const freshEphemeral = privateKeyToAccount(deriveTestKey('mcp-ephemeral-keep-1')).address;

  it('blocks zero, burn, token, vault (v33/v32/v3/v2), router, and public compromised addresses', () => {
    const blockedTargets = [
      zeroAddress,
      '0x000000000000000000000000000000000000dEaD',
      POLICY_TOKEN_ADDRESSES.USDC,
      POLICY_TOKEN_ADDRESSES.cbBTC,
      POLICY_TOKEN_ADDRESSES.NARA,
      POLICY_TOKEN_ADDRESSES.WETH,
      POLICY_CANONICAL_CONTRACTS.vaultV33,
      POLICY_CANONICAL_CONTRACTS.nftV33,
      POLICY_CANONICAL_CONTRACTS.tradeRouterV33,
      POLICY_CANONICAL_CONTRACTS.vaultV32,
      POLICY_CANONICAL_CONTRACTS.nftV32,
      POLICY_CANONICAL_CONTRACTS.tradeRouterV32,
      POLICY_CANONICAL_CONTRACTS.vaultV3,
      POLICY_CANONICAL_CONTRACTS.nftV3,
      POLICY_CANONICAL_CONTRACTS.vaultV2,
      POLICY_CANONICAL_CONTRACTS.nftV2,
      POLICY_CANONICAL_CONTRACTS.naraLiquidityHookV5,
      POLICY_CANONICAL_CONTRACTS.universalRouter,
      POLICY_CANONICAL_CONTRACTS.tokenPaymasterV08,
      '0x5f3A378B685E309AE7404a7483420e49F2FBE6Aa',
      '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
      '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC',
    ];

    for (const addr of blockedTargets) {
      expect(checkDestination(addr).ok).toBe(false);
      expect(() => assertSafeDestination(addr)).toThrow(PolicyViolationError);
    }

    // Rejects bidi Unicode, ENS, bad EIP-55 checksum, and self-send
    expect(checkDestination(`\u202E${safeRecipient}`).ok).toBe(false);
    expect(checkDestination('merchant.eth').ok).toBe(false);
    expect(checkDestination(safeRecipient, { ownAddress: safeRecipient }).ok).toBe(false);

    // Accepts clean EOA in both lowercase and checksummed form
    expect(assertSafeDestination(safeRecipient.toLowerCase())).toBe(safeRecipient);
  });

  it('enforces per-call spend caps, sliding 60s rate limits, 24h budgets, and paired permit nonce dedup', () => {
    let clockMs = 1_700_000_000_000;
    const policy = new BoundedAgentPolicy({
      maxPerCallUsdMicro: 500_000n, // $0.50
      maxDailyUsdMicro: 1_200_000n, // $1.20
      maxSpendsPerMinute: 2,
      nowMs: () => clockMs,
    });

    // Rejects $0.51 USDC on $0.50 cap without consuming rate limit
    expect(() =>
      policy.authorizeAndRecordSpend({
        amount: 510_000n,
        asset: 'USDC',
        recipient: safeRecipient,
      }),
    ).toThrow(/exceeds maxPerCallUsdMicro/);
    expect(policy.getSnapshot().spendsInLastMinute).toBe(0);

    // Paired ReceiveWithAuthorization + MintPermit with identical nonce counts as 1 logical spend
    const mintNonce = keccak256(stringToHex('mint-nonce-1'));
    policy.authorizeAndRecordSpend({
      amount: 400_000n,
      asset: 'USDC',
      dedupKey: `mint:${mintNonce}`,
    });
    policy.authorizeAndRecordSpend({
      amount: 400_000n,
      asset: 'USDC',
      dedupKey: `mint:${mintNonce}`,
    });
    expect(policy.getSnapshot().spendsInLastMinute).toBe(1);
    expect(policy.getSnapshot().spentDailyUsdMicro).toBe('400000');

    // Second spend in same minute succeeds ($0.40 + $0.45 = $0.85)
    clockMs += 10_000;
    policy.authorizeAndRecordSpend({
      amount: 450_000n,
      asset: 'USDC',
      recipient: safeRecipient,
    });
    expect(policy.getSnapshot().spendsInLastMinute).toBe(2);

    // Third spend in same 60s window trips sliding rate limit (2/min)
    clockMs += 10_000;
    expect(() =>
      policy.authorizeAndRecordSpend({
        amount: 200_000n,
        asset: 'USDC',
        recipient: safeRecipient,
      }),
    ).toThrow(/Rate limit exceeded/);

    // Advance past 60s window -> rate limit clears, but $0.85 + $0.40 = $1.25 trips $1.20 daily cap
    clockMs += 55_000;
    expect(() =>
      policy.authorizeAndRecordSpend({
        amount: 400_000n,
        asset: 'USDC',
        recipient: safeRecipient,
      }),
    ).toThrow(/Daily budget exceeded/);

    // Advance past 24h window -> daily cap resets cleanly
    clockMs += 86_400_001;
    expect(() =>
      policy.authorizeAndRecordSpend({
        amount: 400_000n,
        asset: 'USDC',
        recipient: safeRecipient,
      }),
    ).not.toThrow();
  });

  it('enforces allowedRecipients and allowedDomains (blocking HTTP and prefix-spoof domains)', () => {
    const outsider = privateKeyToAccount(deriveTestKey('mcp-outsider-1')).address;
    const policy = new BoundedAgentPolicy({
      allowedRecipients: [safeRecipient],
      allowedDomains: ['api.example.com', '*.trusted.org'],
    });

    expect(policy.assertSafeDestination(safeRecipient)).toBe(safeRecipient);
    expect(() => policy.assertSafeDestination(outsider)).toThrow(/allowedRecipients/);

    expect(policy.assertAllowedDomain('https://api.example.com/v1/infer')).toBe('api.example.com');
    expect(policy.assertAllowedDomain('https://sub.trusted.org/pay')).toBe('sub.trusted.org');
    expect(() => policy.assertAllowedDomain('http://api.example.com/v1')).toThrow(/Non-HTTPS/);
    expect(() => policy.assertAllowedDomain('https://evil-trusted.org/pay')).toThrow(
      /allowedDomains/,
    );
    expect(() => policy.assertAllowedDomain('https://trusted.org/pay')).toThrow(/allowedDomains/);
  });

  it('guards SlipSigner before signing: allows 0%-fee Boot Keep, blocks prompt-injected drains & raw signMessage', async () => {
    const signSpy = vi.spyOn(agentAccount, 'signTypedData');
    const guarded = createPolicyGuardedSigner(agentAccount, {
      maxPerCallUsdMicro: 500_000n,
      maxSpendsPerMinute: 2,
      maxDailyUsdMicro: 2_000_000n,
    });

    // 1. Boot Auto-Keep (AcceptPermit with keepEscrowedInVault: true) passes without burning spend quota
    const keepSig = await guarded.signTypedData({
      domain: {
        name: 'Crypto Slip Protocol',
        version: '3',
        chainId: 8453,
        verifyingContract: POLICY_CANONICAL_CONTRACTS.vaultV33,
      },
      types: {
        AcceptPermit: [
          { name: 'slipId', type: 'uint256' },
          { name: 'newHolder', type: 'address' },
          { name: 'newClaimSigner', type: 'address' },
          { name: 'keepEscrowedInVault', type: 'bool' },
          { name: 'relayer', type: 'address' },
          { name: 'nonce', type: 'uint256' },
          { name: 'deadline', type: 'uint256' },
        ],
      },
      primaryType: 'AcceptPermit',
      message: {
        slipId: 42n,
        newHolder: zeroAddress,
        newClaimSigner: freshEphemeral,
        keepEscrowedInVault: true,
        relayer: zeroAddress,
        nonce: 0n,
        deadline: 1_900_000_000n,
      },
    });
    expect(keepSig).toMatch(/^0x[0-9a-fA-F]{130}$/);
    expect(guarded.policy.getSnapshot().spendsInLastMinute).toBe(0);

    // 2. Prompt-injected SplitPermit for $2.50 or to 0x...dEaD is blocked BEFORE underlying signer runs
    const callsBefore = signSpy.mock.calls.length;
    await expect(
      guarded.signTypedData({
        domain: {
          name: 'Crypto Slip Protocol',
          version: '3',
          chainId: 8453,
          verifyingContract: POLICY_CANONICAL_CONTRACTS.vaultV33,
        },
        types: {
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
        },
        primaryType: 'SplitPermit',
        message: {
          slipId: 42n,
          paymentAmount: 2_500_000n, // $2.50 > $0.50 cap
          merchant: safeRecipient,
          changeReceiver: POLICY_CANONICAL_CONTRACTS.vaultV33,
          newChangeSigner: freshEphemeral,
          relayer: zeroAddress,
          nonce: 1n,
          deadline: 1_900_000_000n,
        },
      }),
    ).rejects.toThrow(/exceeds maxPerCallUsdMicro/);
    expect(signSpy.mock.calls.length).toBe(callsBefore);

    // 3. Blind signMessage is blocked by default
    await expect(guarded.signMessage?.({ message: 'drain me' })).rejects.toThrow(
      /Blind signMessage is blocked/,
    );
  });

  it('enforces 100% Uniswap V4 NARALiquidityHookV5 routing and rejects V3/Aerodrome/wrong-hook calldata', () => {
    const urAbi = parseAbi(['function execute(bytes commands, bytes[] inputs, uint256 deadline)']);

    const buildV4NaraCalldata = (hookAddress: `0x${string}`, commandByte = '0x10') => {
      const singleParam = encodeAbiParameters(
        parseAbiParameters(
          '((address currency0, address currency1, uint24 fee, int24 tickSpacing, address hooks) poolKey, bool zeroForOne, uint128 amountIn, uint128 amountOutMinimum, bytes hookData)',
        ),
        [
          {
            poolKey: {
              currency0: POLICY_TOKEN_ADDRESSES.USDC,
              currency1: POLICY_TOKEN_ADDRESSES.NARA,
              fee: 3000,
              tickSpacing: 60,
              hooks: hookAddress,
            },
            zeroForOne: true,
            amountIn: 250_000n,
            amountOutMinimum: 200_000_000_000_000_000n,
            hookData: '0x',
          },
        ],
      );
      const settleParam = encodeAbiParameters(parseAbiParameters('address, uint256'), [
        POLICY_TOKEN_ADDRESSES.USDC,
        250_000n,
      ]);
      const takeAllParam = encodeAbiParameters(parseAbiParameters('address, uint256'), [
        POLICY_TOKEN_ADDRESSES.NARA,
        200_000_000_000_000_000n,
      ]);
      const v4Input = encodeAbiParameters(parseAbiParameters('bytes, bytes[]'), [
        '0x060c0f',
        [singleParam, settleParam, takeAllParam],
      ]);
      return encodeFunctionData({
        abi: urAbi,
        functionName: 'execute',
        args: [commandByte as `0x${string}`, [v4Input], 1_900_000_000n],
      });
    };

    // Valid canonical V4 hook swap passes
    const validSwapData = buildV4NaraCalldata(POLICY_CANONICAL_CONTRACTS.naraLiquidityHookV5);
    expect(() =>
      assertCanonicalNaraSwapPolicy({
        inAsset: 'USDC',
        outAsset: 'NARA',
        swapTarget: POLICY_CANONICAL_CONTRACTS.universalRouter,
        swapData: validSwapData,
      }),
    ).not.toThrow();

    // Wrong hook rejected
    const bogusHook = privateKeyToAccount(deriveTestKey('bogus-hook')).address;
    expect(() =>
      assertCanonicalNaraSwapPolicy({
        inAsset: 'USDC',
        outAsset: 'NARA',
        swapTarget: POLICY_CANONICAL_CONTRACTS.universalRouter,
        swapData: buildV4NaraCalldata(bogusHook),
      }),
    ).toThrow(/NARALiquidityHookV5/);

    // FLAG_ALLOW_REVERT (0x90) rejected
    expect(() =>
      assertCanonicalNaraSwapPolicy({
        inAsset: 'USDC',
        outAsset: 'NARA',
        swapTarget: POLICY_CANONICAL_CONTRACTS.universalRouter,
        swapData: buildV4NaraCalldata(POLICY_CANONICAL_CONTRACTS.naraLiquidityHookV5, '0x90'),
      }),
    ).toThrow(/FLAG_ALLOW_REVERT/);

    // Uniswap V3 SwapRouter02 or Aerodrome rejected for NARA
    expect(() =>
      assertCanonicalNaraSwapPolicy({
        inAsset: 'USDC',
        outAsset: 'NARA',
        swapTarget: '0x2626664c2603336E57B271c5C0b26F421741e481',
      }),
    ).toThrow(/UniversalRouter/);

    expect(() =>
      assertCanonicalNaraSwapPolicy({
        inAsset: 'USDC',
        outAsset: 'NARA',
        swapTarget: '0xcF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43', // Aerodrome
      }),
    ).toThrow(/not on the canonical router allowlist/);
  });

  it('recursively scrubs _k<64-hex> links and raw 64-hex secrets while supporting explicit outbound DM policy', () => {
    const rawKey = deriveTestKey('mcp-leak-key-99');
    const rawHexNoPrefix = rawKey.slice(2);
    const slipUrl = `https://slip.naraprotocol.io/#startapp=slip_77_5_open_v33_k${rawHexNoPrefix}&vk=secretVoiceKey1234567890ab`;

    const dirtyPayload = {
      status: 'ok',
      claimKey: rawKey,
      leakedUrlInNote: `Check ${slipUrl} now`,
      nested: {
        rawHex: rawHexNoPrefix,
        err: new Error(`Failed signing with ${rawKey}`),
      },
      outboundSlipUrl: slipUrl,
    };

    // Default redaction scrubs EVERY secret including outboundSlipUrl
    const scrubbedDefault = redactSecretsFromToolOutput(dirtyPayload);
    const serializedDefault = JSON.stringify(scrubbedDefault);
    expect(serializedDefault).not.toContain(rawHexNoPrefix);
    expect(serializedDefault).not.toContain('secretVoiceKey1234567890ab');
    expect(scrubbedDefault.claimKey).toBe('[REDACTED_SECRET]');
    expect(scrubbedDefault.nested.err.message).toContain('[REDACTED_SECRET]');

    // Explicit outbound DM link mode preserves outboundSlipUrl & nested MintedPayoutSlipRecord.url/sovereignUrl by default
    const scrubbedOutbound = redactSecretsFromToolOutput(
      {
        ...dirtyPayload,
        outboundLinks: [{ url: slipUrl, sovereignUrl: slipUrl, claimKey: rawKey }],
      },
      { allowOutboundSlipLink: true },
    );
    expect(scrubbedOutbound.outboundSlipUrl).toBe(slipUrl);
    expect(scrubbedOutbound.outboundLinks[0]?.url).toBe(slipUrl);
    expect(scrubbedOutbound.outboundLinks[0]?.sovereignUrl).toBe(slipUrl);
    expect(scrubbedOutbound.outboundLinks[0]?.claimKey).toBe('[REDACTED_SECRET]');
    expect(scrubbedOutbound.claimKey).toBe('[REDACTED_SECRET]');
    expect(scrubbedOutbound.nested.rawHex).toBe('[REDACTED_SECRET]');
    expect(scrubbedOutbound.leakedUrlInNote).not.toContain(rawHexNoPrefix);
  });

  it('3R regressions: enforces multi-asset (cbBTC/ETH/NARA) SplitPermit valuation, blocks changeReceiver remainder theft, and allows pure V-05 Combine', async () => {
    const attacker = privateKeyToAccount(deriveTestKey('mcp-attacker-remainder')).address;
    const splitDomain = {
      name: 'Crypto Slip Protocol',
      version: '3',
      chainId: 8453,
      verifyingContract: POLICY_CANONICAL_CONTRACTS.vaultV33,
    };
    const splitTypes = {
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
    };

    // 1. cbBTC (8 decimals, $50k/BTC): 500,000 sats = $250.00 MUST be blocked under $0.50 cap!
    const guardedBtc = createPolicyGuardedSigner(
      agentAccount,
      { maxPerCallUsdMicro: 500_000n, maxDailyUsdMicro: 5_000_000n },
      { slipAsset: 'cbBTC' },
    );
    await expect(
      guardedBtc.signTypedData({
        domain: splitDomain,
        types: splitTypes,
        primaryType: 'SplitPermit',
        message: {
          slipId: 77n,
          paymentAmount: 500_000n, // 0.005 BTC = $250.00!
          merchant: safeRecipient,
          changeReceiver: POLICY_CANONICAL_CONTRACTS.vaultV33,
          newChangeSigner: freshEphemeral,
          relayer: zeroAddress,
          nonce: 0n,
          deadline: 1_900_000_000n,
        },
      }),
    ).rejects.toThrow(/exceeds maxPerCallUsdMicro/);

    // 800 sats ($0.40) passes on cbBTC
    await expect(
      guardedBtc.signTypedData({
        domain: splitDomain,
        types: splitTypes,
        primaryType: 'SplitPermit',
        message: {
          slipId: 77n,
          paymentAmount: 800n,
          merchant: safeRecipient,
          changeReceiver: POLICY_CANONICAL_CONTRACTS.vaultV33,
          newChangeSigner: freshEphemeral,
          relayer: zeroAddress,
          nonce: 0n,
          deadline: 1_900_000_000n,
        },
      }),
    ).resolves.toMatch(/^0x[0-9a-fA-F]{130}$/);

    // 2. ETH (18 decimals, $2,500/ETH): 0.0001 ETH (10^14 wei = $0.25) succeeds without false $100M DoS!
    const guardedEth = createPolicyGuardedSigner(
      agentAccount,
      { maxPerCallUsdMicro: 500_000n, maxDailyUsdMicro: 5_000_000n },
      { slipAsset: 'ETH' },
    );
    await expect(
      guardedEth.signTypedData({
        domain: splitDomain,
        types: splitTypes,
        primaryType: 'SplitPermit',
        message: {
          slipId: 78n,
          paymentAmount: 100_000_000_000_000n, // 0.0001 ETH = $0.25
          merchant: safeRecipient,
          changeReceiver: POLICY_CANONICAL_CONTRACTS.vaultV33,
          newChangeSigner: freshEphemeral,
          relayer: zeroAddress,
          nonce: 0n,
          deadline: 1_900_000_000n,
        },
      }),
    ).resolves.toMatch(/^0x[0-9a-fA-F]{130}$/);

    // 3. Remainder-theft defense: external changeReceiver (attacker EOA) MUST be rejected!
    await expect(
      guardedEth.signTypedData({
        domain: splitDomain,
        types: splitTypes,
        primaryType: 'SplitPermit',
        message: {
          slipId: 78n,
          paymentAmount: 100_000_000_000_000n,
          merchant: safeRecipient,
          changeReceiver: attacker,
          newChangeSigner: freshEphemeral,
          relayer: zeroAddress,
          nonce: 1n,
          deadline: 1_900_000_000n,
        },
      }),
    ).rejects.toThrow(/changeReceiver/);

    // 4. Pure V-05 Combine (paymentAmount === 0n, merchant === 0x0, changeReceiver === vaultV33) passes without consuming quota!
    const guardedCombine = createPolicyGuardedSigner(agentAccount, {
      maxPerCallUsdMicro: 500_000n,
      maxSpendsPerMinute: 1,
    });
    await expect(
      guardedCombine.signTypedData({
        domain: splitDomain,
        types: {
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
        },
        primaryType: 'RearrangePermit',
        message: {
          slipId: 79n,
          slipIdsHash: deriveTestKey('slip-ids-hash-1'),
          paymentAmount: 0n,
          merchant: zeroAddress,
          changeReceiver: POLICY_CANONICAL_CONTRACTS.vaultV33,
          newChangeSigner: freshEphemeral,
          relayer: zeroAddress,
          nonce: 0n,
          deadline: 1_900_000_000n,
        },
      }),
    ).resolves.toMatch(/^0x[0-9a-fA-F]{130}$/);
    expect(guardedCombine.policy.getSnapshot().spendsInLastMinute).toBe(0);
  });
});
