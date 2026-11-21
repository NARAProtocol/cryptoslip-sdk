import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { describe, expect, it, vi } from 'vitest';
import { Wallet } from 'ethers';
import { hmac } from '@noble/hashes/hmac';
import { p256, hashToCurve } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import {
  createPublicClient,
  encodeEventTopics,
  encodeAbiParameters,
  fallback,
  http,
  keccak256,
  parseAbiParameters,
  stringToHex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { base } from 'viem/chains';

import {
  CANONICAL_VAULT_V33_ADDRESS,
  DEFAULT_BASE_RPC_URLS,
  NO_TAKE_BACK_LOCK,
  OFFGRID_PERMANENT_LOCK_UNTIL,
  SlipStatus,
  USDC_BASE_ADDRESS,
  VOICE_MIN_USD_MICRO,
  computeProtocolFeeCeiling,
  deductProtocolFeeCeiling,
  grossUpForExactNet,
} from '../constants.js';
import { CRYPTO_SLIP_VAULT_V32_ABI, ERC20_PERMIT_EIP3009_ABI } from '../abi.js';
import { encodeSlipUrl, parseSlipUrl } from '../link.js';
import {
  VOICE_ENVELOPE_BLOCK_BYTES,
  VOICE_GCM_IV_BYTES,
  VOICE_GCM_TAG_BYTES,
  VOICE_UPLOAD_ENVELOPE_BYTES,
  VoiceEconomicFloorError,
  assertVoiceEconomicFloor,
  burnVoiceNoteNow,
  checkBurnOnPlayVoiceStatus,
  createVoiceVoprf,
  currentVoiceEpochId,
  decryptVoiceEnvelope,
  deriveVoiceIdentity,
  deriveVoucherVoprfInput,
  encryptVoiceEnvelope,
  meetsVoiceEconomicFloor,
  parseUploadEnvelope,
  playAndBurnVoice,
  previewVoicePassSplit,
  uploadBurnOnPlayVoice,
  verifyVoiceActionSignature,
  voiceVoprf,
} from '../voice.js';
import {
  createSignedPaymentReceipt,
  formatReceiptCsvRow,
  formatReceiptsCsv,
  renderPrintableReceiptHtml,
  verifyPaymentReceiptOnChain,
  verifyPaymentReceiptSignature,
} from '../receipts.js';
import {
  SlipReplayGuard,
  X_CRYPTOSLIP_ACCEPT_HEADER,
  X_CRYPTOSLIP_ERROR_HEADER,
  X_PAYMENT_RECEIPT_HEADER,
  X_PAYMENT_REFUND_AMOUNT_HEADER,
  X_PAYMENT_REFUND_SLIP_HEADER,
  X_PAYMENT_TX_HEADER,
  X_SLIP_HEADER,
  attachRefundSlipHeader,
  decodeReceiptHeaderValue,
  verifyPartnerWebhookSignature,
  withCryptoSlip,
  type PartnerWebhookEventType,
  type PartnerWebhookPayload,
  type TollboothPublicClient,
} from '../middleware.js';
import * as sdkIndex from '../index.js';

// Runtime-derived deterministic test keys (zero hardcoded 64-hex literals in repo!)
const TEST_KEY_CREATOR = keccak256(stringToHex('voice-test-key-creator-1'));
const TEST_KEY_CLAIM = keccak256(stringToHex('voice-test-key-claim-1'));
const TEST_KEY_MERCHANT = keccak256(stringToHex('voice-test-key-merchant-1'));
const TEST_KEY_ISSUER = keccak256(stringToHex('voice-test-key-issuer-1'));
const TEST_KEY_REFUND_CLAIM = keccak256(stringToHex('voice-test-key-refund-claim-1'));
const TEST_KEY_ALT_CREATOR = keccak256(stringToHex('voice-test-key-alt-creator-1'));
const TEST_VOPRF_MASTER_BYTES = new Uint8Array(
  Buffer.from(keccak256(stringToHex('voice-test-voprf-master-1')).slice(2), 'hex'),
);

const creatorAccount = privateKeyToAccount(TEST_KEY_CREATOR);
const claimAccount = privateKeyToAccount(TEST_KEY_CLAIM);
const merchantAccount = privateKeyToAccount(TEST_KEY_MERCHANT);
const issuerAccount = privateKeyToAccount(TEST_KEY_ISSUER);
const altCreatorAccount = privateKeyToAccount(TEST_KEY_ALT_CREATOR);

describe('@cryptoslip/sdk — voice.ts ($1.00+ Floor, 32 KB AES-256-GCM Padding, VOPRF & Burn-on-Play)', () => {
  it('1. Hard-enforces >= $1.00 USD floor (VOICE_MIN_USD_MICRO = 1_000_000n) across all 4 canonical assets', async () => {
    expect(VOICE_MIN_USD_MICRO).toBe(1_000_000n);

    // Below $1.00 floor -> rejected
    expect(meetsVoiceEconomicFloor('USDC', 500_000n)).toBe(false); // $0.50 USDC
    expect(meetsVoiceEconomicFloor('USDC', 999_999n)).toBe(false); // $0.999999 USDC
    expect(meetsVoiceEconomicFloor('ETH', 399_999_999_999_999n)).toBe(false); // < 0.0004 ETH
    expect(meetsVoiceEconomicFloor('cbBTC', 999n)).toBe(false); // < 1,000 sats
    expect(meetsVoiceEconomicFloor('NARA', 399_999_999_999_999n)).toBe(false); // < 0.0004 NARA

    expect(() => assertVoiceEconomicFloor('USDC', 500_000n)).toThrow(VoiceEconomicFloorError);

    // >= $1.00 floor -> accepted
    expect(meetsVoiceEconomicFloor('USDC', 1_000_000n)).toBe(true); // $1.00 USDC
    expect(meetsVoiceEconomicFloor('USDC', 5_000_000n)).toBe(true); // $5.00 USDC
    expect(meetsVoiceEconomicFloor('ETH', 400_000_000_000_000n)).toBe(true); // 0.0004 ETH
    expect(meetsVoiceEconomicFloor('cbBTC', 1_000n)).toBe(true); // 1,000 sats
    expect(meetsVoiceEconomicFloor('BTC', 1_000n)).toBe(true);
    expect(meetsVoiceEconomicFloor('NARA', 400_000_000_000_000n)).toBe(true); // 0.0004 NARA

    // encryptVoiceEnvelope & uploadBurnOnPlayVoice reject $0.50 before touching crypto or network
    const sampleAudio = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    await expect(
      encryptVoiceEnvelope(sampleAudio, 'audio/ogg', { asset: 'USDC', slipAmount: 500_000n }),
    ).rejects.toThrow(VoiceEconomicFloorError);

    const spyFetch = vi.fn();
    await expect(
      uploadBurnOnPlayVoice({
        audioBytes: sampleAudio,
        asset: 'USDC',
        slipAmount: 500_000n,
        slipId: '77',
        claimPrivateKey: TEST_KEY_CLAIM,
        beneficiarySigner: creatorAccount,
        fetchFn: spyFetch as unknown as typeof fetch,
      }),
    ).rejects.toThrow(VoiceEconomicFloorError);
    expect(spyFetch).not.toHaveBeenCalled();
  });

  it('2. Pads short & multi-block audio to exact 32 KB (32,768-byte) AES-256-GCM blocks & zeroizes sensitive buffers', async () => {
    const tinyClip = new Uint8Array(19);
    for (let i = 0; i < tinyClip.length; i++) tinyClip[i] = (i * 13 + 7) & 0xff;
    const tinySnapshot = new Uint8Array(tinyClip);

    const mediumClip = new Uint8Array(24_500);
    for (let i = 0; i < mediumClip.length; i++) mediumClip[i] = (i * 31 + 3) & 0xff;

    const encTiny = await encryptVoiceEnvelope(tinyClip, 'audio/webm', {
      asset: 'USDC',
      slipAmount: 1_000_000n,
      zeroizeInput: true,
    });
    const encMedium = await encryptVoiceEnvelope(mediumClip, 'audio/webm', {
      asset: 'USDC',
      slipAmount: 2_000_000n,
    });

    // Input buffer was scrubbed in place via zeroizeInput
    expect(tinyClip.every((b) => b === 0)).toBe(true);

    // Both 19 B and 24,500 B clips produce the EXACT same ciphertext length (32,768 + 12 IV + 16 tag = 32,796 B)
    const expectedSingleBlockCipherLen =
      VOICE_GCM_IV_BYTES + VOICE_ENVELOPE_BLOCK_BYTES + VOICE_GCM_TAG_BYTES;
    expect(encTiny.paddedPlaintextBytes).toBe(32_768);
    expect(encMedium.paddedPlaintextBytes).toBe(32_768);
    expect(encTiny.ciphertextBytes.byteLength).toBe(expectedSingleBlockCipherLen);
    expect(encMedium.ciphertextBytes.byteLength).toBe(expectedSingleBlockCipherLen);
    expect(encTiny.voiceKeyBase64Url).toMatch(/^[A-Za-z0-9_-]{43}$/);

    // Multi-block clip (40,000 B > 32,768 B) pads cleanly to 65,536 B (2 * 32 KB)
    const largeClip = new Uint8Array(40_000).fill(0x5a);
    const encLarge = await encryptVoiceEnvelope(largeClip, 'audio/mp4');
    expect(encLarge.paddedPlaintextBytes).toBe(65_536);
    expect(encLarge.ciphertextBytes.byteLength).toBe(
      VOICE_GCM_IV_BYTES + 65_536 + VOICE_GCM_TAG_BYTES,
    );

    // Round-trip decrypt + ciphertext & output buffer zeroization
    const decTiny = await decryptVoiceEnvelope(encTiny.ciphertextBytes, encTiny.voiceKeyBase64Url, {
      zeroizeCiphertext: true,
    });
    expect(decTiny.mimeType).toBe('audio/webm');
    expect(decTiny.audioBytes).toEqual(tinySnapshot);
    expect(encTiny.ciphertextBytes.every((b) => b === 0)).toBe(true);

    decTiny.zeroize();
    expect(decTiny.audioBytes.every((b) => b === 0)).toBe(true);

    // Tampered ciphertext must fail closed under GCM authentication
    const tampered = new Uint8Array(encMedium.ciphertextBytes);
    tampered[20] = (tampered[20] ?? 0) ^ 0xff;
    await expect(decryptVoiceEnvelope(tampered, encMedium.voiceKeyBase64Url)).rejects.toThrow();
  });

  it('3. Matches shared/voiceVoprf.mjs & shared/voiceEnvelope.mjs byte-for-byte on RFC 9497 P-256 VOPRF + DLEQ', async () => {
    const thisDir = path.dirname(fileURLToPath(import.meta.url));
    const sharedVoprfPath = path.resolve(thisDir, '../../../../shared/voiceVoprf.mjs');
    const sharedEnvPath = path.resolve(thisDir, '../../../../shared/voiceEnvelope.mjs');
    const hasSharedRef = fs.existsSync(sharedVoprfPath) && fs.existsSync(sharedEnvPath);

    const epochId = 10;
    const sdkKeypair = voiceVoprf.deriveEpochKeypair(TEST_VOPRF_MASTER_BYTES, epochId);

    // Deterministic blind scalar vector test
    let seq = 1;
    const detRng = (len: number) => {
      const out = new Uint8Array(len);
      for (let i = 0; i < len; i++) out[i] = (seq++ * 17 + i) & 0xff;
      return out;
    };
    let seqShared = 1;
    const detRngShared = (len: number) => {
      const out = new Uint8Array(len);
      for (let i = 0; i < len; i++) out[i] = (seqShared++ * 17 + i) & 0xff;
      return out;
    };

    const identity = await deriveVoiceIdentity({
      vaultAddress: CANONICAL_VAULT_V33_ADDRESS,
      slipId: '42',
      mode: 'open',
      claimPrivateKey: TEST_KEY_CLAIM,
      fragmentVoiceKey: 'ABCDEFGHIJKLMNOPQRSTUV',
    });

    const voucherNonce = new Uint8Array(32).fill(0x33);
    const voprfInput = deriveVoucherVoprfInput(identity.voiceKeyIdBytes, voucherNonce);
    const blindedSdk = voiceVoprf.blind(voprfInput, detRng);

    if (hasSharedRef) {
      const sharedVoprfMod = (await import(pathToFileURL(sharedVoprfPath).href)) as Record<string, any>;
      const sharedEnvMod = (await import(pathToFileURL(sharedEnvPath).href)) as Record<string, any>;
      const sharedVoprf = sharedVoprfMod.createVoiceVoprf({ p256, hashToCurve, sha256 });
      const sharedKeypair = sharedVoprf.deriveEpochKeypair(TEST_VOPRF_MASTER_BYTES, epochId);
      expect(sdkKeypair).toEqual(sharedKeypair);

      const sharedSalt = await sharedEnvMod.deriveVoiceSalt(CANONICAL_VAULT_V33_ADDRESS, '42');
      const claimBytes = Buffer.from(TEST_KEY_CLAIM.slice(2), 'hex');
      const sharedAuthKey = await sharedEnvMod.deriveVoiceAuthPrivateKeyBytes(
        new Uint8Array(claimBytes),
        sharedSalt,
      );
      const sharedAuthWallet = new Wallet(`0x${sharedEnvMod.bytesToHex(sharedAuthKey)}`);
      expect(identity.voiceAuthAddress.toLowerCase()).toBe(sharedAuthWallet.address.toLowerCase());

      const sharedInput = await sharedEnvMod.deriveVoucherVoprfInput(
        identity.voiceKeyIdBytes,
        voucherNonce,
      );
      expect(voprfInput).toEqual(sharedInput);

      const blindedShared = sharedVoprf.blind(voprfInput, detRngShared);
      expect(blindedSdk).toEqual(blindedShared);

      const evaluated = sharedVoprf.blindEvaluate(
        sharedKeypair.skHex,
        blindedSdk.blindedHex,
        detRngShared,
      );
      const finalizedToken = voiceVoprf.finalize(
        voprfInput,
        blindedSdk.blindScalarHex,
        sharedKeypair.pkHex,
        evaluated.evaluatedHex,
        evaluated.proofHex,
      );
      expect(sharedVoprf.verifyFinalized(sharedKeypair.skHex, voprfInput, finalizedToken)).toBe(true);
      expect(voiceVoprf.verifyFinalized(sdkKeypair.skHex, voprfInput, finalizedToken)).toBe(true);
    } else {
      const evaluated = voiceVoprf.blindEvaluate(
        sdkKeypair.skHex,
        blindedSdk.blindedHex,
        detRngShared,
      );
      const finalizedToken = voiceVoprf.finalize(
        voprfInput,
        blindedSdk.blindScalarHex,
        sdkKeypair.pkHex,
        evaluated.evaluatedHex,
        evaluated.proofHex,
      );
      expect(voiceVoprf.verifyFinalized(sdkKeypair.skHex, voprfInput, finalizedToken)).toBe(true);
    }

    // Anti-key-tagging: wrong public key or forged DLEQ proof MUST throw
    const wrongEpochKeypair = voiceVoprf.deriveEpochKeypair(TEST_VOPRF_MASTER_BYTES, epochId + 1);
    const evaluatedForTagCheck = voiceVoprf.blindEvaluate(
      sdkKeypair.skHex,
      blindedSdk.blindedHex,
      detRngShared,
    );
    expect(() =>
      voiceVoprf.finalize(
        voprfInput,
        blindedSdk.blindScalarHex,
        wrongEpochKeypair.pkHex,
        evaluatedForTagCheck.evaluatedHex,
        evaluatedForTagCheck.proofHex,
      ),
    ).toThrow();

    // VoicePass split math check
    const splitWithRef = previewVoicePassSplit(10_000_000n, true);
    expect(splitWithRef).toEqual({
      referrerShare: 5_000_000n,
      naraHoldersShare: 3_500_000n,
      treasuryShare: 1_500_000n,
    });

    identity.zeroize();
    expect(identity.voiceAudioKeyBytes.every((b) => b === 0)).toBe(true);

    // Code-mode scrypt KDF parity check (`cryptoslip-voice-kdf-v1:`)
    const codeIdentity = await deriveVoiceIdentity({
      vaultAddress: CANONICAL_VAULT_V33_ADDRESS,
      slipId: '42',
      mode: 'code',
      claimCode: 'ABCD-EFGH-JKMN',
      codeSalt: '0123456789abcdef0123456789abcdef',
    });
    expect(codeIdentity.voiceKeyIdHex).toMatch(/^[0-9a-f]{64}$/);
    codeIdentity.zeroize();
  });

  it('4. Executes full uploadBurnOnPlayVoice -> fragment-only #..._vn1&vk= -> playAndBurnVoice lifecycle', async () => {
    const nowMs = Date.UTC(2026, 10, 21, 7, 0, 0);
    const nowSec = Math.floor(nowMs / 1000);
    const epochId = currentVoiceEpochId(nowMs);
    const serverVoprf = createVoiceVoprf();
    const epochKeys = serverVoprf.deriveEpochKeypair(TEST_VOPRF_MASTER_BYTES, epochId);

    const storedShards = new Map<string, { payload: Uint8Array; burned: boolean }>();

    const mockVoiceFetch: typeof fetch = async (input, init) => {
      const url = new URL(String(input));
      const host = url.host.toLowerCase();

      if (url.pathname === '/api/voice/public-key') {
        return Response.json({
          ok: true,
          epochId,
          pkHex: epochKeys.pkHex,
          previousEpochId: (epochId + 255) % 256,
          previousPkHex: epochKeys.pkHex,
        });
      }

      if (url.pathname === '/api/voice/voucher') {
        const body = JSON.parse(String(init?.body || '{}')) as { blindedHex: string };
        const evalOut = serverVoprf.blindEvaluate(epochKeys.skHex, body.blindedHex);
        return Response.json({
          ok: true,
          epochId,
          evaluatedHex: evalOut.evaluatedHex,
          proofHex: evalOut.proofHex,
          pkHex: evalOut.pkHex,
        });
      }

      if (url.pathname === '/api/voice/upload') {
        const raw = new Uint8Array(await new Response(init?.body as BodyInit).arrayBuffer());
        expect(raw.byteLength).toBe(VOICE_UPLOAD_ENVELOPE_BYTES);
        const parsed = parseUploadEnvelope(raw);
        const inputBytes = deriveVoucherVoprfInput(parsed.voiceKeyIdBytes, parsed.voucherNonceBytes);
        expect(serverVoprf.verifyFinalized(epochKeys.skHex, inputBytes, parsed.voprfOutputBytes)).toBe(
          true,
        );
        storedShards.set(parsed.voiceKeyIdHex, {
          payload: parsed.encryptedPayloadBytes,
          burned: false,
        });
        return Response.json({ ok: true });
      }

      const body = JSON.parse(String(init?.body || '{}')) as {
        voiceKeyId: string;
        timestampSec: number;
        nonce: string;
        signature: string;
      };
      const actionMap: Record<string, 'STATUS' | 'PLAY' | 'ACK' | 'BURN'> = {
        '/api/voice/status': 'STATUS',
        '/api/voice/play': 'PLAY',
        '/api/voice/ack': 'ACK',
        '/api/voice/burn': 'BURN',
      };
      const action = actionMap[url.pathname];
      if (!action) return Response.json({ ok: false }, { status: 404 });

      const verified = await verifyVoiceActionSignature({
        action,
        host,
        voiceKeyIdHex: body.voiceKeyId,
        timestampSec: body.timestampSec,
        nonceHex: body.nonce,
        signature: body.signature,
        nowSec,
      });
      const row = storedShards.get(verified.voiceKeyIdHex);

      if (action === 'STATUS') {
        return Response.json({ ok: true, available: Boolean(row && !row.burned) });
      }
      if (action === 'PLAY') {
        if (!row || row.burned) return Response.json({ ok: false }, { status: 410 });
        return new Response(new Uint8Array(row.payload), {
          status: 200,
          headers: { 'Content-Type': 'application/octet-stream' },
        });
      }
      if (action === 'ACK' || action === 'BURN') {
        if (row && !row.burned) {
          row.payload.fill(0);
          row.burned = true;
          return Response.json({ ok: true, burned: true });
        }
        return Response.json({ ok: true, burned: false });
      }
      return Response.json({ ok: false }, { status: 400 });
    };

    const baseSlip = encodeSlipUrl({
      id: '108',
      amount: 5,
      asset: 'USDC',
      vault: 'v33',
      mode: 'open',
      claimKey: TEST_KEY_CLAIM,
      cancelLockedUntil: OFFGRID_PERMANENT_LOCK_UNTIL,
    });

    const originalAudio = new Uint8Array(2_048);
    for (let i = 0; i < originalAudio.length; i++) originalAudio[i] = (i * 7 + 11) & 0xff;

    const uploaded = await uploadBurnOnPlayVoice({
      audioBytes: originalAudio,
      durationMs: 2_400,
      asset: 'USDC',
      slipAmount: 5_000_000n,
      slipId: '108',
      claimPrivateKey: TEST_KEY_CLAIM,
      beneficiarySigner: creatorAccount,
      slipUrl: baseSlip.webUrl,
      fetchFn: mockVoiceFetch,
      nowSec,
    });

    expect(uploaded.slipUrlWithVoice).toBeDefined();
    const voiceUrl = uploaded.slipUrlWithVoice!;
    // Secret markers MUST stay strictly inside the # fragment (never query string!)
    const parsedUrlObj = new URL(voiceUrl);
    expect(parsedUrlObj.search).toBe('');
    expect(parsedUrlObj.hash).toContain('_vn1_');
    expect(parsedUrlObj.hash).toContain(`&vk=${uploaded.fragmentVoiceKey}`);

    const parsedSlip = parseSlipUrl(voiceUrl);
    expect(parsedSlip?.hasVoiceNote).toBe(true);
    expect(parsedSlip?.voiceKey).toBe(uploaded.fragmentVoiceKey);

    expect(
      await checkBurnOnPlayVoiceStatus({
        slipUrl: voiceUrl,
        fetchFn: mockVoiceFetch,
        nowSec,
      }),
    ).toBe('available');

    const played = await playAndBurnVoice({
      slipUrl: voiceUrl,
      fetchFn: mockVoiceFetch,
      nowSec,
    });
    expect(played.burned).toBe(true);
    expect(played.durationMs).toBe(2_400);
    expect(played.audioBytes).toEqual(originalAudio);

    // Second play attempt fails closed because the slot was burned on first play!
    await expect(
      playAndBurnVoice({
        slipUrl: voiceUrl,
        fetchFn: mockVoiceFetch,
        nowSec,
      }),
    ).rejects.toThrow('Voice note is not available');

    expect(
      await burnVoiceNoteNow({
        slipUrl: voiceUrl,
        fetchFn: mockVoiceFetch,
        nowSec,
      }),
    ).toBe(false);
  });
});

describe('@cryptoslip/sdk — receipts.ts (Signed Proof-of-Payment, 1-RPC-Batch Verification & Green-Zone HTML)', () => {
  const sampleTxHash = keccak256(stringToHex('sample-settled-slip-tx-1'));

  it('5. Signs PaymentReceiptBundleV1 (viem & ethers v6 parity), verifies 1-RPC-batch logs, blocks asset spoofing & passes Live Base RPC check', async () => {
    const gross = grossUpForExactNet(20_000_000n); // 20.00 USDC net -> 20,100,503 gross
    const fee = computeProtocolFeeCeiling(gross);
    const net = deductProtocolFeeCeiling(gross);
    expect(net).toBe(20_000_000n);

    const signedViem = await createSignedPaymentReceipt({
      vault: 'v33',
      slipId: '512',
      txHash: sampleTxHash,
      blockNumber: 38_500_123,
      blockTimestamp: 1_795_200_000,
      settlementType: 'split_pay',
      asset: 'USDC',
      grossAmount: gross,
      feeAmount: fee,
      netAmount: net,
      recipient: merchantAccount.address,
      merchantLabel: 'Asuncion Coffee Bar',
      orderId: 'ord_9912',
      issuedAt: '2026-11-21T07:00:00.000Z',
      signer: issuerAccount,
    });

    const ethersIssuer = new Wallet(TEST_KEY_ISSUER);
    const signedEthers = await createSignedPaymentReceipt({
      vault: 'v33',
      slipId: '512',
      txHash: sampleTxHash,
      blockNumber: 38_500_123,
      blockTimestamp: 1_795_200_000,
      settlementType: 'split_pay',
      asset: 'USDC',
      grossAmount: gross,
      feeAmount: fee,
      netAmount: net,
      recipient: merchantAccount.address,
      merchantLabel: 'Asuncion Coffee Bar',
      orderId: 'ord_9912',
      issuedAt: '2026-11-21T07:00:00.000Z',
      signer: ethersIssuer,
    });

    expect(signedViem.signature?.toLowerCase()).toBe(signedEthers.signature?.toLowerCase());
    expect(await verifyPaymentReceiptSignature(signedViem)).toBe(true);

    // Tampering netAmount invalidates signature immediately
    expect(
      await verifyPaymentReceiptSignature({ ...signedViem, netAmount: '25000000' }),
    ).toBe(false);

    // Build real ABI-encoded Vault SlipSplitAndPaid + USDC Transfer logs
    const splitTopics = encodeEventTopics({
      abi: CRYPTO_SLIP_VAULT_V32_ABI,
      eventName: 'SlipSplitAndPaid',
      args: {
        originalSlipId: 512n,
        changeSlipId: 513n,
        merchant: merchantAccount.address,
      },
    }) as (`0x${string}`)[];
    const splitData = encodeAbiParameters(parseAbiParameters('uint256, uint256'), [
      gross,
      4_899_497n,
    ]);

    const transferTopics = encodeEventTopics({
      abi: ERC20_PERMIT_EIP3009_ABI,
      eventName: 'Transfer',
      args: {
        from: CANONICAL_VAULT_V33_ADDRESS,
        to: merchantAccount.address,
      },
    }) as (`0x${string}`)[];
    const transferData = encodeAbiParameters(parseAbiParameters('uint256'), [net]);

    const getReceiptSpy = vi.fn(async () => ({
      status: 'success' as const,
      blockNumber: 38_500_123n,
      transactionHash: sampleTxHash,
      logs: [
        { address: USDC_BASE_ADDRESS, topics: transferTopics, data: transferData },
        { address: CANONICAL_VAULT_V33_ADDRESS, topics: splitTopics, data: splitData },
      ],
    }));
    const getBlockSpy = vi.fn(async () => ({ timestamp: 1_795_200_000n }));

    const mockPublicClient: ReceiptVerificationClientAlias = {
      getTransactionReceipt: getReceiptSpy,
      getBlock: getBlockSpy,
    };

    const checkOk = await verifyPaymentReceiptOnChain(mockPublicClient, signedViem, {
      expectedRecipient: merchantAccount.address,
      expectedAsset: 'USDC',
      minNetAmount: 20_000_000n,
      expectedIssuer: issuerAccount.address,
      requireIssuerSignature: true,
    });
    expect(checkOk.valid).toBe(true);
    expect(checkOk.issuerVerified).toBe(true);
    expect(checkOk.verifiedNetAmount).toBe(20_000_000n);
    expect(getReceiptSpy).toHaveBeenCalledTimes(1);
    expect(getBlockSpy).toHaveBeenCalledTimes(1);

    // Cross-asset spoofing defense: if Transfer log came from a fake token instead of canonical USDC, reject!
    const spoofedClient: ReceiptVerificationClientAlias = {
      getTransactionReceipt: async () => ({
        status: 'success',
        blockNumber: 38_500_123n,
        logs: [
          { address: altCreatorAccount.address, topics: transferTopics, data: transferData },
          { address: CANONICAL_VAULT_V33_ADDRESS, topics: splitTopics, data: splitData },
        ],
      }),
      getBlock: async () => ({ timestamp: 1_795_200_000n }),
    };
    const spoofedRes = await verifyPaymentReceiptOnChain(spoofedClient, signedViem);
    expect(spoofedRes.valid).toBe(false);
    expect(spoofedRes.reason).toContain('Transfer log');

    // Live read-only Base Mainnet (8453) RPC check confirming v33 Vault contract code exists on Base
    const liveBaseClient = createPublicClient({
      chain: base,
      transport: fallback(DEFAULT_BASE_RPC_URLS.map((u) => http(u, { timeout: 8_000 }))),
    });
    const vaultBytecode = await liveBaseClient.getCode({ address: CANONICAL_VAULT_V33_ADDRESS });
    expect(vaultBytecode && vaultBytecode.length > 100).toBe(true);
  });

  it('6. Renders 100% Legal Green-Zone printable HTML (zero banned words, zero external requests, XSS-safe) & formula-safe CSV', async () => {
    const receipt = await createSignedPaymentReceipt({
      vault: 'v33',
      slipId: '888',
      txHash: sampleTxHash,
      blockNumber: 38_600_000,
      blockTimestamp: 1_795_300_000,
      settlementType: 'claim',
      asset: 'USDC',
      grossAmount: '20100503',
      feeAmount: '100503',
      netAmount: '20000000',
      recipient: merchantAccount.address,
      merchantLabel: '=HYPERLINK("https://evil.test") <script>alert(1)</script>',
      orderId: 'order_green_1',
      signer: issuerAccount,
    });

    const csv = formatReceiptsCsv([receipt]);
    const row = formatReceiptCsvRow(receipt);
    // Formula injection neutralized with leading apostrophe
    expect(row).toContain(`"'=HYPERLINK`);
    expect(csv.split('\n')).toHaveLength(2);

    const html = renderPrintableReceiptHtml(receipt);
    expect(html).toContain('Payment Receipt');
    expect(html).toContain('Non-custodial settlement on Base');
    expect(html).toContain('20.00 USDC');
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');

    // Zero external network requests in printable HTML
    expect(html).not.toMatch(/\b(?:src|href)=["']https?:\/\//i);
    expect(html).not.toMatch(/@import\s+url/i);

    // Exhaustive AGENTS.md Rule #3 Red-Zone scan across the rendered HTML
    const sanitizedForScan = html.replace(/HYPERLINK\([^)]*\)/g, '');
    const bannedPatterns = [
      /\bcash\b/i,
      /\bdollars?\b/i,
      /\bbank\b/i,
      /\baccount\b/i,
      /\bdeposit\b/i,
      /\bescrow\w*\b/i,
      /\bbearer\b/i,
      /\b(un)?lock(ed|s|ing)?\b/i,
      /\byield\b/i,
      /\bAPY\b/i,
      /\binterest\b/i,
      /\bmixer\b/i,
      /\bTornado\b/i,
      /\bFDIC\b/i,
      /\bexpir(e|es|ed|ing|ation)\b/i,
      /\bprincipal\b/i,
      /\bwNARA\b/,
      /\bdrip\b/i,
      /\bepochs?\b/i,
      /\bvouchers?\b/i,
    ];
    for (const banned of bannedPatterns) {
      expect(sanitizedForScan, `HTML violated Green-Zone rule: ${banned}`).not.toMatch(banned);
    }

    const mintReceipt = await createSignedPaymentReceipt({
      ...receipt,
      settlementType: 'mint',
      feeAmount: '0',
      grossAmount: '20000000',
      netAmount: '20000000',
    });
    const mintHtml = renderPrintableReceiptHtml(mintReceipt).replace(/HYPERLINK\([^)]*\)/g, '');
    expect(mintHtml).toContain('Slip created');
    for (const banned of bannedPatterns) {
      expect(mintHtml, `Mint HTML violated Green-Zone rule: ${banned}`).not.toMatch(banned);
    }
  });
});

type ReceiptVerificationClientAlias = Parameters<typeof verifyPaymentReceiptOnChain>[0];

describe('@cryptoslip/sdk — middleware.ts (withCryptoSlip 402 Tollbooth, V-03 Race Lock, V-05 Combine Guard & Refund Header)', () => {
  it('7. Issues HTTP 402 challenge, settles Watch-Only slip, blocks concurrent slipId race (409), supports Hono/Express & attaches X-Payment-Refund-Slip', async () => {
    const requiredNet = 1_000_000n; // 1.00 USDC net
    const requiredGross = grossUpForExactNet(requiredNet); // 1,005,026 USDC gross
    expect(requiredGross).toBe(1_005_026n);

    // Paid slip carries $1.50 USDC gross (1_500_000n) -> net = 1_492_500n (leaves ~0.4925 USDC overcharge!)
    const overpaidSlipGross = 1_500_000n;
    const settledTxHash = keccak256(stringToHex('middleware-settled-tx-1'));

    let settleCallCount = 0;
    const mockPublicClient: TollboothPublicClient = {
      readContract: async ({ functionName, args }) => {
        const queriedId = BigInt((args?.[0] as bigint) ?? 0n);
        if (functionName === 'slips') {
          if (queriedId === 901n) {
            // Unlocked slip (should fail requireNoTakeBack)
            return [
              USDC_BASE_ADDRESS,
              overpaidSlipGross,
              1_795_000_000n,
              0n,
              creatorAccount.address,
              claimAccount.address,
              SlipStatus.ACTIVE,
            ] as const;
          }
          if (queriedId === 902n) {
            return [
              USDC_BASE_ADDRESS,
              overpaidSlipGross,
              1_795_000_000n,
              NO_TAKE_BACK_LOCK,
              altCreatorAccount.address,
              claimAccount.address,
              SlipStatus.ACTIVE,
            ] as const;
          }
          return [
            USDC_BASE_ADDRESS,
            overpaidSlipGross,
            1_795_000_000n,
            NO_TAKE_BACK_LOCK,
            creatorAccount.address,
            claimAccount.address,
            SlipStatus.ACTIVE,
          ] as const;
        }
        if (functionName === 'nonces') {
          return 0n;
        }
        throw new Error(`Unexpected readContract: ${functionName}`);
      },
      getBlock: async () => ({ timestamp: 1_795_100_000n, number: 38_700_000n }),
      getTransactionReceipt: async () => ({
        status: 'success',
        blockNumber: 38_700_001n,
        logs: [],
      }),
    };

    const replayGuard = new SlipReplayGuard();

    const handler = withCryptoSlip(
      {
        merchantAddress: merchantAccount.address,
        asset: 'USDC',
        minNetAmount: requiredNet,
        merchantLabel: 'Compute API',
        requireNoTakeBack: true,
        publicClient: mockPublicClient,
        replayGuard,
        settler: async () => {
          settleCallCount += 1;
          // Simulate 40ms network relay latency so concurrent request #2 races in-flight!
          await new Promise((r) => setTimeout(r, 40));
          return {
            txHash: settledTxHash,
            blockNumber: 38_700_001,
            blockTimestamp: 1_795_100_002,
          };
        },
      },
      async (_req, ctx) => {
        // Endpoint metered actual compute usage at 1.10 USDC (1_100_000n) out of 1.4925 USDC paid net
        const baseResp = Response.json({
          ok: true,
          settledNet: ctx.netAmount.toString(),
          slipId: ctx.slipId,
        });
        return attachRefundSlipHeader(baseResp, {
          asset: 'USDC',
          paidNetAmount: ctx.netAmount,
          usedNetAmount: 1_100_000n,
          mintRefundSlip: async ({ refundDelta, cancelLockedUntil }) => {
            expect(cancelLockedUntil).toBe(NO_TAKE_BACK_LOCK);
            expect(refundDelta).toBe(392_500n);
            return {
              slipId: '999',
              claimKey: TEST_KEY_REFUND_CLAIM,
            };
          },
        });
      },
    );

    // 7A. Missing X-Slip -> HTTP 402 Challenge
    const challengeResp = await handler(new Request('https://slip.naraprotocol.io/api/infer'));
    expect(challengeResp.status).toBe(402);
    expect(challengeResp.headers.get('WWW-Authenticate')).toContain('CryptoSlip');
    const acceptJson = JSON.parse(
      challengeResp.headers.get(X_CRYPTOSLIP_ACCEPT_HEADER) || '{}',
    ) as {
      chainId: number;
      vaultAddress: string;
      grossAmountRequired: string;
      checkoutUrl: string;
    };
    expect(acceptJson.chainId).toBe(8453);
    expect(acceptJson.vaultAddress).toBe(CANONICAL_VAULT_V33_ADDRESS);
    expect(acceptJson.grossAmountRequired).toBe('1005026');
    expect(acceptJson.checkoutUrl).toContain('https://slip.naraprotocol.io/#startapp=pay_');

    // 7B. Unlocked slip (#901, cancelLockedUntil = 0) rejected when requireNoTakeBack = true
    const unlockedSlip = encodeSlipUrl({
      id: '901',
      amount: 1.5,
      asset: 'USDC',
      vault: 'v33',
      mode: 'open',
      claimKey: TEST_KEY_CLAIM,
    });
    const unlockedResp = await handler(
      new Request('https://slip.naraprotocol.io/api/infer', {
        headers: { [X_SLIP_HEADER]: unlockedSlip.webUrl },
      }),
    );
    expect(unlockedResp.status).toBe(402);
    expect(unlockedResp.headers.get(X_CRYPTOSLIP_ERROR_HEADER)).toBe('no_take_back_required');

    // 7C. Concurrent Race Test (V-03): two identical slipId #900 requests fired simultaneously!
    const validLockedSlip = encodeSlipUrl({
      id: '900',
      amount: 1.5,
      asset: 'USDC',
      vault: 'v33',
      mode: 'open',
      claimKey: TEST_KEY_CLAIM,
      cancelLockedUntil: OFFGRID_PERMANENT_LOCK_UNTIL,
    });

    const [raceResp1, raceResp2] = await Promise.all([
      handler(
        new Request('https://slip.naraprotocol.io/api/infer', {
          headers: { [X_SLIP_HEADER]: validLockedSlip.webUrl },
        }),
      ),
      handler(
        new Request('https://slip.naraprotocol.io/api/infer', {
          headers: { [X_SLIP_HEADER]: validLockedSlip.webUrl },
        }),
      ),
    ]);

    const statuses = [raceResp1.status, raceResp2.status].sort((a, b) => a - b);
    expect(statuses).toEqual([200, 409]);
    expect(settleCallCount).toBe(1);

    const winner = raceResp1.status === 200 ? raceResp1 : raceResp2;
    const loser = raceResp1.status === 409 ? raceResp1 : raceResp2;
    expect(loser.headers.get(X_CRYPTOSLIP_ERROR_HEADER)).toBe('slip_in_flight');

    // Winner carries verified receipt header AND stateless No-take-back refund slip header!
    const receiptHeader = winner.headers.get(X_PAYMENT_RECEIPT_HEADER);
    expect(receiptHeader).toBeTruthy();
    const decodedReceipt = decodeReceiptHeaderValue(receiptHeader!);
    expect(decodedReceipt.slipId).toBe('900');
    expect(decodedReceipt.netAmount).toBe('1492500');
    expect(decodedReceipt.recipient).toBe(merchantAccount.address);

    const refundSlipUrl = winner.headers.get(X_PAYMENT_REFUND_SLIP_HEADER);
    expect(refundSlipUrl).toBeTruthy();
    expect(refundSlipUrl).toContain('https://slip.naraprotocol.io/#startapp=slip_999_');
    expect(refundSlipUrl).toContain('_cl9999999999_');
    expect(winner.headers.get(X_PAYMENT_REFUND_AMOUNT_HEADER)).toBe('392500');
    const parsedRefund = parseSlipUrl(refundSlipUrl!);
    expect(parsedRefund?.cancelLockedUntil).toBe(OFFGRID_PERMANENT_LOCK_UNTIL);

    // 7D. Subsequent sequential replay of #900 -> 409 slip_already_settled
    const replayResp = await handler(
      new Request('https://slip.naraprotocol.io/api/infer', {
        headers: { [X_SLIP_HEADER]: validLockedSlip.webUrl },
      }),
    );
    expect(replayResp.status).toBe(409);
    expect(replayResp.headers.get(X_CRYPTOSLIP_ERROR_HEADER)).toBe('slip_already_settled');

    // 7E. Sub-minimum dust refund (< $0.10 USDC) skips minting cleanly without error
    const dustCallback = vi.fn();
    const untouched = await attachRefundSlipHeader(Response.json({ ok: true }), {
      asset: 'USDC',
      paidNetAmount: 1_000_000n,
      usedNetAmount: 950_000n, // 0.05 USDC < 0.10 USDC v33 minimum
      mintRefundSlip: dustCallback,
    });
    expect(dustCallback).not.toHaveBeenCalled();
    expect(untouched.headers.get(X_PAYMENT_REFUND_SLIP_HEADER)).toBeNull();

    // 7F. V-05 Combine mixed-creator guard + Hono & Express middleware adapters
    const mw = withCryptoSlip({
      merchantAddress: merchantAccount.address,
      asset: 'USDC',
      minNetAmount: requiredNet,
      publicClient: mockPublicClient,
      settler: async () => ({
        txHash: keccak256(stringToHex('mw-hono-express-tx')),
        blockNumber: 38_700_010,
        blockTimestamp: 1_795_100_020,
      }),
    });

    // V-05: Combining locked slip #900 (creator 1) + locked slip #902 (creator 2) is rejected!
    const mixedCombineHeader = JSON.stringify({
      kind: 'combine',
      vault: 'v33',
      slipIds: ['903', '902'],
      signatures: ['0x' + '11'.repeat(65), '0x' + '22'.repeat(65)],
      paymentAmount: '1500000',
      merchant: merchantAccount.address,
      changeReceiver: CANONICAL_VAULT_V33_ADDRESS,
      newChangeSigner: claimAccount.address,
      deadline: '1899999999',
    });
    const honoCtxBad = {
      req: {
        raw: new Request('https://slip.naraprotocol.io/api/hono', {
          headers: { [X_SLIP_HEADER]: mixedCombineHeader },
        }),
      },
      set: vi.fn(),
    };
    const honoBadOut = await mw(honoCtxBad, async () => {});
    expect(honoBadOut).toBeInstanceOf(Response);
    expect((honoBadOut as Response).headers.get(X_CRYPTOSLIP_ERROR_HEADER)).toBe(
      'mixed_locked_creators',
    );

    // Express adapter happy path on fresh slip #904
    const freshSlip904 = encodeSlipUrl({
      id: '904',
      amount: 1.5,
      asset: 'USDC',
      vault: 'v33',
      mode: 'open',
      claimKey: TEST_KEY_CLAIM,
      cancelLockedUntil: OFFGRID_PERMANENT_LOCK_UNTIL,
    });
    const expressHeadersOut: Record<string, string> = {};
    const nodeReq = {
      method: 'POST',
      url: '/v1/chat/completions',
      headers: {
        host: 'slip.naraprotocol.io',
        'x-slip': freshSlip904.webUrl,
      },
    } as Record<string, unknown>;
    let nextCalled = false;
    await mw(
      nodeReq as any,
      {
        setHeader: (k: string, v: string) => {
          expressHeadersOut[k] = v;
        },
      },
      () => {
        nextCalled = true;
      },
    );
    expect(nextCalled).toBe(true);
    expect(expressHeadersOut[X_PAYMENT_RECEIPT_HEADER]).toBeTruthy();
  });

  it('8. Path C (X-Payment-Tx) verifies SlipSplitAndPaid + overpayment (overpaidNetAmount > 0n), locks consumed slipId, and enforces combine V-03 + InvalidSigner pre-checks', async () => {
    const requiredNet = 1_000_000n; // 1.00 USDC
    const splitPaymentGross = 1_500_000n; // 1.50 USDC gross -> 7,500 fee -> 1,492,500 net (492,500 overpaid!)
    const splitNet = deductProtocolFeeCeiling(splitPaymentGross);
    expect(splitNet).toBe(1_492_500n);

    const popupSplitTxHash = keccak256(stringToHex('popup-checkout-split-tx-777'));
    const splitTopics = encodeEventTopics({
      abi: CRYPTO_SLIP_VAULT_V32_ABI,
      eventName: 'SlipSplitAndPaid',
      args: {
        originalSlipId: 777n,
        changeSlipId: 778n,
        merchant: merchantAccount.address,
      },
    }) as (`0x${string}`)[];
    const splitData = encodeAbiParameters(parseAbiParameters('uint256, uint256'), [
      splitPaymentGross,
      500_000n,
    ]);
    const transferTopics = encodeEventTopics({
      abi: ERC20_PERMIT_EIP3009_ABI,
      eventName: 'Transfer',
      args: {
        from: CANONICAL_VAULT_V33_ADDRESS,
        to: merchantAccount.address,
      },
    }) as (`0x${string}`)[];
    const transferData = encodeAbiParameters(parseAbiParameters('uint256'), [splitNet]);

    const mockClient: TollboothPublicClient = {
      readContract: async ({ functionName }) => {
        if (functionName === 'slips') {
          return [
            USDC_BASE_ADDRESS,
            1_000_000n, // $1.00 each (so 2 slips = $2.00 total backing)
            1_795_000_000n,
            NO_TAKE_BACK_LOCK,
            creatorAccount.address,
            claimAccount.address,
            SlipStatus.ACTIVE,
          ] as const;
        }
        return 0n;
      },
      getBlock: async () => ({ timestamp: 1_795_400_000n, number: 38_800_000n }),
      getTransactionReceipt: async () => ({
        status: 'success',
        blockNumber: 38_800_000n,
        transactionHash: popupSplitTxHash,
        logs: [
          { address: USDC_BASE_ADDRESS, topics: transferTopics, data: transferData },
          { address: CANONICAL_VAULT_V33_ADDRESS, topics: splitTopics, data: splitData },
        ],
      }),
    };

    const replayGuard = new SlipReplayGuard();
    const txHandler = withCryptoSlip(
      {
        merchantAddress: merchantAccount.address,
        asset: 'USDC',
        minNetAmount: requiredNet,
        publicClient: mockClient,
        replayGuard,
      },
      async (_req, ctx) =>
        Response.json({
          ok: true,
          settlementType: ctx.receipt.settlementType,
          slipId: ctx.slipId,
          netAmount: ctx.netAmount.toString(),
          overpaidNetAmount: ctx.overpaidNetAmount.toString(),
        }),
    );

    // 8A. X-Payment-Tx for SlipSplitAndPaid with overpayment passes & preserves exact 492,500 overpaidNetAmount
    const txResp = await txHandler(
      new Request('https://slip.naraprotocol.io/api/paid', {
        headers: { [X_PAYMENT_TX_HEADER]: popupSplitTxHash },
      }),
    );
    expect(txResp.status).toBe(200);
    const txBody = (await txResp.json()) as {
      ok: boolean;
      settlementType: string;
      slipId: string;
      netAmount: string;
      overpaidNetAmount: string;
    };
    expect(txBody).toEqual({
      ok: true,
      settlementType: 'split_pay',
      slipId: '777',
      netAmount: '1492500',
      overpaidNetAmount: '492500',
    });

    // 8B. Discovered slipId #777 is locked in SlipReplayGuard against subsequent X-Slip replay!
    const slip777 = encodeSlipUrl({
      id: '777',
      amount: 1.5,
      asset: 'USDC',
      vault: 'v33',
      mode: 'open',
      claimKey: TEST_KEY_CLAIM,
      cancelLockedUntil: OFFGRID_PERMANENT_LOCK_UNTIL,
    });
    const slipReplayResp = await txHandler(
      new Request('https://slip.naraprotocol.io/api/paid', {
        headers: { [X_SLIP_HEADER]: slip777.webUrl },
      }),
    );
    expect(slipReplayResp.status).toBe(409);
    expect(slipReplayResp.headers.get(X_CRYPTOSLIP_ERROR_HEADER)).toBe('slip_already_settled');

    // 8C. Combine V-03 dust cliff: 2 slips ($2.00 = 2_000_000n) minus 1_950_000n leaves 50_000n (< 100_000n min) -> dust_cliff
    const combineDustHeader = JSON.stringify({
      kind: 'combine',
      vault: 'v33',
      slipIds: ['801', '802'],
      signatures: ['0x' + '11'.repeat(65), '0x' + '22'.repeat(65)],
      paymentAmount: '1950000',
      merchant: merchantAccount.address,
      changeReceiver: CANONICAL_VAULT_V33_ADDRESS,
      newChangeSigner: claimAccount.address,
      deadline: '1899999999',
    });
    const dustResp = await txHandler(
      new Request('https://slip.naraprotocol.io/api/paid', {
        headers: { [X_SLIP_HEADER]: combineDustHeader },
      }),
    );
    expect(dustResp.status).toBe(402);
    expect(dustResp.headers.get(X_CRYPTOSLIP_ERROR_HEADER)).toBe('dust_cliff');

    // 8D. Combine exact full-amount (remainder === 0n) with non-zero changeReceiver -> invalid_change_signer
    const combineBadZeroChangeHeader = JSON.stringify({
      kind: 'combine',
      vault: 'v33',
      slipIds: ['803', '804'],
      signatures: ['0x' + '11'.repeat(65), '0x' + '22'.repeat(65)],
      paymentAmount: '2000000',
      merchant: merchantAccount.address,
      changeReceiver: CANONICAL_VAULT_V33_ADDRESS,
      newChangeSigner: claimAccount.address,
      deadline: '1899999999',
    });
    const badChangeResp = await txHandler(
      new Request('https://slip.naraprotocol.io/api/paid', {
        headers: { [X_SLIP_HEADER]: combineBadZeroChangeHeader },
      }),
    );
    expect(badChangeResp.status).toBe(402);
    expect(badChangeResp.headers.get(X_CRYPTOSLIP_ERROR_HEADER)).toBe('invalid_change_signer');
  });

  it('9. Verifies signed HMAC-SHA256 partner webhooks (t=...,v1=..., 300s replay window, tampered body/header rejection & domain-separated signing key derivation)', () => {
    // Confirm root re-export from @cryptoslip/sdk index.ts
    expect(sdkIndex.verifyPartnerWebhookSignature).toBe(verifyPartnerWebhookSignature);

    const enc = new TextEncoder();
    const toHex = (bytes: Uint8Array) =>
      Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

    const runtimeWebhookSecret = `whsec_${keccak256(stringToHex('sdk-webhook-secret-test')).slice(2, 34)}`;
    const runtimePartnerKey = `csk_${keccak256(stringToHex('sdk-partner-key-test')).slice(2, 42)}`;
    const runtimePartnerKeySha256Hex = toHex(sha256(enc.encode(runtimePartnerKey)));
    const domainDerivedSigningKeyHex = toHex(
      hmac(sha256, enc.encode('cryptoslip-webhook-signing-v1'), enc.encode(runtimePartnerKey)),
    );

    const nowSeconds = 1_795_500_000;
    const eventType: PartnerWebhookEventType = 'checkout.paid';
    const sampleTxHash = keccak256(stringToHex('partner-webhook-tx-1'));

    const payload: PartnerWebhookPayload = {
      version: 1,
      id: `v33:912:${eventType}:${sampleTxHash}`,
      event: eventType,
      partnerSlug: 'acme-pos',
      chainId: 8453,
      vault: 'v33',
      vaultAddress: CANONICAL_VAULT_V33_ADDRESS,
      slipId: '912',
      txHash: sampleTxHash,
      creator: creatorAccount.address,
      recipient: merchantAccount.address,
      asset: 'USDC',
      assetAddress: USDC_BASE_ADDRESS,
      amount: '2487500',
      grossAmount: '2500000',
      feeAmount: '12500',
      netAmount: '2487500',
      timestamp: nowSeconds,
    };
    const rawBody = JSON.stringify(payload);

    const signWith = (secret: string, ts: number, body: string) => {
      const mac = hmac(sha256, enc.encode(secret), enc.encode(`${ts}.${body}`));
      return `t=${ts},v1=${toHex(mac)}`;
    };

    // 9A. Valid explicit webhookSecret within 300s window -> true (both string and Uint8Array rawBody)
    const validHeader = signWith(runtimeWebhookSecret, nowSeconds - 120, rawBody);
    expect(
      verifyPartnerWebhookSignature({
        rawBody,
        signatureHeader: validHeader,
        secret: runtimeWebhookSecret,
        nowSeconds,
      }),
    ).toBe(true);
    expect(
      verifyPartnerWebhookSignature({
        rawBody: enc.encode(rawBody),
        signatureHeader: validHeader,
        secret: runtimeWebhookSecret,
        nowSeconds,
      }),
    ).toBe(true);

    // 9B. Boundary check: +/- 300s accepted, +/- 301s rejected, non-positive nowSeconds rejected
    expect(
      verifyPartnerWebhookSignature({
        rawBody,
        signatureHeader: signWith(runtimeWebhookSecret, nowSeconds - 300, rawBody),
        secret: runtimeWebhookSecret,
        nowSeconds,
      }),
    ).toBe(true);
    expect(
      verifyPartnerWebhookSignature({
        rawBody,
        signatureHeader: signWith(runtimeWebhookSecret, nowSeconds - 301, rawBody),
        secret: runtimeWebhookSecret,
        nowSeconds,
      }),
    ).toBe(false);
    expect(
      verifyPartnerWebhookSignature({
        rawBody,
        signatureHeader: signWith(runtimeWebhookSecret, nowSeconds + 301, rawBody),
        secret: runtimeWebhookSecret,
        nowSeconds,
      }),
    ).toBe(false);
    expect(
      verifyPartnerWebhookSignature({
        rawBody,
        signatureHeader: signWith(runtimeWebhookSecret, 1, rawBody),
        secret: runtimeWebhookSecret,
        toleranceSeconds: 1000,
        nowSeconds: 0,
      }),
    ).toBe(false);
    expect(
      verifyPartnerWebhookSignature({
        rawBody,
        signatureHeader: signWith(runtimeWebhookSecret, 1, rawBody),
        secret: runtimeWebhookSecret,
        toleranceSeconds: 1000,
        nowSeconds: -10,
      }),
    ).toBe(false);

    // Custom toleranceSeconds override (e.g., 60s)
    expect(
      verifyPartnerWebhookSignature({
        rawBody,
        signatureHeader: signWith(runtimeWebhookSecret, nowSeconds - 90, rawBody),
        secret: runtimeWebhookSecret,
        toleranceSeconds: 60,
        nowSeconds,
      }),
    ).toBe(false);

    // 9C. Tampered body, wrong secret, or malformed headers -> false
    expect(
      verifyPartnerWebhookSignature({
        rawBody: `${rawBody} `,
        signatureHeader: validHeader,
        secret: runtimeWebhookSecret,
        nowSeconds,
      }),
    ).toBe(false);
    expect(
      verifyPartnerWebhookSignature({
        rawBody,
        signatureHeader: validHeader,
        secret: `${runtimeWebhookSecret}_wrong`,
        nowSeconds,
      }),
    ).toBe(false);
    expect(
      verifyPartnerWebhookSignature({
        rawBody,
        signatureHeader: `t=${nowSeconds},t=${nowSeconds},v1=${'a'.repeat(64)}`,
        secret: runtimeWebhookSecret,
        nowSeconds,
      }),
    ).toBe(false);
    expect(
      verifyPartnerWebhookSignature({
        rawBody,
        signatureHeader: '',
        secret: runtimeWebhookSecret,
        nowSeconds,
      }),
    ).toBe(false);

    // 9D. [CRITICAL F-01] Domain-separated signing key derivation (`cryptoslip-webhook-signing-v1`)
    // Worker signs with `HMAC-SHA256('cryptoslip-webhook-signing-v1', rawPartnerKey)` -> SDK verifies with `rawPartnerKey`
    const domainDerivedHeader = signWith(domainDerivedSigningKeyHex, nowSeconds, rawBody);
    expect(
      verifyPartnerWebhookSignature({
        rawBody,
        signatureHeader: domainDerivedHeader,
        secret: runtimePartnerKey,
        nowSeconds,
      }),
    ).toBe(true);
    // Passing leaked `sha256Hex(rawPartnerKey)` (`keyDigestHex` from PARTNER_API_KEYS_JSON) as `secret` MUST FAIL!
    expect(
      verifyPartnerWebhookSignature({
        rawBody,
        signatureHeader: domainDerivedHeader,
        secret: runtimePartnerKeySha256Hex,
        nowSeconds,
      }),
    ).toBe(false);
    // Forging a webhook signature using leaked `keyDigestHex` (`sha256Hex(rawPartnerKey)`) MUST FAIL against `rawPartnerKey`!
    const forgedWithKeyDigestHeader = signWith(runtimePartnerKeySha256Hex, nowSeconds, rawBody);
    expect(
      verifyPartnerWebhookSignature({
        rawBody,
        signatureHeader: forgedWithKeyDigestHeader,
        secret: runtimePartnerKey,
        nowSeconds,
      }),
    ).toBe(false);
  });
});
