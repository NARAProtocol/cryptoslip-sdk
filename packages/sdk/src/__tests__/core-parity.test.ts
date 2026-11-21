import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import util from 'node:util';
import { describe, expect, it } from 'vitest';
import { ethers } from 'ethers';
import {
  createPublicClient,
  createWalletClient,
  fallback,
  http,
  keccak256,
  recoverTypedDataAddress,
  stringToHex,
  type Hex,
} from 'viem';
import { privateKeyToAccount, privateKeyToAddress } from 'viem/accounts';
import { base } from 'viem/chains';

import {
  ASSETS,
  BASE_CHAIN_ID,
  CANONICAL_SHARE_ORIGIN,
  CANONICAL_TRADE_ROUTER_V33_ADDRESS,
  CANONICAL_VAULT_V33_ADDRESS,
  CBBTC_BASE_ADDRESS,
  DEFAULT_BASE_RPC_URLS,
  DEFAULT_CRYPTOSLIP_BUILDER_CODE,
  DEFAULT_NARA_BUILDER_CODE,
  ERC8021_MARKER_HEX,
  FEE_BPS,
  NARA_BASE_ADDRESS,
  NATIVE_ETH_ADDRESS,
  NO_TAKE_BACK_LOCK,
  SOVEREIGN_ENS_ORIGIN,
  USDC_BASE_ADDRESS,
  V33_MICRO_MINIMUMS,
  V33_VAULT_DOMAIN_SEPARATOR,
  appendBuilderCodeSuffix,
  appendErc8021DataSuffix,
  canBindReferrerOnV33,
  computeFeeAndReferralSplit,
  computeProtocolFeeCeiling,
  deductProtocolFeeCeiling,
  grossUpForExactNet,
  minSlipAmount,
  toErc8021DataSuffix,
} from '../constants.js';
import {
  CRYPTO_SLIP_TRADE_ROUTER_V32_ABI,
  CRYPTO_SLIP_VAULT_V32_ABI,
  ERC20_PERMIT_EIP3009_ABI,
  MULTICALL3_ABI,
} from '../abi.js';
import {
  COMPACT_BINARY_SLIP_BYTE_LENGTH,
  SlipLinkSecurityError,
  buildPopupCheckoutUrl,
  buildReceivedSlipLink,
  buildSealedSlipShareUrl,
  buildSlipLinks,
  buildSovereignSlipLink,
  buildTelegramStartAppUrl,
  buildWatchOnlyPosUrl,
  decodeCompactBinarySlipPayload,
  decodePaymentRequest,
  decodeReferralInvite,
  decodeSlipPayload,
  deriveCodeWallet,
  encodeCompactBinarySlipPayload,
  encodePaymentRequest,
  encodeReferralInvite,
  encodeSlipPayload,
  encodeSlipUrl,
  formatClaimCode,
  generateClaimCode,
  generateCodeSalt,
  parsePopupCheckoutUrl,
  parseSlipUrl,
  parseWatchOnlyPosUrl,
  reconstructUnsealedClaimKey,
  sealSlipSecretPart,
  unsealSlipSecretPart,
} from '../link.js';
import {
  ACCEPT_PERMIT_V32_TYPES,
  CASH_PERMIT_TYPES,
  CBBTC_BASE_DOMAIN,
  COMPOSITE_SWAP_OFFER_V32_TYPES,
  MINT_PERMIT_V32_TYPES,
  NARA_BASE_DOMAIN,
  REARRANGE_PERMIT_V32_TYPES,
  REFERRAL_CONSENT_V32_TYPES,
  REFUND_PERMIT_V32_TYPES,
  SPLIT_PERMIT_TYPES,
  SWAP_AND_PAY_V32_TYPES,
  SWAP_OFFER_V32_TYPES,
  TRADE_OFFER_V32_TYPES,
  USDC_BASE_DOMAIN,
  assertValidCancelLock,
  computeEip712DomainSeparator,
  computeMintValidityWindow,
  computePermitDeadline,
  computeRearrangeSlipIdsHash,
  computeTradeRouterDomainSeparator,
  computeVaultDomainSeparator,
  createSlipSignerFromKey,
  deriveCreatedSlipKey,
  deriveKeptSlipHopKey,
  deriveKeptSlipKey,
  deriveNextSlipHolderKey,
  deriveSplitChangeSlipKey,
  fromEthersSigner,
  fromViemAccount,
  fromViemWalletClient,
  getTradeRouterDomain,
  getVaultDomain,
  packPermitWithReferralConsent,
  signAcceptPermit,
  signCashPermit,
  signCompositeSwapOfferPermit,
  signErc2612Permit,
  signMintPermit,
  signPairedEip3009Mint,
  signRearrangePermit,
  signReceiveWithAuthorization,
  signReferralConsent,
  signRefundPermit,
  signSplitPermit,
  signSwapAndPayPermit,
  signSwapOfferPermit,
  signTradeOfferPermit,
  unpackPermitWithReferralConsent,
} from '../permits.js';

// Runtime loader for workspace `client/src/lib/*` & `shared/*` reference modules so Vitest executes
// real cross-implementation parity checks without pulling Vite bundler-mode files into NodeNext `tsc`.
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const loadWorkspaceModule = async <T = Record<string, any>>(specifier: string): Promise<T> => {
  const actualRel = specifier.endsWith('.js') ? `${specifier.slice(0, -3)}.ts` : specifier;
  return (await import(pathToFileURL(path.resolve(TEST_DIR, actualRel)).href)) as T;
};

// Runtime-derived test keys (zero hardcoded 64-hex private key literals in source)
const TEST_KEY_1: Hex = keccak256(stringToHex('sdk-test-key-1'));
const TEST_KEY_2: Hex = keccak256(stringToHex('sdk-test-key-2'));
const TEST_KEY_3: Hex = keccak256(stringToHex('sdk-test-key-3'));
const TEST_SEAL_SCALAR: Hex = keccak256(stringToHex('sdk-test-seal-scalar-v1'));

describe('@cryptoslip/sdk core parity & live Base Mainnet verification', () => {
  it('computes exact v33 Vault DOMAIN_SEPARATOR and matches live Base Mainnet (8453) contracts via eth_call', async () => {
    const computedV33 = computeVaultDomainSeparator('v33');
    expect(computedV33).toBe(V33_VAULT_DOMAIN_SEPARATOR);

    const publicClient = createPublicClient({
      chain: base,
      transport: fallback(DEFAULT_BASE_RPC_URLS.map((url) => http(url, { timeout: 10_000 }))),
    });

    const [
      onChainVaultSep,
      onChainMintTh,
      onChainCashTh,
      onChainSplitTh,
      onChainRearrangeTh,
      onChainAcceptTh,
      onChainRefundTh,
      onChainConsentTh,
      minEth,
      minUsdc,
      minCbBtc,
      minNara,
      routerDomainTuple,
      onChainSwapTh,
      onChainTradeTh,
      onChainSwapPayTh,
      onChainCompositeTh,
      usdcSep,
      cbBtcSep,
      naraSep,
    ] = await Promise.all([
      publicClient.readContract({
        address: CANONICAL_VAULT_V33_ADDRESS,
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        functionName: 'DOMAIN_SEPARATOR',
      }),
      publicClient.readContract({
        address: CANONICAL_VAULT_V33_ADDRESS,
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        functionName: 'MINT_PERMIT_TYPEHASH',
      }),
      publicClient.readContract({
        address: CANONICAL_VAULT_V33_ADDRESS,
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        functionName: 'CASH_PERMIT_TYPEHASH',
      }),
      publicClient.readContract({
        address: CANONICAL_VAULT_V33_ADDRESS,
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        functionName: 'SPLIT_PERMIT_TYPEHASH',
      }),
      publicClient.readContract({
        address: CANONICAL_VAULT_V33_ADDRESS,
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        functionName: 'REARRANGE_PERMIT_TYPEHASH',
      }),
      publicClient.readContract({
        address: CANONICAL_VAULT_V33_ADDRESS,
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        functionName: 'ACCEPT_PERMIT_TYPEHASH',
      }),
      publicClient.readContract({
        address: CANONICAL_VAULT_V33_ADDRESS,
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        functionName: 'REFUND_PERMIT_TYPEHASH',
      }),
      publicClient.readContract({
        address: CANONICAL_VAULT_V33_ADDRESS,
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        functionName: 'REFERRAL_CONSENT_TYPEHASH',
      }),
      publicClient.readContract({
        address: CANONICAL_VAULT_V33_ADDRESS,
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        functionName: 'minSlipAmount',
        args: [NATIVE_ETH_ADDRESS],
      }),
      publicClient.readContract({
        address: CANONICAL_VAULT_V33_ADDRESS,
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        functionName: 'minSlipAmount',
        args: [USDC_BASE_ADDRESS],
      }),
      publicClient.readContract({
        address: CANONICAL_VAULT_V33_ADDRESS,
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        functionName: 'minSlipAmount',
        args: [CBBTC_BASE_ADDRESS],
      }),
      publicClient.readContract({
        address: CANONICAL_VAULT_V33_ADDRESS,
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        functionName: 'minSlipAmount',
        args: [NARA_BASE_ADDRESS],
      }),
      publicClient.readContract({
        address: CANONICAL_TRADE_ROUTER_V33_ADDRESS,
        abi: CRYPTO_SLIP_TRADE_ROUTER_V32_ABI,
        functionName: 'eip712Domain',
      }),
      publicClient.readContract({
        address: CANONICAL_TRADE_ROUTER_V33_ADDRESS,
        abi: CRYPTO_SLIP_TRADE_ROUTER_V32_ABI,
        functionName: 'SWAP_OFFER_TYPEHASH',
      }),
      publicClient.readContract({
        address: CANONICAL_TRADE_ROUTER_V33_ADDRESS,
        abi: CRYPTO_SLIP_TRADE_ROUTER_V32_ABI,
        functionName: 'TRADE_OFFER_TYPEHASH',
      }),
      publicClient.readContract({
        address: CANONICAL_TRADE_ROUTER_V33_ADDRESS,
        abi: CRYPTO_SLIP_TRADE_ROUTER_V32_ABI,
        functionName: 'SWAP_AND_PAY_TYPEHASH',
      }),
      publicClient.readContract({
        address: CANONICAL_TRADE_ROUTER_V33_ADDRESS,
        abi: CRYPTO_SLIP_TRADE_ROUTER_V32_ABI,
        functionName: 'COMPOSITE_SWAP_OFFER_TYPEHASH',
      }),
      publicClient.readContract({
        address: USDC_BASE_ADDRESS,
        abi: ERC20_PERMIT_EIP3009_ABI,
        functionName: 'DOMAIN_SEPARATOR',
      }),
      publicClient.readContract({
        address: CBBTC_BASE_ADDRESS,
        abi: ERC20_PERMIT_EIP3009_ABI,
        functionName: 'DOMAIN_SEPARATOR',
      }),
      publicClient.readContract({
        address: NARA_BASE_ADDRESS,
        abi: ERC20_PERMIT_EIP3009_ABI,
        functionName: 'DOMAIN_SEPARATOR',
      }),
    ]);

    expect(onChainVaultSep.toLowerCase()).toBe(V33_VAULT_DOMAIN_SEPARATOR.toLowerCase());
    expect(onChainVaultSep.toLowerCase()).toBe(computedV33.toLowerCase());

    const encodeTypeString = (
      typeName: string,
      fields: readonly { name: string; type: string }[],
    ) => `${typeName}(${fields.map((f) => `${f.type} ${f.name}`).join(',')})`;

    expect(onChainMintTh).toBe(
      keccak256(stringToHex(encodeTypeString('MintPermit', MINT_PERMIT_V32_TYPES.MintPermit))),
    );
    expect(onChainCashTh).toBe(
      keccak256(stringToHex(encodeTypeString('CashPermit', CASH_PERMIT_TYPES.CashPermit))),
    );
    expect(onChainSplitTh).toBe(
      keccak256(stringToHex(encodeTypeString('SplitPermit', SPLIT_PERMIT_TYPES.SplitPermit))),
    );
    expect(onChainRearrangeTh).toBe(
      keccak256(
        stringToHex(encodeTypeString('RearrangePermit', REARRANGE_PERMIT_V32_TYPES.RearrangePermit)),
      ),
    );
    expect(onChainAcceptTh).toBe(
      keccak256(stringToHex(encodeTypeString('AcceptPermit', ACCEPT_PERMIT_V32_TYPES.AcceptPermit))),
    );
    expect(onChainRefundTh).toBe(
      keccak256(stringToHex(encodeTypeString('RefundPermit', REFUND_PERMIT_V32_TYPES.RefundPermit))),
    );
    expect(onChainConsentTh).toBe(
      keccak256(
        stringToHex(encodeTypeString('ReferralConsent', REFERRAL_CONSENT_V32_TYPES.ReferralConsent)),
      ),
    );

    // Verify exact v33 micro-minimums on Base Mainnet
    expect(minEth).toBe(V33_MICRO_MINIMUMS.ETH);
    expect(minUsdc).toBe(V33_MICRO_MINIMUMS.USDC);
    expect(minCbBtc).toBe(V33_MICRO_MINIMUMS.cbBTC);
    expect(minNara).toBe(V33_MICRO_MINIMUMS.NARA);
    expect(minSlipAmount('USDC', 'v33')).toBe(100_000n);
    expect(minSlipAmount('cbBTC', 'v33')).toBe(100n);
    expect(minSlipAmount('ETH', 'v33')).toBe(1_000_000_000_000n);
    expect(minSlipAmount('NARA', 'v33')).toBe(1_000_000_000_000n);

    // Verify TradeRouter EIP-5267 domain & typehashes
    const routerDomain = getTradeRouterDomain('v33');
    expect(routerDomainTuple[1]).toBe(routerDomain.name);
    expect(routerDomainTuple[2]).toBe(routerDomain.version);
    expect(routerDomainTuple[3]).toBe(BigInt(BASE_CHAIN_ID));
    expect(routerDomainTuple[4].toLowerCase()).toBe(
      CANONICAL_TRADE_ROUTER_V33_ADDRESS.toLowerCase(),
    );
    expect(computeTradeRouterDomainSeparator('v33')).toBe(
      computeEip712DomainSeparator(routerDomain),
    );
    expect(onChainSwapTh).toBe(
      keccak256(
        stringToHex(encodeTypeString('SwapOfferPermit', SWAP_OFFER_V32_TYPES.SwapOfferPermit)),
      ),
    );
    expect(onChainTradeTh).toBe(
      keccak256(
        stringToHex(encodeTypeString('TradeOfferPermit', TRADE_OFFER_V32_TYPES.TradeOfferPermit)),
      ),
    );
    expect(onChainSwapPayTh).toBe(
      keccak256(
        stringToHex(encodeTypeString('SwapAndPayPermit', SWAP_AND_PAY_V32_TYPES.SwapAndPayPermit)),
      ),
    );
    expect(onChainCompositeTh).toBe(
      keccak256(
        stringToHex(
          encodeTypeString(
            'CompositeSwapOfferPermit',
            COMPOSITE_SWAP_OFFER_V32_TYPES.CompositeSwapOfferPermit,
          ),
        ),
      ),
    );

    // Verify live Base USDC, cbBTC & NARA DOMAIN_SEPARATOR() match our EIP-3009 / EIP-2612 domain configs!
    const clientEip3009Helper = await loadWorkspaceModule('../../../../client/src/lib/eip3009Helper.js');
    expect(usdcSep.toLowerCase()).toBe(
      computeEip712DomainSeparator(USDC_BASE_DOMAIN).toLowerCase(),
    );
    expect(cbBtcSep.toLowerCase()).toBe(
      computeEip712DomainSeparator(CBBTC_BASE_DOMAIN).toLowerCase(),
    );
    expect(naraSep.toLowerCase()).toBe(
      computeEip712DomainSeparator(NARA_BASE_DOMAIN).toLowerCase(),
    );
    expect(USDC_BASE_DOMAIN).toEqual(clientEip3009Helper.USDC_BASE_DOMAIN);
    expect(CBBTC_BASE_DOMAIN).toEqual(clientEip3009Helper.CBBTC_BASE_DOMAIN);
    expect(NARA_BASE_DOMAIN).toEqual(clientEip3009Helper.NARA_BASE_DOMAIN);
    expect(MULTICALL3_ABI.length).toBeGreaterThanOrEqual(4);
  });

  it('maintains 100% byte-for-byte link codec parity with client/src/lib/slipLink.ts across open, sovereign, voice, and note URLs', async () => {
    const clientSlipLink = await loadWorkspaceModule('../../../../client/src/lib/slipLink.js');
    const voiceKey = 'AbCdEfGhIjKlMnOpQrStUv12';
    const cases = [
      { id: '1', amount: 0.1, asset: 'USDC' as const, vault: 'v33' as const, lock: undefined },
      { id: '42', amount: 25.5, asset: 'USDC' as const, vault: 'v33' as const, lock: 9_999_999_999 },
      { id: '108', amount: 0.000525, asset: 'cbBTC' as const, vault: 'v33' as const, lock: 9_999_999_999 },
      { id: '999', amount: 0.015, asset: 'ETH' as const, vault: 'v32' as const, lock: undefined },
      { id: '2048', amount: 12.3456, asset: 'NARA' as const, vault: 'v33' as const, lock: 9_999_999_999 },
    ];

    for (const c of cases) {
      const clientAsset = c.asset === 'cbBTC' ? 'BTC' : c.asset;
      const sdkPayload = encodeSlipPayload({
        id: c.id,
        amount: c.amount,
        asset: c.asset,
        vault: c.vault,
        mode: 'open',
        claimKey: TEST_KEY_1,
        cancelLockedUntil: c.lock,
        hasVoiceNote: true,
      });
      const clientPayload = clientSlipLink.encodeSlipPayload({
        id: c.id,
        amount: c.amount,
        asset: clientAsset,
        vault: c.vault,
        mode: 'open',
        claimKey: TEST_KEY_1,
        cancelLockedUntil: c.lock,
        hasVoiceNote: true,
      });

      expect(sdkPayload).toBe(clientPayload);
      expect(decodeSlipPayload(sdkPayload)).toEqual(clientSlipLink.decodeSlipPayload(clientPayload));

      const { webUrl, sovereignUrl, telegramUrl } = encodeSlipUrl({
        id: c.id,
        amount: c.amount,
        asset: c.asset,
        vault: c.vault,
        mode: 'open',
        claimKey: TEST_KEY_1,
        cancelLockedUntil: c.lock,
        voiceKey,
        note: 'Coffee on me',
      });

      expect(webUrl.startsWith(`${CANONICAL_SHARE_ORIGIN}/#startapp=${sdkPayload}`)).toBe(true);
      expect(sovereignUrl.startsWith(`${SOVEREIGN_ENS_ORIGIN}/#startapp=${sdkPayload}`)).toBe(true);
      expect(telegramUrl).toBeNull(); // Open links with _k NEVER produce t.me?startapp= URLs!

      const parsedWeb = parseSlipUrl(webUrl)!;
      const parsedSov = parseSlipUrl(sovereignUrl)!;
      const clientDecoded = clientSlipLink.decodeSlipPayload(webUrl)!;

      expect(parsedWeb.claimAddress).toBe(privateKeyToAddress(TEST_KEY_1));
      expect(parsedWeb.claimKey?.toLowerCase()).toBe(clientDecoded.claimKey?.toLowerCase());
      expect(parsedWeb.vault).toBe(clientDecoded.vault);
      expect(parsedWeb.asset).toBe(clientDecoded.asset);
      expect(parsedWeb.sdkAsset).toBe(c.asset);
      expect(parsedWeb.cancelLockedUntil).toBe(clientDecoded.cancelLockedUntil);
      expect(parsedWeb.voiceKey).toBe(voiceKey);
      expect(parsedWeb.note).toBe('Coffee on me');
      expect(parsedSov).toEqual(parsedWeb);

      const rebuilt = buildReceivedSlipLink({
        rawPayload: sdkPayload,
        voiceKey,
        senderNote: 'Coffee on me',
      });
      expect(rebuilt).toBe(webUrl);
      expect(buildSovereignSlipLink(sdkPayload, { vk: voiceKey, note: 'Coffee on me' })).toBe(
        sovereignUrl,
      );
    }
  });

  it('maintains 100% scrypt 12-char claim-code wallet parity and strictly blocks _k<64hex> in query strings or t.me URLs', async () => {
    const clientClaimCode = await loadWorkspaceModule('../../../../client/src/lib/claimCode.js');
    const rawCode = generateClaimCode();
    const formatted = formatClaimCode(rawCode);
    expect(formatted).toMatch(/^[0-9A-HJ-NP-TV-Z]{4}-[0-9A-HJ-NP-TV-Z]{4}-[0-9A-HJ-NP-TV-Z]{4}$/);

    const salt = generateCodeSalt();
    const [sdkDerived, clientDerived] = await Promise.all([
      deriveCodeWallet(formatted, salt),
      clientClaimCode.deriveClaimWallet(formatted, salt),
    ]);

    expect(sdkDerived.privateKey.toLowerCase()).toBe(clientDerived.privateKey.toLowerCase());
    expect(sdkDerived.address).toBe(clientDerived.address);

    // Key-free _z<32hex> payload IS allowed in Telegram startapp links
    const codePayload = encodeSlipPayload({
      id: '305',
      amount: 10,
      asset: 'USDC',
      vault: 'v33',
      mode: 'code',
      codeSalt: salt,
      cancelLockedUntil: 9_999_999_999,
    });
    expect(codePayload.length).toBeLessThanOrEqual(72); // Fits easily in single 200B LoRa packet!
    const tgUrl = buildTelegramStartAppUrl(codePayload);
    expect(tgUrl).toBe(`https://t.me/cryptoslip_bot/SLIP?startapp=${codePayload}`);
    expect(buildSlipLinks(codePayload).tgLink).toBe(tgUrl);
    expect(parseSlipUrl(tgUrl)).toMatchObject({
      id: '305',
      amount: 10,
      asset: 'USDC',
      vault: 'v33',
      mode: 'code',
      codeSalt: salt,
      cancelLockedUntil: 9_999_999_999,
    });

    // _k<64hex> in query string or ANY t.me URL MUST hard-throw SlipLinkSecurityError!
    const openPayload = encodeSlipPayload({
      id: '306',
      amount: 10,
      asset: 'USDC',
      vault: 'v33',
      mode: 'open',
      claimKey: TEST_KEY_1,
    });
    expect(() => buildTelegramStartAppUrl(openPayload)).toThrow(SlipLinkSecurityError);
    expect(() =>
      parseSlipUrl(`https://t.me/cryptoslip_bot/SLIP?startapp=${openPayload}`),
    ).toThrow(SlipLinkSecurityError);
    expect(() =>
      parseSlipUrl(`https://t.me/cryptoslip_bot/SLIP#startapp=${openPayload}`),
    ).toThrow(SlipLinkSecurityError);
    expect(() =>
      parseSlipUrl(`https://slip.naraprotocol.io/?startapp=${openPayload}`),
    ).toThrow(SlipLinkSecurityError);
    expect(() =>
      parseSlipUrl(`https://slip.naraprotocol.io/?vk=AbCdEfGhIjKlMnOpQrStUv12#startapp=${codePayload}`),
    ).toThrow(SlipLinkSecurityError);
  });

  it('verifies offline ECIES sealSlipSecretPart <-> shared/slipSealCore.mjs parity and enforces Gem #46', async () => {
    const { unsealSlipSecretPart: edgeUnsealSlipSecretPart } = await loadWorkspaceModule(
      '../../../../shared/slipSealCore.mjs',
    );
    const testSealPub = new ethers.SigningKey(TEST_SEAL_SCALAR).compressedPublicKey as Hex;
    const openPayload = encodeSlipPayload({
      id: '512',
      amount: 20,
      asset: 'USDC',
      vault: 'v33',
      mode: 'open',
      claimKey: TEST_KEY_2,
    });

    const sealed = buildSealedSlipShareUrl({
      rawPayloadOrUrl: openPayload,
      sealPublicKey: testSealPub,
      note: 'For you',
    });
    expect(sealed.sealedPayload).not.toContain(TEST_KEY_2.slice(2));
    expect(sealed.sealedPayload).toContain(`_s${TEST_KEY_2.slice(2, 50).toLowerCase()}`);

    // Unseal using Worker's exact `shared/slipSealCore.mjs` (ethers) AND SDK's `unsealSlipSecretPart` (@noble)
    const workerTail = edgeUnsealSlipSecretPart(
      ethers,
      sealed.sealToken,
      '512',
      'v33',
      TEST_SEAL_SCALAR,
    );
    const sdkTail = unsealSlipSecretPart(sealed.sealToken, '512', 'v33', TEST_SEAL_SCALAR);
    expect(sdkTail).toBe(workerTail);
    expect(sdkTail).toBe(TEST_KEY_2.slice(50).toLowerCase());

    const parsedSealed = parseSlipUrl(sealed.shareUrl)!;
    const reconstructed = reconstructUnsealedClaimKey(parsedSealed.claimKeyPrefix!, sdkTail);
    expect(reconstructed.toLowerCase()).toBe(TEST_KEY_2.toLowerCase());

    // Gem #46: Sealing a No take-back (cancelLockedUntil == 9_999_999_999) slip MUST hard-throw!
    expect(() =>
      sealSlipSecretPart('0123456789abcdef', '512', 'v33', testSealPub, {
        cancelLockedUntil: NO_TAKE_BACK_LOCK,
      }),
    ).toThrow(SlipLinkSecurityError);

    const lockedPayload = encodeSlipPayload({
      id: '513',
      amount: 20,
      asset: 'USDC',
      vault: 'v33',
      mode: 'open',
      claimKey: TEST_KEY_2,
      cancelLockedUntil: 9_999_999_999,
    });
    expect(() =>
      buildSealedSlipShareUrl({ rawPayloadOrUrl: lockedPayload, sealPublicKey: testSealPub }),
    ).toThrow(SlipLinkSecurityError);
  });

  it('encodes & parses watch-only POS URLs, popup #checkout URLs, referral invites, and 69-byte compact binary payloads', async () => {
    const clientSlipLink = await loadWorkspaceModule('../../../../client/src/lib/slipLink.js');
    const merchant = privateKeyToAddress(TEST_KEY_3);

    // Watch-only POS URL
    const posUrl = buildWatchOnlyPosUrl({
      merchantAddress: merchant,
      asset: 'USDC',
      feeMode: 'net',
      merchantName: 'Asuncion Cafe',
    });
    expect(posUrl).toBe(
      `https://slip.naraprotocol.io/#startapp=pos_${merchant}_net&m=Asuncion%20Cafe`,
    );
    expect(parseWatchOnlyPosUrl(posUrl)).toEqual({
      merchantAddress: merchant,
      asset: 'USDC',
      feeMode: 'net',
      merchantName: 'Asuncion Cafe',
    });

    // Popup #checkout URL
    const checkoutUrl = buildPopupCheckoutUrl({
      recipientAddress: merchant,
      amount: 45.5,
      asset: 'USDC',
      feeMode: 'net',
      orderId: 'ord_98765',
      callbackOrigin: 'https://partner.example.com/callback',
      merchantName: 'PredMarket',
      note: 'Payout #98765',
    });
    expect(checkoutUrl).toContain(`#startapp=pay_${merchant}_45-50_net&`);
    expect(checkoutUrl).toContain('order=ord_98765');
    expect(parsePopupCheckoutUrl(checkoutUrl)).toEqual({
      recipientAddress: merchant,
      amount: 45.5,
      feeMode: 'net',
      orderId: 'ord_98765',
      callbackOrigin: 'https://partner.example.com',
      merchantName: 'PredMarket',
      note: 'Payout #98765',
    });

    // Payment request & referral invite parity
    expect(encodePaymentRequest({ recipientAddress: merchant, amount: 12.5 })).toBe(
      clientSlipLink.encodePaymentRequest({ recipientAddress: merchant, amount: 12.5 }),
    );
    expect(decodePaymentRequest(`pay_${merchant}_12-50`)).toEqual(
      clientSlipLink.decodePaymentRequest(`pay_${merchant}_12-50`),
    );
    const inv = encodeReferralInvite(merchant);
    expect(inv).toBe(clientSlipLink.encodeReferralInvite(merchant));
    expect(decodeReferralInvite(inv)).toBe(merchant.toLowerCase());

    // Exact 69-byte compact binary QR / LoRa codec round-trip (open & code modes)
    const openBin = encodeCompactBinarySlipPayload({
      slipId: 777n,
      amountAtomic: 25_000_000n,
      asset: 'USDC',
      vault: 'v33',
      mode: 'open',
      cancelLockedUntil: NO_TAKE_BACK_LOCK,
      hasVoiceNote: true,
      claimKey: TEST_KEY_1,
    });
    expect(openBin.byteLength).toBe(COMPACT_BINARY_SLIP_BYTE_LENGTH);
    expect(openBin.byteLength).toBe(69);
    expect(decodeCompactBinarySlipPayload(openBin)).toEqual({
      slipId: 777n,
      amountAtomic: 25_000_000n,
      asset: 'USDC',
      vault: 'v33',
      mode: 'open',
      cancelLockedUntil: NO_TAKE_BACK_LOCK,
      hasVoiceNote: true,
      claimKey: TEST_KEY_1.toLowerCase(),
    });

    const salt = generateCodeSalt();
    const codeBin = encodeCompactBinarySlipPayload({
      slipId: 888n,
      amountAtomic: 100n,
      asset: 'cbBTC',
      vault: 'v33',
      mode: 'code',
      cancelLockedUntil: NO_TAKE_BACK_LOCK,
      codeSalt: salt,
    });
    expect(codeBin.byteLength).toBe(69);
    expect(decodeCompactBinarySlipPayload(codeBin)).toEqual({
      slipId: 888n,
      amountAtomic: 100n,
      asset: 'cbBTC',
      vault: 'v33',
      mode: 'code',
      cancelLockedUntil: NO_TAKE_BACK_LOCK,
      hasVoiceNote: false,
      codeSalt: salt.toLowerCase(),
    });
  });

  it('maintains 100% byte-for-byte ERC-8021 bc_ea68lz8s calldata suffix parity with client/src/lib/erc8021.ts', async () => {
    const clientErc8021 = await loadWorkspaceModule('../../../../client/src/lib/erc8021.js');
    const singleSuffix = toErc8021DataSuffix(DEFAULT_CRYPTOSLIP_BUILDER_CODE);
    expect(singleSuffix).toBe(clientErc8021.toErc8021DataSuffix('bc_ea68lz8s'));
    expect(singleSuffix.endsWith(ERC8021_MARKER_HEX)).toBe(true);

    const dualCodes = [DEFAULT_CRYPTOSLIP_BUILDER_CODE, DEFAULT_NARA_BUILDER_CODE] as const;
    expect(toErc8021DataSuffix(dualCodes)).toBe(clientErc8021.toErc8021DataSuffix(dualCodes));

    const sampleCalldata = '0x12345678000000000000000000000000000000000000000000000000000000000000002a';
    const suffixed = appendBuilderCodeSuffix(sampleCalldata);
    expect(suffixed).toBe(clientErc8021.appendErc8021DataSuffix(sampleCalldata, 'bc_ea68lz8s'));
    // Idempotent when called twice
    expect(appendBuilderCodeSuffix(suffixed)).toBe(suffixed);
    expect(appendErc8021DataSuffix(sampleCalldata)).toBe(suffixed);
  });

  it('signs byte-identical EIP-712 / EIP-3009 / EIP-2612 permits across privateKey, viem LocalAccount, viem WalletClient, and ethers v6 Signer without leaking keys', async () => {
    const clientPermitHelper = await loadWorkspaceModule(
      '../../../../client/src/lib/permitHelper.js',
    );
    const clientEip3009Helper = await loadWorkspaceModule(
      '../../../../client/src/lib/eip3009Helper.js',
    );
    const rawKeySigner = createSlipSignerFromKey(TEST_KEY_1);
    const viemAccount = privateKeyToAccount(TEST_KEY_1);
    const viemAccSigner = fromViemAccount(viemAccount);
    const walletClient = createWalletClient({
      account: viemAccount,
      chain: base,
      transport: http(DEFAULT_BASE_RPC_URLS[0]),
    });
    const viemWcSigner = fromViemWalletClient(walletClient);
    const ethersWallet = new ethers.Wallet(TEST_KEY_1);
    const ethersSigner = await fromEthersSigner(ethersWallet);

    // Zero key leakage in logs/JSON/inspect
    const keyBodyLower = TEST_KEY_1.slice(2).toLowerCase();
    expect(String(rawKeySigner).toLowerCase()).not.toContain(keyBodyLower);
    expect(JSON.stringify(rawKeySigner).toLowerCase()).not.toContain(keyBodyLower);
    expect(util.inspect(rawKeySigner).toLowerCase()).not.toContain(keyBodyLower);

    const claimAccount = privateKeyToAccount(TEST_KEY_2);
    const recipientWallet = new ethers.Wallet(TEST_KEY_3);
    const recipientAddr = privateKeyToAddress(TEST_KEY_3);
    const headTs = 1_760_000_000n;
    const deadline = computePermitDeadline(headTs, 3600n);
    expect(deadline).toBe(1_760_003_600n);
    expect(computeMintValidityWindow(headTs, 7200n)).toEqual({
      validAfter: 0n,
      validBefore: 1_760_007_200n,
    });

    // Law #3 cancel-lock guard
    expect(assertValidCancelLock(0)).toBe(0n);
    expect(assertValidCancelLock(NO_TAKE_BACK_LOCK)).toBe(NO_TAKE_BACK_LOCK);
    expect(() => assertValidCancelLock(1n)).toThrow('Law #3');
    expect(() => assertValidCancelLock(1_760_003_600n)).toThrow('Law #3');

    // CashPermit across all 4 signer adapters + client permitHelper parity
    const cashParams = {
      slipId: 42n,
      recipient: recipientAddr,
      nonce: 0n,
      deadline,
      vault: 'v33' as const,
    };
    const [sigKey, sigAcc, sigWc, sigEth, clientCash] = await Promise.all([
      signCashPermit(rawKeySigner, cashParams),
      signCashPermit(viemAccSigner, cashParams),
      signCashPermit(viemWcSigner, cashParams),
      signCashPermit(ethersSigner, cashParams),
      clientPermitHelper.createOpenCashPermit(ethersWallet, {
        slipId: 42n,
        recipient: recipientAddr,
        nonce: 0n,
        verifyingContract: CANONICAL_VAULT_V33_ADDRESS,
        deadline,
      }),
    ]);

    expect(sigKey.signature).toBe(sigAcc.signature);
    expect(sigKey.signature).toBe(sigWc.signature);
    expect(sigKey.signature).toBe(sigEth.signature);
    expect(sigKey.signature.toLowerCase()).toBe(clientCash.signature.toLowerCase());

    // ReferralConsent + 130-byte bundle parity
    const [sdkConsent, clientConsentSig] = await Promise.all([
      signReferralConsent(TEST_KEY_3, {
        slipId: 42n,
        referrer: viemAccount.address,
        deadline,
        vault: 'v33',
      }),
      clientPermitHelper.signReferralConsent(recipientWallet, {
        recipient: recipientAddr,
        slipId: 42n,
        referrer: viemAccount.address,
        deadline,
        verifyingContract: CANONICAL_VAULT_V33_ADDRESS,
      }),
    ]);
    expect(sdkConsent.signature.toLowerCase()).toBe(clientConsentSig.toLowerCase());

    const packed130 = packPermitWithReferralConsent(sigKey.signature, sdkConsent.signature);
    expect(packed130.length).toBe(2 + 260); // 0x + 130 bytes
    expect(unpackPermitWithReferralConsent(packed130)).toEqual({
      permitSignature: sigKey.signature,
      referralConsentSignature: sdkConsent.signature,
    });

    // MintPermit + EIP-3009 (USDC & cbBTC) + EIP-2612 (NARA) parity
    const nonce = keccak256(stringToHex('sdk-mint-nonce-1'));
    const directMintSigned = await signMintPermit(TEST_KEY_1, {
      token: USDC_BASE_ADDRESS,
      amount: 100_000n,
      claimSigner: claimAccount.address,
      cancelLockedUntil: NO_TAKE_BACK_LOCK,
      validBefore: deadline,
      nonce,
    });
    const pairedUsdc = await signPairedEip3009Mint(TEST_KEY_1, {
      token: 'USDC',
      amount: 100_000n,
      claimSigner: claimAccount.address,
      cancelLockedUntil: NO_TAKE_BACK_LOCK,
      validBefore: deadline,
      nonce,
    });
    expect(pairedUsdc.mintSignature).toBe(directMintSigned.signature);
    const ethersMintSig = await ethersWallet.signTypedData(
      getVaultDomain('v33'),
      MINT_PERMIT_V32_TYPES as unknown as Record<string, ethers.TypedDataField[]>,
      pairedUsdc.mintPermit,
    );
    expect(pairedUsdc.mintSignature.toLowerCase()).toBe(ethersMintSig.toLowerCase());

    const cbBtcAuth = await signReceiveWithAuthorization(TEST_KEY_1, {
      token: 'cbBTC',
      value: 100n,
      validBefore: deadline,
      nonce,
    });
    const recoveredCbBtc = await recoverTypedDataAddress({
      domain: CBBTC_BASE_DOMAIN,
      types: {
        ReceiveWithAuthorization: [
          { name: 'from', type: 'address' },
          { name: 'to', type: 'address' },
          { name: 'value', type: 'uint256' },
          { name: 'validAfter', type: 'uint256' },
          { name: 'validBefore', type: 'uint256' },
          { name: 'nonce', type: 'bytes32' },
        ],
      },
      primaryType: 'ReceiveWithAuthorization',
      message: {
        from: cbBtcAuth.from,
        to: cbBtcAuth.to,
        value: cbBtcAuth.value,
        validAfter: cbBtcAuth.validAfter,
        validBefore: cbBtcAuth.validBefore,
        nonce: cbBtcAuth.nonce,
      },
      signature: cbBtcAuth.signature,
    });
    expect(recoveredCbBtc).toBe(viemAccount.address);

    const naraPermit = await signErc2612Permit(TEST_KEY_1, {
      token: 'NARA',
      value: 1_000_000_000_000n,
      nonce: 0n,
      deadline,
    });
    const ethersNaraSig = await ethersWallet.signTypedData(
      NARA_BASE_DOMAIN,
      clientEip3009Helper.ERC20_PERMIT_TYPES,
      {
        owner: viemAccount.address,
        spender: CANONICAL_VAULT_V33_ADDRESS,
        value: 1_000_000_000_000n,
        nonce: 0n,
        deadline,
      },
    );
    expect(naraPermit.signature.toLowerCase()).toBe(ethersNaraSig.toLowerCase());

    // AcceptPermit, SplitPermit, RearrangePermit, RefundPermit, SwapOfferPermit, SwapAndPayPermit, CompositeSwapOfferPermit, TradeOfferPermit
    const acceptSigned = await signAcceptPermit(TEST_KEY_2, {
      slipId: 42n,
      newHolder: recipientAddr,
      newClaimSigner: recipientAddr,
      keepEscrowedInVault: true,
      nonce: 0n,
      deadline,
    });
    expect(acceptSigned.signature).toMatch(/^0x[0-9a-f]{130}$/);

    const splitSigned = await signSplitPermit(TEST_KEY_2, {
      slipId: 42n,
      paymentAmount: 500_000n,
      merchant: recipientAddr,
      changeReceiver: CANONICAL_VAULT_V33_ADDRESS,
      newChangeSigner: viemAccount.address,
      nonce: 0n,
      deadline,
    });
    const clientSplit = await clientPermitHelper.createOpenSplitPermit(
      new ethers.Wallet(TEST_KEY_2),
      {
        slipId: 42n,
        paymentAmount: 500_000n,
        merchant: recipientAddr,
        changeReceiver: CANONICAL_VAULT_V33_ADDRESS,
        newChangeSigner: viemAccount.address,
        nonce: 0n,
        verifyingContract: CANONICAL_VAULT_V33_ADDRESS,
        deadline,
      },
    );
    expect(splitSigned.signature.toLowerCase()).toBe(clientSplit.signature.toLowerCase());

    const slipIds = [10n, 20n, 30n];
    expect(computeRearrangeSlipIdsHash(slipIds)).toBe(
      ethers.solidityPackedKeccak256(['uint256[]'], [slipIds]),
    );
    const rearrangeSigned = await signRearrangePermit(TEST_KEY_2, {
      slipId: 10n,
      slipIds,
      paymentAmount: 1_000_000n,
      merchant: recipientAddr,
      changeReceiver: CANONICAL_VAULT_V33_ADDRESS,
      newChangeSigner: viemAccount.address,
      nonce: 0n,
      deadline,
    });
    expect(rearrangeSigned.signature).toMatch(/^0x[0-9a-f]{130}$/);

    const refundSigned = await signRefundPermit(TEST_KEY_1, {
      slipId: 42n,
      destination: viemAccount.address,
      nonce: 0n,
      deadline,
    });
    expect(refundSigned.signature).toMatch(/^0x[0-9a-f]{130}$/);

    const swapSigned = await signSwapOfferPermit(TEST_KEY_2, {
      slipId: 42n,
      swapAmount: 1_000_000n,
      outAsset: NARA_BASE_ADDRESS,
      minAmountOut: 100_000_000_000_000n,
      newOutputSigner: recipientAddr,
      outputCancelLockedUntil: NO_TAKE_BACK_LOCK,
      swapTarget: '0x6fF5693b99212Da76ad316178A184AB56D299b43',
      swapData: '0xdeadbeef',
      nonce: 0n,
      deadline,
    });
    expect(swapSigned.signature).toMatch(/^0x[0-9a-f]{130}$/);

    const swapPaySigned = await signSwapAndPayPermit(TEST_KEY_2, {
      slipId: 42n,
      swapAmount: 1_000_000n,
      merchant: recipientAddr,
      outAsset: NARA_BASE_ADDRESS,
      minAmountOut: 100_000_000_000_000n,
      swapTarget: '0x6fF5693b99212Da76ad316178A184AB56D299b43',
      swapData: '0xdeadbeef',
      nonce: 0n,
      deadline,
    });
    expect(swapPaySigned.signature).toMatch(/^0x[0-9a-f]{130}$/);

    const compSwapSigned = await signCompositeSwapOfferPermit(TEST_KEY_2, {
      slipId: 42n,
      swapAmount: 10_000n,
      midAsset: USDC_BASE_ADDRESS,
      outAsset: NARA_BASE_ADDRESS,
      leg2AmountIn: 5_000_000n,
      minAmountOut: 100_000_000_000_000n,
      newOutputSigner: recipientAddr,
      outputCancelLockedUntil: 0n,
      swapTarget1: '0x6131B5fae19EA4f9D964eAc0408E4408b66337b5',
      swapData1: '0x1122',
      swapTarget2: '0x6fF5693b99212Da76ad316178A184AB56D299b43',
      swapData2: '0x3344',
      nonce: 0n,
      deadline,
    });
    expect(compSwapSigned.signature).toMatch(/^0x[0-9a-f]{130}$/);

    const tradeSigned = await signTradeOfferPermit(TEST_KEY_2, {
      mySlipId: 42n,
      counterpartySlipId: 99n,
      myNewClaimSigner: recipientAddr,
      nonce: 0n,
      deadline,
    });
    expect(tradeSigned.signature).toMatch(/^0x[0-9a-f]{130}$/);
  });

  it('maintains 100% deterministic ephemeral hop-key derivation parity with client/src/lib/keptSlipRecovery.ts', async () => {
    const clientKeptRecovery = await loadWorkspaceModule(
      '../../../../client/src/lib/keptSlipRecovery.js',
    );
    for (const vault of ['v33', 'v32', 'v3', 'v2'] as const) {
      expect(deriveKeptSlipKey(TEST_KEY_1, vault, '105')).toBe(
        clientKeptRecovery.deriveKeptSlipKey(TEST_KEY_1, vault, '105'),
      );
      for (let hop = 0; hop < 5; hop++) {
        expect(deriveKeptSlipHopKey(TEST_KEY_1, vault, '105', hop)).toBe(
          clientKeptRecovery.deriveKeptSlipHopKey(TEST_KEY_1, vault, '105', hop),
        );
      }
      expect(deriveSplitChangeSlipKey(TEST_KEY_1, vault, '105')).toBe(
        clientKeptRecovery.deriveSplitChangeSlipKey(TEST_KEY_1, vault, '105'),
      );
      expect(deriveCreatedSlipKey(TEST_KEY_1, vault, 7)).toBe(
        clientKeptRecovery.deriveCreatedSlipKey(TEST_KEY_1, vault, 7),
      );
    }

    const hop0 = deriveKeptSlipHopKey(TEST_KEY_1, 'v33', '105', 0);
    const hop1 = deriveKeptSlipHopKey(TEST_KEY_1, 'v33', '105', 1);
    expect(deriveNextSlipHolderKey(TEST_KEY_1, 'v33', '105', hop0)).toBe(hop1);
    expect(
      clientKeptRecovery.deriveNextSlipHolderKey(TEST_KEY_1, 'v33', '105', hop0),
    ).toBe(hop1);
  });

  it('proves fee ceiling (FEE_BPS = 50) & grossUpForExactNet exactness across edge cases and 500 fuzz inputs', () => {
    expect(FEE_BPS).toBe(50n);
    expect(computeProtocolFeeCeiling(0n)).toBe(0n);
    expect(computeProtocolFeeCeiling(1n)).toBe(1n);
    expect(computeProtocolFeeCeiling(200n)).toBe(1n);
    expect(computeProtocolFeeCeiling(201n)).toBe(2n);
    expect(computeProtocolFeeCeiling(100_000n)).toBe(500n); // $0.10 -> $0.0005
    expect(computeProtocolFeeCeiling(1_000_000n)).toBe(5_000n); // $1.00 -> $0.005

    const split = computeFeeAndReferralSplit(201n, true);
    expect(split).toEqual({
      totalFee: 2n,
      referralFee: 1n,
      protocolFee: 1n,
      netAmount: 199n,
    });
    // Odd fee (3 wei): referrer gets floor(3/2)=1, protocol gets 3-1=2 (`CryptoSlipProtocolV32.sol:1675-1681`)
    const oddSplit = computeFeeAndReferralSplit(401n, true);
    expect(oddSplit).toEqual({
      totalFee: 3n,
      referralFee: 1n,
      protocolFee: 2n,
      netAmount: 398n,
    });

    const deterministicTargets = [
      1n,
      2n,
      99n,
      100n,
      199n,
      200n,
      201n,
      100_000n, // $0.10 USDC
      1_000_000n, // $1.00 USDC
      1_500_000n, // $1.50 USDC
      9_999_999n,
      100_000_000n,
      1_000_000_000_000n,
      123_456_789_012_345_678_901n,
    ];

    // Deterministic LCG PRNG for 500 reproducible fuzz inputs across 1..10^26
    let seed = 0x5119_2026n;
    const fuzzTargets = [...deterministicTargets];
    for (let i = 0; i < 500; i++) {
      seed = (seed * 6364136223846793005n + 1442695040888963407n) & ((1n << 88n) - 1n);
      const val = (seed % (10n ** BigInt((i % 25) + 1))) + 1n;
      fuzzTargets.push(val);
    }

    for (const targetNet of fuzzTargets) {
      const gross = grossUpForExactNet(targetNet);
      const netAtGross = deductProtocolFeeCeiling(gross);
      const netAtGrossMinusOne = deductProtocolFeeCeiling(gross - 1n);
      expect(netAtGross >= targetNet).toBe(true);
      expect(netAtGrossMinusOne < targetNet).toBe(true);
    }

    // Referral binding helper checks
    const relayer = privateKeyToAddress(TEST_KEY_3);
    const partner = privateKeyToAddress(TEST_KEY_1);
    const claimKeyAddr = privateKeyToAddress(TEST_KEY_2);
    const userWallet = '0x1111111111111111111111111111111111111111';
    expect(
      canBindReferrerOnV33({
        caller: relayer,
        creator: partner,
        claimSignerAtClaim: claimKeyAddr,
        recipient: userWallet,
        assetOrAddress: ASSETS.USDC.address,
        amount: 100_000n,
      }),
    ).toBe(true);
    // Creator self-broadcasting cashWithPermit cannot bind referrer (`msg.sender == creator`)
    expect(
      canBindReferrerOnV33({
        caller: partner,
        creator: partner,
        claimSignerAtClaim: claimKeyAddr,
        recipient: userWallet,
        assetOrAddress: ASSETS.USDC.address,
        amount: 100_000n,
      }),
    ).toBe(false);
    // Sub-minimum (< $0.10 USDC) cannot bind referrer
    expect(
      canBindReferrerOnV33({
        caller: relayer,
        creator: partner,
        claimSignerAtClaim: claimKeyAddr,
        recipient: userWallet,
        assetOrAddress: ASSETS.USDC.address,
        amount: 99_999n,
      }),
    ).toBe(false);
  });
});
