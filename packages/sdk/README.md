# `@cryptoslip/sdk` — Official TypeScript SDK for CryptoSLIP V3.2

Zero-bloat, non-custodial TypeScript SDK for **CryptoSLIP Protocol V3.2** on **Base Mainnet (`8453`)**.

Built on `viem` v2, `@noble/curves`, `@noble/hashes`, and `scrypt-js` with native Node.js 22+ ESM subpath exports, zero DOM dependencies, and full tree-shaking across Workers, backends, CLIs, and autonomous agents.

## Protocol Architecture & Canonical Addresses (`Base 8453`)

| Component | Address / Identifier | Notes |
| :--- | :--- | :--- |
| **`CryptoSlipVaultV32` (`v33`)** | `0x3f80aa68Fb4834d6E119EE1cf932C14419Cf63EB` | Active micro-minimum issuance vault (`ISSUE_VAULT = 'v33'`) |
| **`CryptoSlipNFTV32` (`v33`)** | `0x356a701DABDeabe61F7Fc79D730617CEcbd7B94f` | Transferable 1-of-1 Raden/Nacre position NFT |
| **`CryptoSlipTradeRouterV32` (`v33`)** | `0x2069CA17D45d3421D28f15F20262575333CECF51` | Slip-to-slip swaps & atomic P2P barter |
| **`NARALiquidityHookV5`** | `0x07d8F2Dfd121B10dE3176DeAb6A8C0eaa2646aCC` | Mandatory Uniswap V4 Hook for 100% of `NARA` legs |
| **Circle `TokenPaymasterV08`** | `0x0578cFB241215b77442a541325d6A4E6dFE700Ec` | Self-funded `USDC` network fee settlement (`EntryPoint v0.8`) |
| **Base Builder Code (`ERC-8021`)** | `bc_ea68lz8s` | Appended automatically via `appendBuilderCodeSuffix` |

### Supported Assets, Micro-Minimums & Fee Schedule (`v33`)

- **Assets & `v33` Minimums:** `USDC` (`0.10 USDC` / `100_000n`), `cbBTC` (`100 sats` / `100n`), `ETH` (`0.000001 ETH` / `10^12` wei), `NARA` (`0.000001 NARA` / `10^12` wei).
- **Fee Schedule:** `0%` on slip creation, `0%` on 1st `Keep in Slips` (`keepSlip`), `0%` on direct creator reclaim (`refundSlipDirect`), and `0.50%` (`FEE_BPS = 50n`, ceiling-rounded) on claim to external wallet, 2nd+ re-transfer, split, or combine.
- **Partner `50/50` Referral Revenue Share:** When a partner wallet creates payout slips (`creator = partnerWallet`), recipients who claim to their wallet bind `referrerOf[recipient] = partnerWallet` permanently on-chain, streaming **`0.25%` of lifetime settlement volume** in `USDC`, `cbBTC`, `ETH`, and `NARA` to the partner.
- **Perpetual Validity:** Slips never carry an end date; they remain active on Base until claimed, kept, or reclaimed (unless created with `No take-back` `9_999_999_999n`).

---

## Installation & Subpath Exports

```bash
npm install @cryptoslip/sdk viem
```

Import from the root barrel or individual tree-shakeable subpaths:

```ts
import { ISSUE_VAULT, grossUpForExactNet } from '@cryptoslip/sdk/constants';
import { CRYPTO_SLIP_VAULT_V32_ABI } from '@cryptoslip/sdk/abi';
import { encodeSlipUrl, parseSlipUrl } from '@cryptoslip/sdk/link';
import { toSlipSigner, createSlipSignerFromKey } from '@cryptoslip/sdk/permits';
import { prepareBatchPayoutSlips, executeBatchPayoutSlips } from '@cryptoslip/sdk/batch';
import { keepSlip, claimSlip, splitAndPay, combineSlips } from '@cryptoslip/sdk/operations';
import { RelayGatewayClient } from '@cryptoslip/sdk/paymaster';
import { encryptVoiceEnvelope, uploadBurnOnPlayVoice } from '@cryptoslip/sdk/voice';
import { createSignedPaymentReceipt, verifyPaymentReceiptOnChain } from '@cryptoslip/sdk/receipts';
import { withCryptoSlip, attachRefundSlipHeader } from '@cryptoslip/sdk/middleware';
import { BoundedAgentPolicy, createPolicyGuardedSigner } from '@cryptoslip/sdk/policy';
```

---

## 5 Copy-Paste Integration Recipes

### 1. 500-Slip 1-Transaction `Multicall3` Batch Payouts

Create up to `500` non-custodial `USDC` or `cbBTC` payout links in **one Base transaction** using offline EIP-3009 `ReceiveWithAuthorization` + `MintPermit` (`relayer = address(0)`). Preserves `creator = partnerWallet` on every slip so your platform earns `0.25%` lifetime referral rewards when recipients claim.

```ts
import { createPublicClient, createWalletClient, http } from 'viem';
import { base } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';
import { executeBatchPayoutSlips } from '@cryptoslip/sdk/batch';

const partnerSigner = privateKeyToAccount(process.env.PARTNER_SIGNER_KEY as `0x${string}`);
const publicClient = createPublicClient({ chain: base, transport: http('https://mainnet.base.org') });
const walletClient = createWalletClient({
  account: partnerSigner,
  chain: base,
  transport: http('https://mainnet.base.org'),
});

const payouts = Array.from({ length: 500 }, (_, i) => ({
  amount: 5_000_000n, // 5.00 USDC (6 decimals)
  asset: 'USDC' as const,
  noTakeBack: true, // Irrevocable 9_999_999_999n finality for instant winner confidence
  grossUpForExitFee: true, // Recipient nets >= 5.00 USDC even if claiming directly to an external wallet
  note: `Tournament #42 Prize #${i + 1}`,
}));

const result = await executeBatchPayoutSlips({
  publicClient,
  walletClient,
  signer: partnerSigner,
  items: payouts,
});

console.log(`Minted ${result.mintedSlips.length} slips in tx:`, result.txHashes);
// Deliver result.mintedSlips[i].url ('https://slip.naraprotocol.io/#startapp=slip_...') via private DM!
```

---

### 2. Prediction-Market `Keep in Slips` Shielded Payout

Let winning traders move payouts into a `1:1` non-commingled, fresh ephemeral key (`0%` 1st `Keep` fee) so public copy-trading graphs cannot link their trading history to their personal spending wallet.

```ts
import { createPublicClient, http } from 'viem';
import { base } from 'viem/chains';
import { parseSlipUrl } from '@cryptoslip/sdk/link';
import { keepSlip, splitAndPay } from '@cryptoslip/sdk/operations';
import { RelayGatewayClient } from '@cryptoslip/sdk/paymaster';

const publicClient = createPublicClient({ chain: base, transport: http('https://mainnet.base.org') });
const relayClient = new RelayGatewayClient();

// 1. Parse the inbound payout link ('<YOUR_SLIP_URL>') strictly from its # fragment
const parsed = parseSlipUrl('<YOUR_SLIP_URL>');
if (!parsed?.claimKey) throw new Error('Expected open slip URL');

// 2. Rotate claimSigner on-chain at 0% fee into a fresh local key (invalidating the original link)
const kept = await keepSlip({
  publicClient,
  relayClient,
  slipId: parsed.id,
  vault: parsed.vault,
  claimSigner: parsed.claimKey,
});

// 3. Spend an exact slice ($2.50 USDC) to a merchant while keeping remaining change in a new rotated slip
const spend = await splitAndPay({
  publicClient,
  relayClient,
  slipId: kept.slipId,
  vault: kept.vault,
  claimSigner: kept.newClaimPrivateKey,
  paymentAmount: 2_500_000n,
  merchant: '0x1111111111111111111111111111111111111199',
});

console.log('Merchant paid in tx:', spend.txHash);
```

---

### 3. Hono / HTTP `402` `withCryptoSlip()` Zero-Key Tollbooth + Overcharge Refund Header

Gate any paid API, inference endpoint, or webhook behind Base settlement straight into a watch-only merchant Safe (**zero private key on the API server**). Includes concurrent `slipId` replay protection and stateless `X-Payment-Refund-Slip` overcharge refunds.

```ts
import { Hono } from 'hono';
import { createPublicClient, http } from 'viem';
import { base } from 'viem/chains';
import { withCryptoSlip, attachRefundSlipHeader } from '@cryptoslip/sdk/middleware';

const app = new Hono();
const publicClient = createPublicClient({ chain: base, transport: http('https://mainnet.base.org') });

app.post(
  '/v1/completions',
  withCryptoSlip({
    publicClient,
    merchantAddress: '0xe320C281c86079eA85f2Bc67864E873A61D551E3', // Watch-only cold Safe!
    asset: 'USDC',
    minNetAmount: 250_000n, // Requires >= 0.25 USDC net settlement
    requireNoTakeBack: true,
    merchantLabel: 'Inference API',
  }),
  async (c) => {
    const settlement = c.get('cryptoSlip');
    const response = Response.json({
      ok: true,
      settledNet: settlement.receipt.netAmount,
      txHash: settlement.receipt.txHash,
      output: 'Verified completion result',
    });

    // Optional: attach an X-Payment-Refund-Slip header when metered usage is under pre-paid amount
    return await attachRefundSlipHeader(response, {
      paidNetAmount: settlement.netAmount,
      usedNetAmount: 100_000n,
      refundSlipUrl: '<YOUR_SLIP_URL>',
    });
  },
);
```

---

### 4. `$1.00+` Burn-on-Play VOPRF Encrypted Voice Slip

Attach an end-to-end `AES-256-GCM` (`32 KB` block-padded) + RFC 9497 `P-256` VOPRF burn-on-play voice message to any slip worth `>= $1.00` USD equivalent. The decryption key (`&vk=`) travels exclusively inside the `#` URL fragment and is zeroized from memory after use.

```ts
import { encryptVoiceEnvelope, uploadBurnOnPlayVoice } from '@cryptoslip/sdk/voice';
import { encodeSlipUrl } from '@cryptoslip/sdk/link';

// 1. Encrypt audio bytes locally with 32 KB length-hiding padding (enforces >= $1.00 slip floor)
const envelope = await encryptVoiceEnvelope(audioBytes, 'audio/webm;codecs=opus', {
  asset: 'USDC',
  slipAmount: 5_000_000n, // $5.00 USDC slip
});

// 2. Upload burn-on-play voice note via RFC 9497 VOPRF pass to isolated voice vault
const uploaded = await uploadBurnOnPlayVoice({
  audioBytes,
  asset: 'USDC',
  slipAmount: 5_000_000n,
  slipId: '1024',
  vault: 'v33',
  claimPrivateKey: ephemeralClaimKey,
  beneficiarySigner: partnerSigner,
});

// 3. Embed _vn1 + #...&vk=<voiceKey> strictly inside the URL # fragment
const { webUrl } = encodeSlipUrl({
  id: '1024',
  amount: 5,
  asset: 'USDC',
  vault: 'v33',
  mode: 'open',
  claimKey: ephemeralClaimKey,
  hasVoiceNote: true,
  voiceKey: uploaded.fragmentVoiceKey ?? envelope.voiceKeyBase64Url,
});
```

---

### 5. Signed Payment Receipt Creation & 1-RPC On-Chain Verification

Produce portable, tamper-evident `PaymentReceiptBundleV1` proofs (`JSON`, `CSV`, or self-contained printable HTML) and verify exact Base Mainnet settlement without trusting a third-party facilitator database.

```ts
import { createPublicClient, http } from 'viem';
import { base } from 'viem/chains';
import {
  createSignedPaymentReceipt,
  verifyPaymentReceiptOnChain,
  renderPrintableReceiptHtml,
} from '@cryptoslip/sdk/receipts';

const publicClient = createPublicClient({ chain: base, transport: http('https://mainnet.base.org') });

const bundle = await createSignedPaymentReceipt({
  vault: 'v33',
  slipId: '1024',
  txHash: ('0x' + 'ab'.repeat(32)) as `0x${string}`,
  blockNumber: 28_500_000,
  blockTimestamp: 1_795_000_000,
  settlementType: 'split_pay',
  asset: 'USDC',
  grossAmount: '5025126',
  feeAmount: '25126',
  netAmount: '5000000',
  recipient: '0x1111111111111111111111111111111111111199',
  merchantLabel: 'Acme Cloud',
  orderId: 'ord_9912',
});

const verification = await verifyPaymentReceiptOnChain(publicClient, bundle);
if (verification.valid) {
  const printableHtml = renderPrintableReceiptHtml(bundle);
  console.log('Verified Base settlement receipt HTML length:', printableHtml.length);
}
```

---

## Out-of-Context Agent Firewall (`@cryptoslip/sdk/policy`)

Wrap any `SlipSigner` with `createPolicyGuardedSigner` to enforce deterministic per-call caps, sliding-window rate limits, protocol contract denylists, canonical `NARALiquidityHookV5` swap verification, and output secret scrubbing (`redactSecretsFromToolOutput`) before signing. For a turnkey Model Context Protocol stdio server, see [`@cryptoslip/mcp`](../mcp/README.md).
