# CryptoSLIP TypeScript SDK & PocketSlip MCP (`v1.0.0`)

[![CI](https://github.com/NARAProtocol/cryptoslip-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/NARAProtocol/cryptoslip-sdk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Network: Base 8453](https://img.shields.io/badge/Base_Mainnet-8453-0052FF.svg)](https://basescan.org/address/0x3f80aa68Fb4834d6E119EE1cf932C14419Cf63EB#code)

Official **Zero-DOM TypeScript 6 SDK (`@cryptoslip/sdk`)** and **Bounded Agent MCP Server (`@cryptoslip/mcp`)** for **CryptoSLIP Protocol V3.2** on **Base Mainnet (`8453`)** — live at [https://slip.naraprotocol.io](https://slip.naraprotocol.io), ENS [https://cryptoslip.eth.limo](https://cryptoslip.eth.limo), and Telegram Mini App [@cryptoslip_bot/SLIP](https://t.me/cryptoslip_bot/SLIP).

---

## Packages

| Package | Path | Description |
| :--- | :--- | :--- |
| **`@cryptoslip/sdk`** | [`packages/sdk`](./packages/sdk) | 12 tree-shakeable zero-DOM subpaths (`Node 22+`, Cloudflare Workers, Deno, Bun, Browsers): 1-tx `Multicall3` batch payouts (`1..500` items in `<50ms` offline signing), zero-key `withCryptoSlip()` HTTP `402` Hono/Fetch/Express middleware + `verifyPartnerWebhookSignature()`, `0%` 1st `Keep in Slips` (`1:1` non-commingled wallet privacy), Circle `TokenPaymasterV08` `USDC` network fee UserOps, VOPRF encrypted voice notes, verifiable EIP-712 receipts, and `BoundedAgentPolicy` spend firewall. |
| **`@cryptoslip/mcp`** | [`packages/mcp`](./packages/mcp) | `PocketSlip` Model Context Protocol (`stdio`) server & OpenClaw [`SKILL.md`](./packages/mcp/SKILL.md). Provisions AI agents with a bounded `#` slip URL (`<1s` boot `Keep` rotation invalidating the `.env` link at `0%` fee) instead of a raw wallet private key, exposing 7 policy-guarded tools. |

---

## Quick Install

### From npm (or Direct Signed GitHub Release Tarball)

```bash
# Standard install
npm install @cryptoslip/sdk viem

# Or pin directly to the verified v1.0.0 GitHub Release tarball
npm install https://github.com/NARAProtocol/cryptoslip-sdk/releases/download/v1.0.0/cryptoslip-sdk-1.0.0.tgz viem
```

---

## Why Builders & AI Agents Integrate CryptoSLIP

1. **1-Tx `Multicall3` Partner Dispenser (`1..500` Links, Zero `ERC20.approve`):** Mint up to 500 revocable DM links or irrevocable `No take-back` (`cancelLockedUntil = 9_999_999_999`) bounties in a single Base transaction via EIP-3009 `ReceiveWithAuthorization` + `MintPermit`, while preserving `slip.creator == partnerWallet` (`0%` creator reclaim on unopened DM links + `0.25%` lifetime on-chain `referrerOf` revenue share).
2. **`0%` 1st `Keep in Slips` (`1:1` Non-Commingled Wallet Privacy):** Recipients and agents rotate `claimSigner` on-chain at `0%` protocol fee (`nonces(slipId): 0 -> 1`), keeping funds in isolated `1:1` positions rather than exposing their primary wallet balance or trade history.
3. **Zero-Key HTTP `402` Tollbooth (`withCryptoSlip`) & Signed Webhooks:** Gate Hono, Fetch, or Express APIs directly into a watch-only multisig Safe with synchronous `SlipReplayGuard`, stateless `X-Payment-Refund-Slip` overcharge refunds, and `HMAC-SHA256` `verifyPartnerWebhookSignature()` (`slip.claimed`, `slip.kept`, `checkout.paid`).
4. **Bounded `PocketSlip` Agent Wallets (`@cryptoslip/mcp`):** Never hand an LLM or untrusted sub-agent your main wallet private key. Hand it a `$5.00 USDC` slip URL; on startup, `PocketSlipVault` rotates the key on-chain in `<1s` and enforces out-of-context `BoundedAgentPolicy` per-call/daily USD caps, sliding-window rate limits, and output secret scrubbing.

---

## Canonical Base Mainnet (`8453`) Verified Contracts

| Contract | Address | Notes |
| :--- | :--- | :--- |
| **`CryptoSlipVaultV32` (`v33`)** | [`0x3f80aa68Fb4834d6E119EE1cf932C14419Cf63EB`](https://basescan.org/address/0x3f80aa68Fb4834d6E119EE1cf932C14419Cf63EB#code) | Active micro-minimum vault (`0.10 USDC`, `100 sats cbBTC`, `1e-6 ETH / NARA`) |
| **`CryptoSlipNFTV32` (`v33`)** | [`0x356a701DABDeabe61F7Fc79D730617CEcbd7B94f`](https://basescan.org/address/0x356a701DABDeabe61F7Fc79D730617CEcbd7B94f#code) | Synchronized 1-of-1 position NFT |
| **`CryptoSlipTradeRouterV32` (`v33`)** | [`0x2069CA17D45d3421D28f15F20262575333CECF51`](https://basescan.org/address/0x2069CA17D45d3421D28f15F20262575333CECF51#code) | Slip-to-slip & swap-and-pay router |
| **`NARALiquidityHookV5`** | [`0x07d8F2Dfd121B10dE3176DeAb6A8C0eaa2646aCC`](https://basescan.org/address/0x07d8F2Dfd121B10dE3176DeAb6A8C0eaa2646aCC#code) | Canonical Uniswap V4 Hook for `100%` of `NARA` swap legs |
| **Base Builder Code (`ERC-8021`)** | `bc_ea68lz8s` | Appended automatically as Schema 0 calldata suffix |

---

## Local Verification

```bash
cd packages/sdk && npm install && npm run typecheck && npm run lint && npm test && npm run build
cd ../mcp && npm install && npm run typecheck && npm run lint && npm test && npm run build
```

## Security & Disclosure

- Claim keys (`_k<64hex>`), voice keys (`&vk=`), and seals travel **strictly inside `#` URL fragments** — never inside HTTP query strings or server logs.
- Report vulnerabilities via [`https://slip.naraprotocol.io/.well-known/security.txt`](https://slip.naraprotocol.io/.well-known/security.txt) (`security@naraprotocol.io`).

## License

[MIT](./LICENSE)
