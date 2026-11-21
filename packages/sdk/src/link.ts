import { randomBytes } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import * as scryptMod from 'scrypt-js';

const scrypt: typeof scryptMod.scrypt =
  (scryptMod as unknown as { default?: { scrypt: typeof scryptMod.scrypt } }).default?.scrypt ??
  scryptMod.scrypt;
import {
  bytesToBigInt,
  bytesToHex,
  concatBytes,
  hexToBytes,
  numberToBytes,
  stringToBytes,
  type Address,
  type Hex,
} from 'viem';
import { privateKeyToAccount, privateKeyToAddress, type PrivateKeyAccount } from 'viem/accounts';
import {
  CANONICAL_SHARE_ORIGIN,
  ISSUE_VAULT,
  NO_TAKE_BACK_LOCK,
  OFFGRID_PERMANENT_LOCK_UNTIL,
  SLIP_SEAL_PUBLIC_KEY,
  SOVEREIGN_ENS_ORIGIN,
  TELEGRAM_APP_LINK,
  isV32ProtocolVault,
  normalizeSdkAsset,
  toLinkAsset,
  type AnyAssetSymbol,
  type SdkAssetSymbol,
  type SupportedLinkAsset,
  type VaultTag,
} from './constants.js';

export type SlipLinkMode = 'open' | 'code';

export class SlipLinkSecurityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SlipLinkSecurityError';
  }
}

export interface DecodedSlipLink {
  id: string;
  amount: number;
  asset: SupportedLinkAsset;
  vault: VaultTag;
  mode: SlipLinkMode;
  /** 0x-prefixed private key, present for open links */
  claimKey?: Hex;
  /** 48 hex chars (24-byte prefix), present for social-sealed open links (_s<48-hex>) */
  claimKeyPrefix?: string;
  /** 32 hex chars, present for code-protected links */
  codeSalt?: string;
  /** Optional 0x-prefixed referrer wallet address (never emitted on V3.2 links) */
  referrer?: string;
  /** Optional V3.2 off-grid protection lock UNIX timestamp (seconds) before which creator cannot refund */
  cancelLockedUntil?: number;
  /** Optional Burn-on-Play encrypted voice note marker (_vn1) carried strictly inside # fragment */
  hasVoiceNote?: boolean;
  /** Older links advertised a PIN/recipient restriction that was never enforced */
  legacyProtection?: 'pin' | 'recipient';
}

export interface ParsedSlipUrl extends DecodedSlipLink {
  sdkAsset: SdkAssetSymbol;
  /** Checksummed EVM address derived from `claimKey` (for open unsealed links) */
  claimAddress?: Address;
  /** Fragment-only burn-on-play voice key (`&vk=...`), never read from query string */
  voiceKey?: string;
  /** Sanitized sender note (`&note=...` or `?n=...`) */
  note?: string;
  /** Fragment-only Slip Seal token (`&seal=...`), never read from query string */
  socialSeal?: string;
  /** Fragment-only formatted 12-char claim code (`&code=XXXX-XXXX-XXXX`), never read from query string */
  claimCode?: string;
}

const KEY_RE = /^k(0x)?([0-9a-fA-F]{64})$/;
const SEALED_KEY_PREFIX_RE = /^s([0-9a-fA-F]{48})$/;
const SALT_RE = /^z([0-9a-fA-F]{32})$/;
const LOCK_UNTIL_RE = /^cl(9999999999)$/;
const VOICE_NOTE_FLAG_RE = /^vn1$/i;
export const VOICE_KEY_FRAGMENT_RE = /^[A-Za-z0-9_-]{22,44}$/;
const SLIP_SEAL_TOKEN_RE = /^[A-Za-z0-9_-]{40,120}$/;

const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export const CLAIM_CODE_LENGTH = 12;
const SCRYPT_N = 1 << 14;
const SCRYPT_R = 8;
const SCRYPT_P = 1;

const FORBIDDEN_NOTE_WORDS_RE =
  /\b(?:you\s+received|dollars?|cash|bank|account|deposit|escrow|bearer|locked?|locks?|gas|base\s+l2|crypto\s+slip|fdic|redeem\w*|refund\w*|revert\w*|expir\w*|vouchers?|basescan)\b/gi;

const SHARED_HOSTING_BLOCKED_ON_SOCIAL_RE = /(?:^|\.)(?:4everland\.app|eth\.limo|eth\.link)$/i;
const TELEGRAM_HOST_RE = /(?:^|\.)(?:t\.me|telegram\.me|telegram\.dog)$/i;

// ============================================================================
// Secret Detection & Fragment-Only Transport Guards
// ============================================================================

/** Checks whether a string contains a raw/URL-encoded claim key (`_k<64hex>`), sealed prefix (`_s<48hex>`), or `seal=`. */
export const containsClaimKey = (raw: string): boolean => {
  let value = raw || '';
  for (let i = 0; i < 3; i++) {
    if (
      /(?:^|[^0-9a-zA-Z])(?:k(?:0x)?[0-9a-f]{64}|s[0-9a-f]{48})(?:[^0-9a-f]|$)/i.test(value) ||
      /(?:^|[#&?])seal=[A-Za-z0-9_-]{40,120}(?:[&#]|$)/i.test(value)
    ) {
      return true;
    }
    try {
      const decoded = decodeURIComponent(value);
      if (decoded === value) break;
      value = decoded;
    } catch {
      break;
    }
  }
  return false;
};

/**
 * True for any payload or URL carrying claim keys, Slip Seal tokens, claim codes, or private voice/note markers
 * (`_vn1`, `&vk=`, `&en=`, `&code=`). Such links MUST NEVER enter HTTP query strings or `t.me` URLs.
 */
export const requiresFragmentOnlyTransport = (raw: string): boolean => {
  if (containsClaimKey(raw)) return true;
  let value = raw || '';
  for (let i = 0; i < 3; i++) {
    if (
      /(?:^|_)vn\d+(?:_|[&#?]|$)/i.test(value) ||
      /(?:^|[#&?])(?:vk|en|code)=[A-Za-z0-9_-]{4,}/i.test(value)
    ) {
      return true;
    }
    try {
      const decoded = decodeURIComponent(value);
      if (decoded === value) break;
      value = decoded;
    } catch {
      break;
    }
  }
  return false;
};

export const safeTelegramInitData = (raw: unknown): string | undefined =>
  typeof raw === 'string' && raw && !containsClaimKey(raw) ? raw : undefined;

/**
 * Enforces Hard Invariant #4: throws `SlipLinkSecurityError` if any claim key (`_k<64hex>`),
 * sealed prefix (`_s<48hex>`), Slip Seal, claim code, or voice key touches an HTTP query string
 * or any `t.me` / `telegram.me` URL (even inside a fragment on `t.me`).
 */
export function assertFragmentSafeUrl(rawUrl: string): void {
  const trimmed = (rawUrl || '').trim();
  if (!trimmed) return;
  if (/^https?:/i.test(trimmed)) {
    let parsed: URL;
    try {
      parsed = new URL(trimmed);
    } catch {
      throw new SlipLinkSecurityError('Malformed slip URL');
    }
    const serverVisiblePart = `${parsed.origin}${parsed.pathname}${parsed.search}`;
    if (requiresFragmentOnlyTransport(serverVisiblePart)) {
      throw new SlipLinkSecurityError(
        'Claim keys, seals, codes, and voice secrets MUST travel strictly in URL # fragments and never in query strings or paths.',
      );
    }
    if (TELEGRAM_HOST_RE.test(parsed.hostname) && requiresFragmentOnlyTransport(trimmed)) {
      throw new SlipLinkSecurityError(
        'Claim keys and fragment secrets MUST NEVER be placed on t.me URLs; only key-free _z<32hex> salt payloads are permitted in Telegram startapp links.',
      );
    }
    return;
  }
  if (/^(?:t\.me|telegram\.me)\//i.test(trimmed) && requiresFragmentOnlyTransport(trimmed)) {
    throw new SlipLinkSecurityError(
      'Claim keys and fragment secrets MUST NEVER be placed on t.me URLs; only key-free _z<32hex> salt payloads are permitted in Telegram startapp links.',
    );
  }
  const qIdx = trimmed.indexOf('?');
  const hIdx = trimmed.indexOf('#');
  if (qIdx >= 0 && (hIdx < 0 || qIdx < hIdx)) {
    const queryPart = hIdx >= 0 ? trimmed.slice(0, hIdx) : trimmed;
    if (requiresFragmentOnlyTransport(queryPart)) {
      throw new SlipLinkSecurityError(
        'Claim keys, seals, codes, and voice secrets MUST travel strictly in URL # fragments and never in query strings.',
      );
    }
  }
}

// ============================================================================
// Amount, Label & Note Sanitizers (`slipLink.ts` & `voucherCardImage.ts` Parity)
// ============================================================================

export const formatPlainDecimal = (amount: number, maxDecimals = 8): string => {
  if (!Number.isFinite(amount) || amount <= 0) return '0';
  return amount.toFixed(maxDecimals).replace(/\.?0+$/, '') || '0';
};

export const formatAmountToken = (amount: number, asset: AnyAssetSymbol): string => {
  const linkAsset = toLinkAsset(asset);
  if (linkAsset === 'ETH' || linkAsset === 'BTC' || linkAsset === 'NARA') {
    const decimals = linkAsset === 'BTC' || linkAsset === 'ETH' ? 8 : 6;
    return amount.toFixed(decimals).replace(/\.?0+$/, '').replace('.', '-');
  }
  return amount % 1 === 0 ? amount.toFixed(0) : amount.toFixed(2).replace('.', '-');
};

export const parseAmountToken = (token: string | undefined): number => {
  const n = parseFloat((token || '').replace('-', '.'));
  return Number.isFinite(n) && n > 0 ? n : 0;
};

export function sanitizeSlipNote(raw?: string | null): string {
  if (!raw || typeof raw !== 'string') return '';
  const cleaned = raw
    .replace(/https?:\/\/\S+/gi, '')
    .replace(/\bslip_[A-Za-z0-9_-]+/gi, '')
    .replace(/\bseal=[A-Za-z0-9_-]{16,}/gi, '')
    .replace(/0x[0-9a-fA-F]{6,}/g, '')
    .replace(/\b[0-9a-fA-F]{16,}\b/g, '')
    .replace(/\b[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}\b/g, '')
    .replace(/\b[0-9A-HJ-NP-TV-Z]{4}\s+[0-9A-HJ-NP-TV-Z]{4}\s+[0-9A-HJ-NP-TV-Z]{4}\b/g, '')
    .replace(/\b[0-9A-HJ-NP-TV-Z]{12}\b/g, '')
    .replace(/[<>"'`\\]/g, '')
    .replace(/\p{Extended_Pictographic}/gu, '')
    .replace(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/gu, '')
    .replace(FORBIDDEN_NOTE_WORDS_RE, '')
    .replace(/\s+/g, ' ')
    .trim();
  return cleaned.slice(0, 36).trim();
}

const sanitizeShortLabel = (raw: string | null | undefined, maxLen: number): string | undefined => {
  if (!raw || typeof raw !== 'string') return undefined;
  let stripped = '';
  for (let i = 0; i < raw.length; i++) {
    const code = raw.charCodeAt(i);
    stripped += code < 32 || code === 127 || code === 60 || code === 62 ? ' ' : raw[i];
  }
  const cleaned = stripped.replace(/\s+/g, ' ').trim().slice(0, maxLen);
  return cleaned || undefined;
};

// ============================================================================
// Core Slip Payload Encoder / Decoder (`client/src/lib/slipLink.ts` Byte Parity)
// ============================================================================

export interface EncodeSlipLinkInput {
  id: string | bigint | number;
  amount: number;
  asset: AnyAssetSymbol;
  vault?: VaultTag;
  mode: SlipLinkMode;
  claimKey?: string;
  claimKeyPrefix?: string;
  codeSalt?: string;
  referrer?: string;
  cancelLockedUntil?: number | bigint;
  hasVoiceNote?: boolean;
}

export const encodeSlipPayload = (input: EncodeSlipLinkInput): string => {
  const idStr = String(input.id);
  if (!/^\d{1,20}$/.test(idStr) || /^0+$/.test(idStr)) {
    throw new Error('Slip id must be a positive numeric integer');
  }
  if (!Number.isFinite(input.amount) || input.amount <= 0) {
    throw new Error('Slip amount must be positive');
  }
  const linkAsset = toLinkAsset(input.asset);
  const vault = input.vault ?? ISSUE_VAULT;
  const parts = ['slip', idStr, formatAmountToken(input.amount, linkAsset), input.mode];
  const effectiveVault: VaultTag =
    vault === 'v33'
      ? 'v33'
      : vault === 'v32' || (vault === 'v3' && linkAsset === 'NARA')
        ? 'v32'
        : vault;
  if (effectiveVault === 'v33') parts.push('v33');
  else if (effectiveVault === 'v32') parts.push('v32');
  else if (effectiveVault === 'v3') parts.push('v3');

  if (linkAsset === 'ETH') parts.push('eth');
  if (linkAsset === 'BTC') parts.push('btc');
  if (linkAsset === 'NARA') parts.push('nara');

  const lockNum =
    input.cancelLockedUntil !== undefined ? Number(input.cancelLockedUntil) : 0;
  if (lockNum !== 0 && lockNum !== OFFGRID_PERMANENT_LOCK_UNTIL) {
    throw new Error(`Invalid cancelLockedUntil: expected 0 or ${OFFGRID_PERMANENT_LOCK_UNTIL}`);
  }
  if (isV32ProtocolVault(effectiveVault) && lockNum === OFFGRID_PERMANENT_LOCK_UNTIL) {
    parts.push(`cl${OFFGRID_PERMANENT_LOCK_UNTIL}`);
  }
  if (input.hasVoiceNote) {
    parts.push('vn1');
  }
  if (input.mode === 'open') {
    if (input.claimKeyPrefix && !input.claimKey) {
      const prefix = input.claimKeyPrefix.replace(/^0x/i, '').toLowerCase();
      if (!/^[0-9a-f]{48}$/.test(prefix)) {
        throw new Error('Sealed open links require a 48-hex claimKeyPrefix');
      }
      parts.push(`s${prefix}`);
    } else {
      const key = (input.claimKey || '').replace(/^0x/i, '');
      if (!/^[0-9a-fA-F]{64}$/.test(key)) {
        throw new Error('Open links need the slip claim key');
      }
      parts.push(`k${key}`);
    }
  } else {
    if (!/^[0-9a-fA-F]{32}$/.test(input.codeSalt || '')) {
      throw new Error('Code links need a 32-hex salt');
    }
    parts.push(`z${input.codeSalt}`);
  }
  return parts.join('_');
};

/** Extract the raw start parameter from a full link, a deep link, or a bare payload. */
export const extractStartParam = (raw: string): string => {
  let clean = (raw || '').trim();
  if (/^ethereum:/i.test(clean)) return clean;
  const m = clean.match(/(?:[?#&]|^)(?:startapp|start)=([A-Za-z0-9_-]+)/);
  if (m?.[1]) return m[1];
  const pay = clean.match(/(?:[?#&]|^)pay=([A-Za-z0-9_-]+)/);
  if (pay?.[1]) return pay[1];
  clean = clean.replace(/^.*\/(?=slip_|pay_|pos_|ref_)/, '');
  if (/^(?:slip_|pay_|pos_|ref_|restore_)/i.test(clean)) {
    clean = clean.split(/[&#?]/)[0] ?? clean;
  }
  return clean;
};

export const decodeSlipPayload = (raw: string): DecodedSlipLink | null => {
  const payload = extractStartParam(raw);
  if (!payload.startsWith('slip_')) return null;
  const parts = payload.split('_');
  const id = parts[1] || '';
  if (!/^\d{1,20}$/.test(id) || /^0+$/.test(id)) return null;
  const amount = parseAmountToken(parts[2]);
  if (amount <= 0) return null;

  const rawMode = (parts[3] || 'open').toLowerCase();
  const flags = parts.slice(4);
  const keyMatch = flags.map((p) => p.match(KEY_RE)).find(Boolean);
  const sealedKeyMatch = flags.map((p) => p.match(SEALED_KEY_PREFIX_RE)).find(Boolean);
  const saltMatch = flags.map((p) => p.match(SALT_RE)).find(Boolean);
  const clMatch = flags.map((p) => p.match(LOCK_UNTIL_RE)).find(Boolean);
  const hasVoiceNote = flags.some((p) => VOICE_NOTE_FLAG_RE.test(p));

  const asset: SupportedLinkAsset = flags.includes('eth')
    ? 'ETH'
    : flags.includes('btc')
      ? 'BTC'
      : flags.includes('nara')
        ? 'NARA'
        : 'USDC';
  const rawVault: VaultTag = flags.includes('v33')
    ? 'v33'
    : flags.includes('v32')
      ? 'v32'
      : flags.includes('v3')
        ? 'v3'
        : 'v2';
  const resolvedVault: VaultTag = rawVault === 'v3' && asset === 'NARA' ? 'v32' : rawVault;

  const decoded: DecodedSlipLink = {
    id,
    amount,
    asset,
    vault: resolvedVault,
    mode: rawMode === 'code' ? 'code' : 'open',
  };
  if (keyMatch?.[2]) decoded.claimKey = `0x${keyMatch[2]}` as Hex;
  if (sealedKeyMatch?.[1]) decoded.claimKeyPrefix = sealedKeyMatch[1].toLowerCase();
  if (saltMatch?.[1]) decoded.codeSalt = saltMatch[1];
  if (clMatch && isV32ProtocolVault(resolvedVault)) {
    decoded.cancelLockedUntil = OFFGRID_PERMANENT_LOCK_UNTIL;
  }
  if (hasVoiceNote && !sealedKeyMatch) decoded.hasVoiceNote = true;
  if (rawMode === 'pin') decoded.legacyProtection = 'pin';
  if (rawMode === 'rec' || rawMode === 'recipient') decoded.legacyProtection = 'recipient';
  if (decoded.mode === 'code' && !decoded.codeSalt) return null;
  return decoded;
};

// ============================================================================
// Canonical Web, Sovereign ENS & Telegram Link Builders + Strict URL Parser
// ============================================================================

export const isSharedGatewayBlockedOnSocial = (hostname: string): boolean =>
  SHARED_HOSTING_BLOCKED_ON_SOCIAL_RE.test((hostname || '').replace(/\.+$/, ''));

export const buildSlipLinks = (
  payload: string,
  origin: string = CANONICAL_SHARE_ORIGIN,
): { webLink: string; tgLink: string; sovereignLink: string } => {
  if (!/^[A-Za-z0-9_-]{1,512}$/.test(payload)) {
    throw new Error('Invalid slip link payload');
  }
  const webOrigin = (origin || CANONICAL_SHARE_ORIGIN).replace(/\/$/, '');
  const base = new URL(webOrigin + '/');
  const fragmentOnly = requiresFragmentOnlyTransport(payload);
  if (TELEGRAM_HOST_RE.test(base.hostname)) {
    throw new SlipLinkSecurityError(
      'Cannot use t.me as web origin; use buildTelegramStartAppUrl for key-free code payloads.',
    );
  }
  if (
    (base.protocol !== 'https:' && !(base.protocol === 'http:' && !fragmentOnly)) ||
    base.username ||
    base.password ||
    base.search ||
    base.hash
  ) {
    throw new Error('Open CryptoSLIP over HTTPS to share a slip safely.');
  }
  const webLink = `${base.href}#startapp=${payload}`;
  const sovereignLink = `${SOVEREIGN_ENS_ORIGIN}/#startapp=${payload}`;
  return {
    tgLink: fragmentOnly ? webLink : `${TELEGRAM_APP_LINK}?startapp=${payload}`,
    webLink,
    sovereignLink,
  };
};

/**
 * Builds a `https://t.me/cryptoslip_bot/SLIP?startapp=...` link ONLY for key-free payloads
 * (such as `_z<32hex>` code-protected slips without voice/note secrets, `pos_`, `pay_`, or `ref_`).
 * HARD-THROWS `SlipLinkSecurityError` if `_k<64hex>`, `_s<48hex>`, or `_vn1` is present!
 */
export function buildTelegramStartAppUrl(payload: string): string {
  if (!/^[A-Za-z0-9_-]{1,512}$/.test(payload)) {
    throw new Error('Invalid Telegram startapp payload');
  }
  if (requiresFragmentOnlyTransport(payload)) {
    throw new SlipLinkSecurityError(
      'Refusing to build t.me?startapp= URL for a payload containing a claim key or secret marker.',
    );
  }
  return `${TELEGRAM_APP_LINK}?startapp=${payload}`;
}

/**
 * Builds a sovereign ENS gateway URL (`https://cryptoslip.eth.limo/#startapp=slip_...`).
 */
export function buildSovereignSlipLink(
  payload: string,
  extraFragment?: { seal?: string; vk?: string; code?: string; note?: string },
): string {
  const { sovereignLink } = buildSlipLinks(payload, SOVEREIGN_ENS_ORIGIN);
  let out = sovereignLink;
  if (extraFragment?.seal) {
    if (!SLIP_SEAL_TOKEN_RE.test(extraFragment.seal)) throw new Error('Invalid Slip Seal token');
    out += `&seal=${extraFragment.seal}`;
  }
  if (extraFragment?.vk) {
    if (!VOICE_KEY_FRAGMENT_RE.test(extraFragment.vk)) throw new Error('Invalid voice key');
    out += `&vk=${extraFragment.vk}`;
  }
  if (extraFragment?.code) {
    if (!isWellFormedClaimCode(extraFragment.code)) throw new Error('Invalid 12-char claim code');
    out += `&code=${formatClaimCode(extraFragment.code)}`;
  }
  const cleanNote = sanitizeSlipNote(extraFragment?.note);
  if (cleanNote) {
    out += `&note=${encodeURIComponent(cleanNote)}`;
  }
  return out;
}

export interface EncodeSlipUrlOptions extends EncodeSlipLinkInput {
  origin?: string;
  voiceKey?: string;
  note?: string;
  socialSeal?: string;
  /** Optional fragment-only claim code (`&code=XXXX-XXXX-XXXX`), never placed in query string */
  embedClaimCodeInFragment?: string;
  includePublicPreviewParams?: boolean;
  usdEstimate?: number;
}

/**
 * High-level encoder producing canonical `#startapp=slip_...`, sovereign `.eth.limo`, and safe Telegram URLs.
 */
export function encodeSlipUrl(options: EncodeSlipUrlOptions): {
  payload: string;
  webUrl: string;
  sovereignUrl: string;
  telegramUrl: string | null;
} {
  const hasVoice = Boolean(options.hasVoiceNote || options.voiceKey);
  const payload = encodeSlipPayload({
    ...options,
    hasVoiceNote: hasVoice,
  });
  const origin = options.origin || CANONICAL_SHARE_ORIGIN;
  const { webLink } = buildSlipLinks(payload, origin);

  let fragmentSuffix = '';
  if (options.socialSeal) {
    if (!SLIP_SEAL_TOKEN_RE.test(options.socialSeal)) {
      throw new Error('Invalid Slip Seal token');
    }
    fragmentSuffix += `&seal=${options.socialSeal}`;
  }
  if (options.voiceKey) {
    if (!VOICE_KEY_FRAGMENT_RE.test(options.voiceKey)) {
      throw new Error('Invalid voice key');
    }
    fragmentSuffix += `&vk=${options.voiceKey}`;
  }
  if (options.embedClaimCodeInFragment) {
    if (!isWellFormedClaimCode(options.embedClaimCodeInFragment)) {
      throw new Error('Invalid 12-character claim code');
    }
    fragmentSuffix += `&code=${formatClaimCode(options.embedClaimCodeInFragment)}`;
  }
  const cleanNote = sanitizeSlipNote(options.note);
  if (cleanNote) {
    fragmentSuffix += `&note=${encodeURIComponent(cleanNote)}`;
  }

  let webUrl = `${webLink}${fragmentSuffix}`;
  if (options.includePublicPreviewParams) {
    try {
      const u = new URL(webUrl);
      if (u.protocol === 'https:' && u.origin === CANONICAL_SHARE_ORIGIN) {
        const linkAsset = toLinkAsset(options.asset);
        const cleanAmt =
          linkAsset === 'USDC'
            ? options.amount % 1 === 0
              ? String(options.amount)
              : options.amount.toFixed(2)
            : String(Number(options.amount.toFixed(8)));
        u.searchParams.set('v', cleanAmt);
        u.searchParams.set('c', linkAsset);
        if (
          linkAsset !== 'USDC' &&
          typeof options.usdEstimate === 'number' &&
          Number.isFinite(options.usdEstimate) &&
          options.usdEstimate > 0
        ) {
          u.searchParams.set('u', options.usdEstimate.toFixed(2));
        }
        if (cleanNote) {
          u.searchParams.set('n', cleanNote);
        }
        webUrl = u.toString();
      }
    } catch {
      /* keep fragment URL untouched */
    }
  }

  assertFragmentSafeUrl(webUrl);
  const sovereignUrl = `${SOVEREIGN_ENS_ORIGIN}/#startapp=${payload}${fragmentSuffix}`;
  const telegramUrl =
    !requiresFragmentOnlyTransport(payload) && !fragmentSuffix
      ? buildTelegramStartAppUrl(payload)
      : null;

  return { payload, webUrl, sovereignUrl, telegramUrl };
}

/**
 * Strict, full-featured parser for CryptoSLIP URLs and payloads (`onboarding.ts` + `slipLink.ts` parity).
 * HARD-THROWS `SlipLinkSecurityError` if `_k<64hex>`, `_s<48hex>`, `seal=`, `vk=`, or `code=` touches
 * an HTTP query string or a `t.me` URL.
 */
export function parseSlipUrl(rawUrlOrPayload: string): ParsedSlipUrl | null {
  const raw = (rawUrlOrPayload || '').trim();
  if (!raw) return null;
  assertFragmentSafeUrl(raw);

  const decoded = decodeSlipPayload(raw);
  if (!decoded) return null;

  const result: ParsedSlipUrl = {
    ...decoded,
    sdkAsset: normalizeSdkAsset(decoded.asset),
  };

  if (decoded.claimKey) {
    result.claimAddress = privateKeyToAddress(decoded.claimKey);
  }

  let hashString = '';
  let searchString = '';
  if (/^https?:/i.test(raw)) {
    try {
      const u = new URL(raw);
      hashString = u.hash.replace(/^#\/?/, '');
      searchString = u.search.replace(/^\?/, '');
    } catch {
      return null;
    }
  } else {
    const hashIdx = raw.indexOf('#');
    if (hashIdx >= 0) {
      hashString = raw.slice(hashIdx + 1).replace(/^\/?/, '');
    } else if (!raw.includes('?') && raw.includes('&')) {
      hashString = raw;
    }
  }

  if (hashString) {
    const hashParams = new URLSearchParams(hashString);
    const vk = (hashParams.get('vk') || '').trim();
    if (VOICE_KEY_FRAGMENT_RE.test(vk)) {
      result.voiceKey = vk;
    }
    const seal = (hashParams.get('seal') || '').trim();
    if (SLIP_SEAL_TOKEN_RE.test(seal)) {
      result.socialSeal = seal;
    }
    const code = (hashParams.get('code') || '').trim();
    if (code && isWellFormedClaimCode(code)) {
      result.claimCode = formatClaimCode(code);
    }
    const hashNote = sanitizeSlipNote(hashParams.get('note'));
    if (hashNote) {
      result.note = hashNote;
    }
  }

  if (!result.note && searchString) {
    const searchParams = new URLSearchParams(searchString);
    const nParam = searchParams.get('n');
    if (nParam && !requiresFragmentOnlyTransport(nParam)) {
      const cleanQueryNote = sanitizeSlipNote(nParam);
      if (cleanQueryNote) {
        result.note = cleanQueryNote;
      }
    }
  }

  return result;
}

export const buildReceivedSlipLink = (
  received: {
    rawPayload?: string;
    socialSeal?: string;
    claimCode?: string;
    voiceKey?: string;
    senderNote?: string;
  },
  origin: string = CANONICAL_SHARE_ORIGIN,
): string | null => {
  const payload = received.rawPayload || '';
  if (!/^slip_[A-Za-z0-9_-]{1,507}$/.test(payload)) return null;
  const sealed = payload.split('_').some((part) => SEALED_KEY_PREFIX_RE.test(part));
  if (received.socialSeal ? !SLIP_SEAL_TOKEN_RE.test(received.socialSeal) : sealed) return null;
  const code =
    received.claimCode && isWellFormedClaimCode(received.claimCode)
      ? formatClaimCode(received.claimCode)
      : '';
  const voiceKey =
    received.voiceKey && VOICE_KEY_FRAGMENT_RE.test(received.voiceKey) ? received.voiceKey : '';
  let link: string;
  try {
    link = buildSlipLinks(payload, origin).webLink;
    if ((received.socialSeal || code || voiceKey) && new URL(link).protocol !== 'https:') {
      return null;
    }
  } catch {
    return null;
  }
  if (received.socialSeal) link += `&seal=${received.socialSeal}`;
  if (voiceKey && !sealed) link += `&vk=${voiceKey}`;
  if (code) link += `&code=${code}`;
  if (received.senderNote) link += `&note=${encodeURIComponent(received.senderNote.slice(0, 36))}`;
  return link;
};

// ============================================================================
// 12-Character Crockford-Base32 `scrypt` Claim Codes (`claimCode.ts` Byte Parity)
// ============================================================================

export const generateClaimCode = (): string => {
  const bytes = randomBytes(8);
  let n = bytesToBigInt(bytes);
  let out = '';
  for (let i = 0; i < CLAIM_CODE_LENGTH; i++) {
    out += CROCKFORD[Number(n & 31n)];
    n >>= 5n;
  }
  return out;
};

export const normalizeClaimCode = (input: string): string =>
  (input || '')
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1')
    .replace(/U/g, 'V');

export const isWellFormedClaimCode = (input: string): boolean => {
  const c = normalizeClaimCode(input);
  return c.length === CLAIM_CODE_LENGTH && [...c].every((ch) => CROCKFORD.includes(ch));
};

export const formatClaimCode = (code: string): string =>
  normalizeClaimCode(code).replace(/(.{4})(?=.)/g, '$1-');

export const generateCodeSalt = (): string => bytesToHex(randomBytes(16)).slice(2);

export interface DerivedCodeWallet {
  readonly privateKey: Hex;
  readonly address: Address;
  readonly account: PrivateKeyAccount;
}

/**
 * Deterministically derives the slip's secp256k1 claim key from `(code, saltHex)` using
 * `scrypt` (`N = 16384, r = 8, p = 1, dkLen = 32`).
 * 100% byte-for-byte identical to `client/src/lib/claimCode.ts:deriveClaimWallet`.
 */
export async function deriveCodeWallet(code: string, saltHex: string): Promise<DerivedCodeWallet> {
  if (!isWellFormedClaimCode(code)) {
    throw new Error('Claim code must be 12 letters/numbers');
  }
  if (!/^[0-9a-fA-F]{32}$/.test(saltHex)) {
    throw new Error('Link is missing its 32-hex code salt');
  }
  const password = stringToBytes(`cryptoslip-claim-v1:${normalizeClaimCode(code)}`);
  for (let counter = 0; counter < 8; counter++) {
    const salt = hexToBytes(
      `0x${saltHex.toLowerCase()}${counter.toString(16).padStart(2, '0')}` as Hex,
    );
    const derived = await scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, 32);
    const k = bytesToBigInt(derived);
    if (k > 0n && k < SECP256K1_N) {
      const privateKey = bytesToHex(derived);
      const account = privateKeyToAccount(privateKey);
      return {
        privateKey,
        address: account.address,
        account,
      };
    }
  }
  throw new Error('Could not derive a claim key');
}

export const deriveClaimWallet = deriveCodeWallet;

// ============================================================================
// Offline Slip Seal ECIES Codec (`farcasterHelper.ts` & `slipSealCore.mjs` Parity)
// ============================================================================

function encodeBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function decodeBase64Url(input: string): Uint8Array {
  const clean = String(input || '')
    .trim()
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  if (!clean || !/^[A-Za-z0-9+/=]+$/.test(clean)) {
    throw new Error('Invalid Slip Seal encoding');
  }
  const padded = clean + '='.repeat((4 - (clean.length % 4)) % 4);
  return new Uint8Array(Buffer.from(padded, 'base64'));
}

export interface SealSlipOptions {
  /** Gem #46 guard: passing a `No take-back` (`9_999_999_999`) timestamp throws immediately! */
  cancelLockedUntil?: number | bigint;
  /** Optional deterministic ephemeral private key (`0x` + 64 hex) strictly for deterministic vector tests */
  ephemeralPrivateKeyForTest?: Hex;
}

/**
 * Seals a slip secret fragment (`12-char` claim code or `16-hex` open-key tail) using secp256k1 ECIES
 * bound to `(vault, slipId)` (`cs-seal-v1:<vault>:<slipId>`).
 *
 * Enforces **Gem #46**: HARD-THROWS if sealing a `No take-back` (`cancelLockedUntil == 9_999_999_999`) slip
 * so `No take-back` slips stay 100% self-contained without any Slip Seal server dependency!
 */
export function sealSlipSecretPart(
  secretPart: string,
  slipId: string,
  vault: VaultTag | string = ISSUE_VAULT,
  sealPublicKey: Hex | string = SLIP_SEAL_PUBLIC_KEY,
  options?: SealSlipOptions,
): string {
  if (
    options?.cancelLockedUntil !== undefined &&
    BigInt(options.cancelLockedUntil) !== 0n
  ) {
    throw new SlipLinkSecurityError(
      'Gem #46 violation: No take-back slips (cancelLockedUntil == 9_999_999_999) MUST stay 100% self-contained and cannot use Slip Seal.',
    );
  }
  if (!/^\d{1,20}$/.test(String(slipId || '')) || /^0+$/.test(String(slipId))) {
    throw new Error('Invalid slip ID for Slip Seal');
  }
  const cleanSecret = (secretPart || '').trim();
  if (!/^[0-9A-Za-z]{8,24}$/.test(cleanSecret)) {
    throw new Error('Invalid Slip Seal secret fragment.');
  }
  const cleanVault = String(vault || ISSUE_VAULT).toLowerCase();
  if (!['v33', 'v32', 'v3', 'v2'].includes(cleanVault)) {
    throw new Error('Invalid slip vault for Slip Seal');
  }

  const ephPrivBytes = options?.ephemeralPrivateKeyForTest
    ? hexToBytes(options.ephemeralPrivateKeyForTest)
    : new Uint8Array(randomBytes(32));

  try {
    const ephPub = secp256k1.getPublicKey(ephPrivBytes, true);
    const pubKeyHex = sealPublicKey.startsWith('0x') ? sealPublicKey.slice(2) : sealPublicKey;
    // Uncompressed 65-byte ECDH shared point matches `ethers.SigningKey.computeSharedSecret` byte-for-byte.
    const sharedSecret = secp256k1.getSharedSecret(ephPrivBytes, pubKeyHex, false);
    const context = stringToBytes(`cs-seal-v1:${cleanVault}:${slipId}`);
    const keyStream = keccak_256(
      concatBytes([sharedSecret, ephPub, context, stringToBytes(':enc')]),
    );
    const plainBytes = stringToBytes(cleanSecret);
    const cipherBytes = new Uint8Array(plainBytes.length);
    for (let i = 0; i < plainBytes.length; i++) {
      cipherBytes[i] = (plainBytes[i] ?? 0) ^ (keyStream[i] ?? 0);
    }
    const macBytes = keccak_256(
      concatBytes([sharedSecret, ephPub, context, cipherBytes, stringToBytes(':mac')]),
    ).slice(0, 8);
    sharedSecret.fill(0);
    keyStream.fill(0);
    plainBytes.fill(0);
    const packed = concatBytes([ephPub, cipherBytes, macBytes]);
    return encodeBase64Url(packed);
  } finally {
    if (!options?.ephemeralPrivateKeyForTest) {
      ephPrivBytes.fill(0);
    }
  }
}

/**
 * Unseals a Slip Seal token using a secp256k1 private scalar (`0x` + 64 hex).
 * Byte-for-byte parity with `shared/slipSealCore.mjs:unsealSlipSecretPart`.
 */
export function unsealSlipSecretPart(
  sealToken: string,
  slipId: string,
  vault: VaultTag | string,
  sealScalar: Hex | string,
): string {
  if (!/^\d{1,20}$/.test(String(slipId || '')) || /^0+$/.test(String(slipId))) {
    throw new Error('Invalid slip ID');
  }
  const cleanVault = String(vault || ISSUE_VAULT).toLowerCase();
  if (!['v33', 'v32', 'v3', 'v2'].includes(cleanVault)) {
    throw new Error('Invalid slip vault');
  }
  const packed = decodeBase64Url(sealToken);
  if (packed.length < 49 || packed.length > 65) {
    throw new Error('Invalid Slip Seal length');
  }
  const ephPub = packed.slice(0, 33);
  const cipherBytes = packed.slice(33, packed.length - 8);
  const macBytes = packed.slice(packed.length - 8);

  const scalarHex = (sealScalar.startsWith('0x') ? sealScalar.slice(2) : sealScalar).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(scalarHex)) {
    throw new Error('Invalid Slip Seal scalar');
  }
  let sharedSecret: Uint8Array;
  try {
    sharedSecret = secp256k1.getSharedSecret(scalarHex, ephPub, false);
  } catch {
    throw new Error('Invalid Slip Seal ephemeral key');
  }

  const context = stringToBytes(`cs-seal-v1:${cleanVault}:${slipId}`);
  const expectedMac = keccak_256(
    concatBytes([sharedSecret, ephPub, context, cipherBytes, stringToBytes(':mac')]),
  ).slice(0, 8);
  let diff = 0;
  for (let i = 0; i < 8; i++) {
    diff |= (macBytes[i] ?? 0) ^ (expectedMac[i] ?? 0);
  }
  if (diff !== 0) {
    sharedSecret.fill(0);
    throw new Error('Slip Seal does not match this slip');
  }

  const keyStream = keccak_256(
    concatBytes([sharedSecret, ephPub, context, stringToBytes(':enc')]),
  );
  const plainBytes = new Uint8Array(cipherBytes.length);
  for (let i = 0; i < cipherBytes.length; i++) {
    plainBytes[i] = (cipherBytes[i] ?? 0) ^ (keyStream[i] ?? 0);
  }
  sharedSecret.fill(0);
  keyStream.fill(0);

  const secretPart = new TextDecoder('utf-8', { fatal: true }).decode(plainBytes);
  plainBytes.fill(0);
  if (!/^[0-9A-Za-z]{8,24}$/.test(secretPart)) {
    throw new Error('Malformed Slip Seal secret');
  }
  return secretPart;
}

export interface SealedSlipShareResult {
  sealedPayload: string;
  sealToken: string;
  shareUrl: string;
}

/**
 * Converts an open or code-protected slip link into a bot-shielded Slip Seal share link
 * (`#startapp=slip_..._s<48hex>&seal=<token>`). Hard-throws on `No take-back` (`Gem #46`)!
 */
export function buildSealedSlipShareUrl(options: {
  rawPayloadOrUrl: string;
  claimCode?: string;
  note?: string;
  origin?: string;
  sealPublicKey?: Hex | string;
}): SealedSlipShareResult {
  const cleanPayload = extractStartParam(options.rawPayloadOrUrl);
  const decoded = decodeSlipPayload(cleanPayload);
  if (!cleanPayload || !decoded) {
    throw new Error('Invalid slip link for Slip Seal.');
  }
  if (
    decoded.cancelLockedUntil !== undefined &&
    BigInt(decoded.cancelLockedUntil) === NO_TAKE_BACK_LOCK
  ) {
    throw new SlipLinkSecurityError(
      'Gem #46 violation: No take-back slips stay 100% self-contained and cannot use Slip Seal.',
    );
  }
  if (decoded.cancelLockedUntil && decoded.cancelLockedUntil > Math.floor(Date.now() / 1000)) {
    throw new SlipLinkSecurityError(
      'No take-back slips stay 100% self-contained so they work forever without any Slip Seal server.',
    );
  }

  const pubKey = options.sealPublicKey || SLIP_SEAL_PUBLIC_KEY;
  let sealedPayload = cleanPayload;
  let sealToken: string;

  if (decoded.mode === 'code') {
    if (!options.claimCode || !isWellFormedClaimCode(options.claimCode)) {
      throw new Error('Missing 12-character claim code for protected social drop.');
    }
    sealToken = sealSlipSecretPart(
      normalizeClaimCode(options.claimCode),
      decoded.id,
      decoded.vault,
      pubKey,
    );
  } else if (decoded.claimKey) {
    const keyHex = decoded.claimKey.replace(/^0x/i, '').toLowerCase();
    const keyPrefix = keyHex.slice(0, 48);
    const keyTail = keyHex.slice(48, 64);
    sealedPayload = cleanPayload.replace(/_k(?:0x)?[0-9a-fA-F]{64}/, `_s${keyPrefix}`);
    sealToken = sealSlipSecretPart(keyTail, decoded.id, decoded.vault, pubKey);
  } else {
    throw new Error('Slip link is missing its claim credential.');
  }

  const rawOrigin = (options.origin || CANONICAL_SHARE_ORIGIN).trim().replace(/\/+$/, '');
  let safeOrigin: string = CANONICAL_SHARE_ORIGIN;
  try {
    const u = new URL(rawOrigin);
    if (u.protocol === 'https:' && !isSharedGatewayBlockedOnSocial(u.hostname)) {
      safeOrigin = rawOrigin;
    }
  } catch {
    safeOrigin = CANONICAL_SHARE_ORIGIN;
  }

  const cleanNote = sanitizeSlipNote(options.note);
  let shareUrl = `${safeOrigin}/#startapp=${sealedPayload}&seal=${sealToken}`;
  if (cleanNote) {
    shareUrl += `&note=${encodeURIComponent(cleanNote)}`;
  }
  return { sealedPayload, sealToken, shareUrl };
}

/** Reconstructs full `0x<64hex>` `claimKey` from `_s<48hex>` + unsealed `16-hex` `secretPart`. */
export function reconstructUnsealedClaimKey(claimKeyPrefix: string, secretPart: string): Hex {
  const prefix = (claimKeyPrefix || '').replace(/^0x/i, '').toLowerCase();
  const tail = (secretPart || '').trim().toLowerCase();
  if (!/^[0-9a-f]{48}$/.test(prefix) || !/^[0-9a-f]{16}$/.test(tail)) {
    throw new Error('Invalid sealed prefix or secret tail for claim key reconstruction');
  }
  return `0x${prefix}${tail}`;
}

// ============================================================================
// Watch-Only POS URLs, Payment Requests, Popup `#checkout` & Referral Invites
// ============================================================================

export interface PaymentRequestLink {
  recipientAddress: string;
  amount: number;
  asset?: SupportedLinkAsset;
  feeMode?: 'gross' | 'net';
  merchantName?: string;
  note?: string;
}

export interface PopupCheckoutLink extends PaymentRequestLink {
  orderId?: string;
  callbackOrigin?: string;
}

export interface TerminalLinkPayload {
  merchantAddress: string;
  asset: SupportedLinkAsset;
  feeMode: 'gross' | 'net';
  merchantName?: string;
}

export const extractPaymentRequestMeta = (
  raw: string,
): { merchantName?: string; note?: string; orderId?: string; callbackOrigin?: string } => {
  const clean = (raw || '').trim();
  if (!clean) return {};
  try {
    const parseParams = (qs: string) => {
      const p = new URLSearchParams(qs);
      const rawOrigin = (p.get('origin') || '').trim();
      let validOrigin: string | undefined;
      if (rawOrigin) {
        try {
          const ou = new URL(rawOrigin);
          if (ou.protocol === 'https:' || (ou.protocol === 'http:' && (ou.hostname === 'localhost' || ou.hostname === '127.0.0.1'))) {
            validOrigin = ou.origin;
          }
        } catch {
          validOrigin = undefined;
        }
      }
      return {
        merchantName: sanitizeShortLabel(p.get('m') || p.get('merchant'), 40),
        note: sanitizeShortLabel(p.get('note') || p.get('memo'), 60),
        orderId: sanitizeShortLabel(p.get('order') || p.get('orderId'), 64),
        callbackOrigin: validOrigin,
      };
    };
    if (/^https?:/i.test(clean)) {
      const u = new URL(clean);
      const fromHash = parseParams(u.hash.replace(/^#\/?/, ''));
      const fromQuery = parseParams(u.search.replace(/^\?/, ''));
      return {
        merchantName: fromHash.merchantName || fromQuery.merchantName,
        note: fromHash.note || fromQuery.note,
        orderId: fromHash.orderId || fromQuery.orderId,
        callbackOrigin: fromHash.callbackOrigin || fromQuery.callbackOrigin,
      };
    }
    const hashIdx = clean.indexOf('#');
    if (hashIdx >= 0) return parseParams(clean.slice(hashIdx + 1).replace(/^\/?/, ''));
    const ampIdx = clean.indexOf('&');
    if (ampIdx >= 0) return parseParams(clean.slice(ampIdx + 1));
  } catch {
    /* ignore malformed metadata */
  }
  return {};
};

export const encodePaymentRequest = (input: {
  recipientAddress: string;
  amount: number;
  asset?: AnyAssetSymbol;
  feeMode?: 'gross' | 'net';
}): string => {
  const addr = (input.recipientAddress || '').trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(addr) || /^0x0{40}$/i.test(addr)) {
    throw new Error('Invalid recipient address');
  }
  const asset: SupportedLinkAsset = input.asset ? toLinkAsset(input.asset) : 'USDC';
  const amtToken =
    input.amount > 0 && Number.isFinite(input.amount) ? formatAmountToken(input.amount, asset) : '0';
  const parts = ['pay', addr, amtToken];
  if (asset === 'BTC') parts.push('btc');
  else if (asset === 'ETH') parts.push('eth');
  else if (asset === 'NARA') parts.push('nara');
  if (input.feeMode === 'net') parts.push('net');
  return parts.join('_');
};

export const decodePaymentRequest = (raw: string): PaymentRequestLink | null => {
  const payload = extractStartParam(raw);
  if (!payload.startsWith('pay_')) return null;
  const parts = payload.split('_');
  const addr = parts[1] || '';
  if (!/^0x[0-9a-fA-F]{40}$/.test(addr) || /^0x0{40}$/i.test(addr)) return null;
  const flags = parts.slice(3).map((p) => p.toLowerCase());
  const asset: SupportedLinkAsset | undefined = flags.includes('btc')
    ? 'BTC'
    : flags.includes('eth')
      ? 'ETH'
      : flags.includes('nara')
        ? 'NARA'
        : undefined;
  const feeMode: 'net' | undefined = flags.includes('net') ? 'net' : undefined;
  const meta = extractPaymentRequestMeta(raw);
  return {
    recipientAddress: addr,
    amount: parseAmountToken(parts[2]),
    ...(asset ? { asset } : {}),
    ...(feeMode ? { feeMode } : {}),
    ...(meta.merchantName ? { merchantName: meta.merchantName } : {}),
    ...(meta.note ? { note: meta.note } : {}),
  };
};

/**
 * Builds a popup `#checkout` URL (`https://slip.naraprotocol.io/#startapp=pay_<addr>_<amt>&order=<id>&origin=<url>`).
 */
export function buildPopupCheckoutUrl(input: {
  recipientAddress: string;
  amount: number;
  asset?: AnyAssetSymbol;
  feeMode?: 'gross' | 'net';
  orderId?: string;
  callbackOrigin?: string;
  merchantName?: string;
  note?: string;
  appOrigin?: string;
}): string {
  const payload = encodePaymentRequest({
    recipientAddress: input.recipientAddress,
    amount: input.amount,
    asset: input.asset,
    feeMode: input.feeMode,
  });
  const baseOrigin = (input.appOrigin || CANONICAL_SHARE_ORIGIN).replace(/\/$/, '');
  const extra = new URLSearchParams();
  const cleanOrder = sanitizeShortLabel(input.orderId, 64);
  if (cleanOrder) extra.set('order', cleanOrder);
  if (input.callbackOrigin) {
    const ou = new URL(input.callbackOrigin);
    if (
      ou.protocol !== 'https:' &&
      !(ou.protocol === 'http:' && (ou.hostname === 'localhost' || ou.hostname === '127.0.0.1'))
    ) {
      throw new Error('Popup checkout callbackOrigin must use HTTPS (or localhost HTTP)');
    }
    extra.set('origin', ou.origin);
  }
  const cleanMerchant = sanitizeShortLabel(input.merchantName, 40);
  if (cleanMerchant) extra.set('m', cleanMerchant);
  const cleanNote = sanitizeShortLabel(input.note, 60);
  if (cleanNote) extra.set('note', cleanNote);
  const suffix = extra.toString();
  return `${baseOrigin}/#startapp=${payload}${suffix ? `&${suffix}` : ''}`;
}

export function parsePopupCheckoutUrl(raw: string): PopupCheckoutLink | null {
  const base = decodePaymentRequest(raw);
  if (!base) return null;
  const meta = extractPaymentRequestMeta(raw);
  return {
    ...base,
    ...(meta.orderId ? { orderId: meta.orderId } : {}),
    ...(meta.callbackOrigin ? { callbackOrigin: meta.callbackOrigin } : {}),
  };
}

export const encodeTerminalPayload = (input: {
  merchantAddress: string;
  asset?: AnyAssetSymbol;
  feeMode?: 'gross' | 'net';
}): string => {
  const addr = (input.merchantAddress || '').trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(addr) || /^0x0{40}$/i.test(addr)) {
    throw new Error('Invalid merchant address');
  }
  const asset: SupportedLinkAsset = input.asset ? toLinkAsset(input.asset) : 'USDC';
  const parts = ['pos', addr];
  if (asset === 'BTC') parts.push('btc');
  else if (asset === 'ETH') parts.push('eth');
  else if (asset === 'NARA') parts.push('nara');
  if (input.feeMode === 'net') parts.push('net');
  return parts.join('_');
};

export const decodeTerminalPayload = (raw: string): TerminalLinkPayload | null => {
  const payload = extractStartParam(raw);
  if (!/^pos_/i.test(payload)) return null;
  const parts = payload.split('_');
  const addr = parts[1] || '';
  if (!/^0x[0-9a-fA-F]{40}$/.test(addr) || /^0x0{40}$/i.test(addr)) return null;
  const flags = parts.slice(2).map((p) => p.toLowerCase());
  const asset: SupportedLinkAsset = flags.includes('btc')
    ? 'BTC'
    : flags.includes('eth')
      ? 'ETH'
      : flags.includes('nara')
        ? 'NARA'
        : 'USDC';
  const feeMode: 'gross' | 'net' = flags.includes('net') ? 'net' : 'gross';
  const meta = extractPaymentRequestMeta(raw);
  return {
    merchantAddress: addr,
    asset,
    feeMode,
    ...(meta.merchantName ? { merchantName: meta.merchantName } : {}),
  };
};

/**
 * Builds a watch-only POS terminal URL (`https://slip.naraprotocol.io/#startapp=pos_<address>&m=<label>`).
 * Zero private keys on counter/staff devices.
 */
export function buildWatchOnlyPosUrl(input: {
  merchantAddress: string;
  asset?: AnyAssetSymbol;
  feeMode?: 'gross' | 'net';
  merchantName?: string;
  origin?: string;
}): string {
  const payload = encodeTerminalPayload(input);
  const baseOrigin = (input.origin || CANONICAL_SHARE_ORIGIN).replace(/\/$/, '');
  const cleanMerchant = sanitizeShortLabel(input.merchantName, 40);
  return `${baseOrigin}/#startapp=${payload}${cleanMerchant ? `&m=${encodeURIComponent(cleanMerchant)}` : ''}`;
}

export const parseWatchOnlyPosUrl = decodeTerminalPayload;

export const encodeReferralInvite = (referrerAddress: string): string => {
  const clean = (referrerAddress || '').trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(clean) || /^0x0{40}$/i.test(clean)) {
    throw new Error('Invalid referrer address');
  }
  return `ref_${clean.toLowerCase()}`;
};

export const decodeReferralInvite = (raw: string): string | null => {
  const payload = extractStartParam(raw);
  if (!/^ref_/i.test(payload)) return null;
  const addr = payload.slice(4).trim();
  if (!/^0x[0-9a-fA-F]{40}$/i.test(addr) || /^0x0{40}$/i.test(addr)) return null;
  return addr.toLowerCase();
};

// ============================================================================
// 69-Byte Compact Binary QR / Meshtastic LoRa Codec
// Layout: "CSLP" (4B) || flags (1B) || slipId uint64 (8B) || amountAtomic uint192 (24B) || secret (32B) = 69B
// ============================================================================

export const COMPACT_BINARY_SLIP_BYTE_LENGTH = 69 as const;
const COMPACT_MAGIC = new Uint8Array([0x43, 0x53, 0x4c, 0x50]); // "CSLP"

const VAULT_TO_BITS: Record<VaultTag, number> = { v33: 0, v32: 1, v3: 2, v2: 3 };
const BITS_TO_VAULT: readonly VaultTag[] = ['v33', 'v32', 'v3', 'v2'];

const ASSET_TO_BITS: Record<SdkAssetSymbol, number> = { USDC: 0, cbBTC: 1, ETH: 2, NARA: 3 };
const BITS_TO_ASSET: readonly SdkAssetSymbol[] = ['USDC', 'cbBTC', 'ETH', 'NARA'];

export interface CompactBinarySlipData {
  slipId: bigint;
  amountAtomic: bigint;
  asset: SdkAssetSymbol;
  vault: VaultTag;
  mode: SlipLinkMode;
  cancelLockedUntil: bigint;
  hasVoiceNote: boolean;
  claimKey?: Hex;
  codeSalt?: string;
}

export function encodeCompactBinarySlipPayload(input: {
  slipId: bigint | number | string;
  amountAtomic: bigint;
  asset: AnyAssetSymbol;
  vault?: VaultTag;
  mode: SlipLinkMode;
  cancelLockedUntil?: bigint | number;
  hasVoiceNote?: boolean;
  claimKey?: Hex | string;
  codeSalt?: string;
}): Uint8Array {
  const slipId = BigInt(input.slipId);
  if (slipId <= 0n || slipId >= 1n << 64n) {
    throw new RangeError('Compact binary slipId must fit in uint64 (> 0)');
  }
  if (input.amountAtomic <= 0n || input.amountAtomic >= 1n << 192n) {
    throw new RangeError('Compact binary amountAtomic must fit in uint192 (> 0)');
  }
  const vault = input.vault ?? ISSUE_VAULT;
  const sdkAsset = normalizeSdkAsset(input.asset);
  const lock = input.cancelLockedUntil !== undefined ? BigInt(input.cancelLockedUntil) : 0n;
  if (lock !== 0n && lock !== NO_TAKE_BACK_LOCK) {
    throw new Error(`Invalid cancelLockedUntil: expected 0n or ${NO_TAKE_BACK_LOCK}`);
  }
  const noTakeBackBit = isV32ProtocolVault(vault) && lock === NO_TAKE_BACK_LOCK ? 1 : 0;
  const modeBit = input.mode === 'code' ? 1 : 0;
  const voiceBit = input.hasVoiceNote ? 1 : 0;

  const flags =
    ((VAULT_TO_BITS[vault] & 0x03) << 6) |
    ((ASSET_TO_BITS[sdkAsset] & 0x03) << 4) |
    (modeBit << 2) |
    (noTakeBackBit << 1) |
    voiceBit;

  const idBytes = numberToBytes(slipId, { size: 8 });
  const amountBytes = numberToBytes(input.amountAtomic, { size: 24 });
  const secretBytes = new Uint8Array(32);

  if (input.mode === 'open') {
    const cleanKey = (input.claimKey || '').replace(/^0x/i, '');
    if (!/^[0-9a-fA-F]{64}$/.test(cleanKey)) {
      throw new Error('Compact open slip requires a 32-byte claimKey');
    }
    secretBytes.set(hexToBytes(`0x${cleanKey}` as Hex), 0);
  } else {
    const cleanSalt = (input.codeSalt || '').replace(/^0x/i, '').toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(cleanSalt)) {
      throw new Error('Compact code slip requires a 16-byte (32-hex) codeSalt');
    }
    secretBytes.set(hexToBytes(`0x${cleanSalt}` as Hex), 0);
  }

  const out = concatBytes([COMPACT_MAGIC, new Uint8Array([flags]), idBytes, amountBytes, secretBytes]);
  if (out.length !== COMPACT_BINARY_SLIP_BYTE_LENGTH) {
    throw new Error('Internal error: compact binary slip must be 69 bytes');
  }
  return out;
}

export function decodeCompactBinarySlipPayload(bytes: Uint8Array): CompactBinarySlipData {
  if (!(bytes instanceof Uint8Array) || bytes.length !== COMPACT_BINARY_SLIP_BYTE_LENGTH) {
    throw new Error(`Expected ${COMPACT_BINARY_SLIP_BYTE_LENGTH}-byte compact slip payload`);
  }
  for (let i = 0; i < 4; i++) {
    if (bytes[i] !== COMPACT_MAGIC[i]) {
      throw new Error('Invalid compact slip magic header');
    }
  }
  const flags = bytes[4] ?? 0;
  const vault = BITS_TO_VAULT[(flags >> 6) & 0x03] ?? 'v33';
  const asset = BITS_TO_ASSET[(flags >> 4) & 0x03] ?? 'USDC';
  const mode: SlipLinkMode = ((flags >> 2) & 0x01) === 1 ? 'code' : 'open';
  const isLocked = ((flags >> 1) & 0x01) === 1 && isV32ProtocolVault(vault);
  const hasVoiceNote = (flags & 0x01) === 1;

  const slipId = bytesToBigInt(bytes.slice(5, 13));
  const amountAtomic = bytesToBigInt(bytes.slice(13, 37));
  if (slipId <= 0n || amountAtomic <= 0n) {
    throw new Error('Compact slip id and amount must be positive');
  }
  const secretSlice = bytes.slice(37, 69);

  if (mode === 'open') {
    const scalar = bytesToBigInt(secretSlice);
    if (scalar <= 0n || scalar >= SECP256K1_N) {
      throw new Error('Invalid secp256k1 claimKey in compact slip payload');
    }
    return {
      slipId,
      amountAtomic,
      asset,
      vault,
      mode,
      cancelLockedUntil: isLocked ? NO_TAKE_BACK_LOCK : 0n,
      hasVoiceNote,
      claimKey: bytesToHex(secretSlice),
    };
  }

  for (let i = 16; i < 32; i++) {
    if (secretSlice[i] !== 0) {
      throw new Error('Non-zero padding in compact code slip payload');
    }
  }
  return {
    slipId,
    amountAtomic,
    asset,
    vault,
    mode,
    cancelLockedUntil: isLocked ? NO_TAKE_BACK_LOCK : 0n,
    hasVoiceNote,
    codeSalt: bytesToHex(secretSlice.slice(0, 16)).slice(2),
  };
}
