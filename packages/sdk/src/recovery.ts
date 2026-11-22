import {
  decodeFunctionResult,
  encodeFunctionData,
  getAddress,
  type Address,
  type Hex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { CRYPTO_SLIP_VAULT_V32_ABI } from './abi.js';

const MULTICALL3_AGGREGATE3_VIEW_ABI = [
  {
    type: 'function',
    name: 'aggregate3',
    stateMutability: 'view',
    inputs: [
      {
        name: 'calls',
        type: 'tuple[]',
        components: [
          { name: 'target', type: 'address' },
          { name: 'allowFailure', type: 'bool' },
          { name: 'callData', type: 'bytes' },
        ],
      },
    ],
    outputs: [
      {
        name: 'returnData',
        type: 'tuple[]',
        components: [
          { name: 'success', type: 'bool' },
          { name: 'returnData', type: 'bytes' },
        ],
      },
    ],
  },
] as const;
import {
  ISSUE_VAULT,
  isV32ProtocolVault,
  MULTICALL3_ADDRESS,
  resolveAssetMetadata,
  SlipStatus,
  vaultAddress,
  ZERO_ADDRESS,
  type SdkAssetSymbol,
  type SlipStatusCode,
  type VaultTag,
} from './constants.js';
import type { BaseCompatiblePublicClient } from './paymaster.js';
import {
  deriveKeptSlipHopKey,
  deriveKeptSlipKey,
  deriveSplitChangeSlipKey,
  MAX_KEPT_SLIP_HOPS,
} from './permits.js';

const MULTICALL_BATCH_SIZE = 200;
const MULTICALL_WAVE_CONCURRENCY = 4;
const DEFAULT_MAX_LOOKBACK_SLIPS = 25_000;
const DEFAULT_UNANCHORED_RING_WINDOW = 10_000;

export interface RawVaultSlipSummary {
  readonly slipId: bigint;
  readonly asset: SdkAssetSymbol;
  readonly assetAddress: Address;
  readonly amount: bigint;
  readonly createdAt: number;
  readonly cancelLockedUntil: bigint;
  readonly creator: Address;
  readonly claimSigner: Address;
  readonly status: SlipStatusCode;
}

export interface RecoveredPocketSlipMatch {
  readonly slipId: string;
  readonly vault: VaultTag;
  readonly asset: SdkAssetSymbol;
  readonly amountUnits: bigint;
  readonly claimPrivateKey: Hex;
  readonly claimSigner: Address;
  readonly kind: 'kept' | 'split_change';
  readonly sourceParentId: string;
  readonly hop?: number;
}

function normalizePk(pk: Hex | string): Hex {
  const clean = pk.trim().replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]{64}$/.test(clean)) {
    throw new Error('recoveryMasterKey must be a 32-byte hex private key.');
  }
  return `0x${clean}` as Hex;
}

function tryResolveKnownAsset(rawAssetAddr: Address): SdkAssetSymbol | null {
  try {
    return resolveAssetMetadata(rawAssetAddr).symbol;
  } catch {
    return null;
  }
}

async function readVaultTotalSlips(
  publicClient: BaseCompatiblePublicClient,
  vAddr: Address,
): Promise<bigint> {
  const total = await publicClient.readContract({
    address: vAddr,
    abi: CRYPTO_SLIP_VAULT_V32_ABI,
    functionName: 'totalSlips',
  });
  return typeof total === 'bigint' ? total : BigInt(total as number | string);
}

async function fetchSlipBatch(params: {
  publicClient: BaseCompatiblePublicClient;
  vAddr: Address;
  ids: readonly bigint[];
}): Promise<RawVaultSlipSummary[]> {
  const { publicClient, vAddr, ids } = params;
  if (ids.length === 0) return [];

  try {
    const calls = ids.map((id) => ({
      target: vAddr,
      allowFailure: true,
      callData: encodeFunctionData({
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        functionName: 'slips',
        args: [id],
      }),
    }));

    const results = await publicClient.readContract({
      address: MULTICALL3_ADDRESS,
      abi: MULTICALL3_AGGREGATE3_VIEW_ABI,
      functionName: 'aggregate3',
      args: [calls],
    });

    const decodedRows: RawVaultSlipSummary[] = [];
    for (let i = 0; i < ids.length; i++) {
      const id = ids[i];
      const entry = results[i];
      if (id === undefined || !entry?.success || !entry.returnData || entry.returnData === '0x') continue;
      const tuple = decodeFunctionResult({
        abi: CRYPTO_SLIP_VAULT_V32_ABI,
        functionName: 'slips',
        data: entry.returnData,
      });
      const status = Number(tuple[6]) as SlipStatusCode;
      if (status === SlipStatus.NONE) continue;
      const rawAssetAddr = getAddress(tuple[0]);
      const symbol = tryResolveKnownAsset(rawAssetAddr);
      if (!symbol) continue;
      decodedRows.push({
        slipId: id,
        asset: symbol,
        assetAddress: rawAssetAddr,
        amount: tuple[1],
        createdAt: Number(tuple[2]),
        cancelLockedUntil: BigInt(tuple[3]),
        creator: getAddress(tuple[4]),
        claimSigner: getAddress(tuple[5]),
        status,
      });
    }
    return decodedRows;
  } catch {
    // Fallback to direct `slips(id)` reads (e.g. lightweight unit-test mocks without Multicall3)
    const rows = await Promise.all(
      ids.map(async (id): Promise<RawVaultSlipSummary | null> => {
        try {
          const tuple = await publicClient.readContract({
            address: vAddr,
            abi: CRYPTO_SLIP_VAULT_V32_ABI,
            functionName: 'slips',
            args: [id],
          });
          const status = Number(tuple[6]) as SlipStatusCode;
          if (status === SlipStatus.NONE) return null;
          const rawAssetAddr = getAddress(tuple[0]);
          const symbol = tryResolveKnownAsset(rawAssetAddr);
          if (!symbol) return null;
          return {
            slipId: id,
            asset: symbol,
            assetAddress: rawAssetAddr,
            amount: tuple[1],
            createdAt: Number(tuple[2]),
            cancelLockedUntil: BigInt(tuple[3]),
            creator: getAddress(tuple[4]),
            claimSigner: getAddress(tuple[5]),
            status,
          };
        } catch {
          return null;
        }
      }),
    );
    return rows.filter((r): r is RawVaultSlipSummary => r !== null);
  }
}

/**
 * Locates an active slip on `vault` controlled by `targetClaimSigner`, scanning from
 * `startSlipId` up to `maxSlipId` (defaults to `totalSlips()`) in `Multicall3` batches.
 * Used by `PocketSlip` write-ahead crash recovery when a `splitAndPay` transaction mined
 * before the caller persisted the emitted `changeSlipId`.
 */
export async function findActiveSlipByClaimSigner(params: {
  publicClient: BaseCompatiblePublicClient;
  targetClaimSigner: Address;
  vault?: VaultTag;
  startSlipId?: bigint | number | string;
  maxSlipId?: bigint | number | string;
}): Promise<RawVaultSlipSummary | null> {
  const { publicClient, vault = ISSUE_VAULT } = params;
  const targetLower = params.targetClaimSigner.toLowerCase();
  if (!targetLower || targetLower === ZERO_ADDRESS) return null;

  const vAddr = vaultAddress(vault);
  const ceiling =
    params.maxSlipId !== undefined
      ? BigInt(params.maxSlipId)
      : await readVaultTotalSlips(publicClient, vAddr);
  const floor = params.startSlipId !== undefined ? BigInt(params.startSlipId) : 1n;
  if (ceiling < floor || ceiling <= 0n) return null;

  for (let end = ceiling; end >= floor; end -= BigInt(MULTICALL_BATCH_SIZE)) {
    const start =
      end - BigInt(MULTICALL_BATCH_SIZE) + 1n > floor
        ? end - BigInt(MULTICALL_BATCH_SIZE) + 1n
        : floor;
    const ids: bigint[] = [];
    for (let id = end; id >= start; id--) {
      ids.push(id);
    }
    const batch = await fetchSlipBatch({ publicClient, vAddr, ids });
    for (const row of batch) {
      if (
        row.status === SlipStatus.ACTIVE &&
        row.amount > 0n &&
        row.claimSigner.toLowerCase() === targetLower
      ) {
        return row;
      }
    }
  }

  return null;
}

/**
 * Deterministically scans Base Mainnet `vault` via `Multicall3` and recovers all active
 * kept slips (`hop 0..4`) and `splitAndPay` change slips (`split_change`) derived from
 * `recoveryMasterKey` (e.g. `CRYPTOSLIP_OPERATOR_KEY`), even when local disk state was wiped.
 *
 * If `lineageRootSlipId` is provided, walks forward along the exact split lineage starting
 * from `lineageRootSlipId` first in O(chain_depth) before falling back to a full vault scan.
 */
export async function scanPocketSlipsFromChain(params: {
  publicClient: BaseCompatiblePublicClient;
  recoveryMasterKey: Hex | string;
  vault?: VaultTag;
  lineageRootSlipId?: bigint | number | string;
  minSlipId?: bigint | number | string;
  maxSlipId?: bigint | number | string;
  /** Maximum slips scanned backwards when `minSlipId` and `lineageRootSlipId` are omitted (default `25,000`). */
  maxLookbackSlips?: number;
  /** Return immediately once the newest active deterministic slip is found (1 RPC wave ~120ms for PocketSlip). */
  stopOnFirstMatch?: boolean;
}): Promise<RecoveredPocketSlipMatch[]> {
  const { publicClient, vault = ISSUE_VAULT, stopOnFirstMatch = false } = params;
  const masterPk = normalizePk(params.recoveryMasterKey);
  const vAddr = vaultAddress(vault);
  const total =
    params.maxSlipId !== undefined
      ? BigInt(params.maxSlipId)
      : await readVaultTotalSlips(publicClient, vAddr);
  if (total <= 0n) return [];

  const lookback = BigInt(Math.max(200, params.maxLookbackSlips ?? DEFAULT_MAX_LOOKBACK_SLIPS));
  const defaultBoundedFloor = total > lookback ? total - lookback + 1n : 1n;
  const floor =
    params.minSlipId !== undefined
      ? BigInt(params.minSlipId)
      : params.lineageRootSlipId !== undefined
        ? BigInt(params.lineageRootSlipId)
        : defaultBoundedFloor;
  const startFloor = floor > 1n ? floor : 1n;
  if (total < startFloor) return [];

  const isLegacyVault = !isV32ProtocolVault(vault);
  const addrCache = new Map<Hex, Address>();
  const addrOf = (pk: Hex): Address => {
    const hit = addrCache.get(pk);
    if (hit) return hit;
    const computed = getAddress(privateKeyToAccount(pk).address);
    addrCache.set(pk, computed);
    return computed;
  };

  const childRing = new Map<
    string,
    { pk: Hex; addr: Address; kind: 'kept' | 'split_change'; parentId: string }
  >();
  let ringMin = 0;
  let ringMax = 0;

  const matchRow = (row: RawVaultSlipSummary): RecoveredPocketSlipMatch | null => {
    const idStr = row.slipId.toString();
    const signerLower = row.claimSigner.toLowerCase();

    // 1. Check in-place hops (0..4) on `row.slipId` — O(1)
    for (let hop = 0; hop < MAX_KEPT_SLIP_HOPS; hop++) {
      const pk = deriveKeptSlipHopKey(masterPk, vault, idStr, hop);
      const addr = addrOf(pk);
      if (addr.toLowerCase() === signerLower) {
        return {
          slipId: idStr,
          vault,
          asset: row.asset,
          amountUnits: row.amount,
          claimPrivateKey: pk,
          claimSigner: addr,
          kind: 'kept',
          sourceParentId: idStr,
          hop,
        };
      }
    }

    // 2. Check in-place fallback split key on `row.slipId` — O(1)
    const splitPk = deriveSplitChangeSlipKey(masterPk, vault, idStr);
    const splitAddr = addrOf(splitPk);
    if (splitAddr.toLowerCase() === signerLower) {
      return {
        slipId: idStr,
        vault,
        asset: row.asset,
        amountUnits: row.amount,
        claimPrivateKey: splitPk,
        claimSigner: splitAddr,
        kind: 'split_change',
        sourceParentId: idStr,
      };
    }

    // 3. Check cross-ID child slips (`changeSlipId > parentSlipId`)
    // Bounded to `DEFAULT_UNANCHORED_RING_WINDOW` (10,000 EC ops < 80ms CPU) per pass so Node's
    // event loop never stalls even on 100k+ slip vaults.
    if (row.slipId > 1n && row.slipId <= BigInt(Number.MAX_SAFE_INTEGER)) {
      const neededMaxParent = Number(row.slipId - 1n);
      const minFloorParent =
        params.lineageRootSlipId !== undefined ? Math.max(1, Number(BigInt(params.lineageRootSlipId))) : 1;
      const minParent = Math.max(minFloorParent, neededMaxParent - DEFAULT_UNANCHORED_RING_WINDOW + 1);

      if (ringMin === 0 || neededMaxParent > ringMax || minParent < ringMin) {
        // Bound synchronous derivations per expansion to DEFAULT_UNANCHORED_RING_WINDOW
        const boundedStart =
          ringMin > 0 && neededMaxParent > ringMax
            ? Math.max(minParent, ringMax + 1)
            : minParent;
        const boundedEnd =
          ringMin > 0 && minParent < ringMin && neededMaxParent <= ringMax
            ? ringMin - 1
            : neededMaxParent;
        for (let p = boundedStart; p <= boundedEnd; p++) {
          const pStr = String(p);
          if (isLegacyVault) {
            const k0 = deriveKeptSlipKey(masterPk, vault, pStr);
            const a0 = addrOf(k0);
            childRing.set(a0.toLowerCase(), { pk: k0, addr: a0, kind: 'kept', parentId: pStr });
          }
          const ks = deriveSplitChangeSlipKey(masterPk, vault, pStr);
          const as = addrOf(ks);
          childRing.set(as.toLowerCase(), {
            pk: ks,
            addr: as,
            kind: 'split_change',
            parentId: pStr,
          });
        }
        ringMin = ringMin > 0 ? Math.min(ringMin, boundedStart) : boundedStart;
        ringMax = Math.max(ringMax, boundedEnd);
      }

      const hit = childRing.get(signerLower);
      if (hit) {
        return {
          slipId: idStr,
          vault,
          asset: row.asset,
          amountUnits: row.amount,
          claimPrivateKey: hit.pk,
          claimSigner: hit.addr,
          kind: hit.kind,
          sourceParentId: hit.parentId,
        };
      }
    }

    return null;
  };

  // Build newest-first batch ranges and execute in waves of `MULTICALL_WAVE_CONCURRENCY`
  const batches: bigint[][] = [];
  for (let end = total; end >= startFloor; end -= BigInt(MULTICALL_BATCH_SIZE)) {
    const start =
      end - BigInt(MULTICALL_BATCH_SIZE) + 1n > startFloor
        ? end - BigInt(MULTICALL_BATCH_SIZE) + 1n
        : startFloor;
    const ids: bigint[] = [];
    for (let id = end; id >= start; id--) {
      ids.push(id);
    }
    batches.push(ids);
  }

  const matches: RecoveredPocketSlipMatch[] = [];
  const unmatchedRows: RawVaultSlipSummary[] = [];

  for (let w = 0; w < batches.length; w += MULTICALL_WAVE_CONCURRENCY) {
    const wave = batches.slice(w, w + MULTICALL_WAVE_CONCURRENCY);
    const waveResults = await Promise.all(
      wave.map((ids) => fetchSlipBatch({ publicClient, vAddr, ids })),
    );
    const ringMinBeforeWave = ringMin;
    for (const batch of waveResults) {
      for (const row of batch) {
        if (row.status !== SlipStatus.ACTIVE || row.amount <= 0n) continue;
        const matched = matchRow(row);
        if (matched) {
          matches.push(matched);
          if (stopOnFirstMatch) {
            return matches;
          }
        } else {
          unmatchedRows.push(row);
        }
      }
    }
    // If childRing expanded downward to older parents during this wave, re-check earlier high-ID unmatched rows
    if (ringMinBeforeWave > 0 && ringMin < ringMinBeforeWave && unmatchedRows.length > 0) {
      for (let i = unmatchedRows.length - 1; i >= 0; i--) {
        const prevRow = unmatchedRows[i];
        if (!prevRow) continue;
        const hit = childRing.get(prevRow.claimSigner.toLowerCase());
        if (hit) {
          unmatchedRows.splice(i, 1);
          matches.push({
            slipId: prevRow.slipId.toString(),
            vault,
            asset: prevRow.asset,
            amountUnits: prevRow.amount,
            claimPrivateKey: hit.pk,
            claimSigner: hit.addr,
            kind: hit.kind,
            sourceParentId: hit.parentId,
          });
          if (stopOnFirstMatch) {
            matches.sort((a, b) => (BigInt(b.slipId) > BigInt(a.slipId) ? 1 : -1));
            return [matches[0]!];
          }
        }
      }
    }
  }

  // If lineageRootSlipId was set across a >10k gap and still unmatched, check lineageRootSlipId..ringMin-1 bounded
  if (
    matches.length === 0 &&
    unmatchedRows.length > 0 &&
    params.lineageRootSlipId !== undefined
  ) {
    const rootNum = Math.max(1, Number(BigInt(params.lineageRootSlipId)));
    if (ringMin === 0 || rootNum < ringMin) {
      const extraEnd = Math.min(
        ringMin > 0 ? ringMin - 1 : Number(total),
        rootNum + DEFAULT_UNANCHORED_RING_WINDOW - 1,
      );
      for (let p = rootNum; p <= extraEnd; p++) {
        const pStr = String(p);
        const ks = deriveSplitChangeSlipKey(masterPk, vault, pStr);
        const as = addrOf(ks);
        childRing.set(as.toLowerCase(), { pk: ks, addr: as, kind: 'split_change', parentId: pStr });
      }
      for (const prevRow of unmatchedRows) {
        const hit = childRing.get(prevRow.claimSigner.toLowerCase());
        if (hit) {
          matches.push({
            slipId: prevRow.slipId.toString(),
            vault,
            asset: prevRow.asset,
            amountUnits: prevRow.amount,
            claimPrivateKey: hit.pk,
            claimSigner: hit.addr,
            kind: hit.kind,
            sourceParentId: hit.parentId,
          });
          if (stopOnFirstMatch) return matches;
        }
      }
    }
  }

  return matches;
}
