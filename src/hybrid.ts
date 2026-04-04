/**
 * Hybrid custody model for Zcash agents.
 *
 * Two custody paths, one interface:
 *
 * TRANSPARENT (secp256k1 via Ika MPC):
 *   - t-addr transactions signed through 2PC-MPC
 *   - Neither party holds the full key
 *   - Policy enforced by Sui Move contract
 *   - Same key signs BTC and ETH
 *
 * SHIELDED (RedPallas via local Orchard wallet):
 *   - Orchard transactions signed locally (direct key)
 *   - Ika cannot sign RedPallas (Pallas curve not supported)
 *   - Privacy from Zcash protocol, not from MPC
 *   - Every shielded spend attested to ZAP1
 *
 * The gap:
 *   Orchard uses RedPallas on the Pallas curve. Ika supports secp256k1,
 *   Ed25519, secp256r1, and Ristretto. None of these are Pallas.
 *   Until an MPC network adds Pallas curve support, shielded custody
 *   requires holding keys directly.
 *
 * The bridge:
 *   shield()  - move ZEC from t-addr (MPC) to shielded pool (local wallet)
 *   unshield() - move ZEC from shielded back to t-addr (for MPC custody)
 *   Both operations attested on-chain via ZAP1.
 */

import type { ZcashIkaConfig, DWalletHandle, SignRequest, SignResult } from "./index.js";
import { sign } from "./index.js";

export type CustodyMode = "mpc" | "local";

export interface HybridWallet {
  /** MPC-custody transparent wallet (secp256k1 dWallet on Ika) */
  transparent: {
    mode: "mpc";
    walletId: string;
    publicKey: Uint8Array;
    tAddress: string;
    encryptionSeed: string;
  };
  /** Local-custody shielded wallet (Orchard keys held directly) */
  shielded: {
    mode: "local";
    /** Unified address (starts with u1) */
    uAddress: string;
    /** Whether the local wallet is initialized */
    initialized: boolean;
  };
  /** ZAP1 attestation endpoint */
  zap1ApiUrl: string;
}

export interface ShieldRequest {
  /** Amount in zatoshis to move from t-addr to shielded pool */
  amount: number;
  /** Optional memo for the shielding transaction */
  memo?: string;
}

export interface UnshieldRequest {
  /** Amount in zatoshis to move from shielded back to t-addr */
  amount: number;
  /** Optional memo */
  memo?: string;
}

export interface ShieldResult {
  /** Zcash transaction ID */
  txid: string;
  /** Direction */
  direction: "shield" | "unshield";
  /** Amount moved */
  amount: number;
  /** ZAP1 attestation leaf hash */
  leafHash?: string;
}

/**
 * Create a hybrid wallet - MPC for transparent, local for shielded.
 *
 * The transparent side is an Ika dWallet (already created via createWallet).
 * The shielded side connects to the local Zebra/Zashi wallet.
 */
export function createHybridWallet(
  transparentWallet: DWalletHandle,
  shieldedAddress: string,
  zap1ApiUrl: string,
): HybridWallet {
  return {
    transparent: {
      mode: "mpc",
      walletId: transparentWallet.id,
      publicKey: transparentWallet.publicKey,
      tAddress: transparentWallet.address,
      encryptionSeed: transparentWallet.encryptionSeed,
    },
    shielded: {
      mode: "local",
      uAddress: shieldedAddress,
      initialized: shieldedAddress.startsWith("u1"),
    },
    zap1ApiUrl,
  };
}

/**
 * Sign a transparent transaction through MPC.
 * Delegates to the Ika sign() function.
 */
export async function signTransparent(
  config: ZcashIkaConfig,
  wallet: HybridWallet,
  sighash: Uint8Array,
): Promise<SignResult> {
  return sign(config, {
    messageHash: sighash,
    walletId: wallet.transparent.walletId,
    chain: "zcash-transparent",
    encryptionSeed: wallet.transparent.encryptionSeed,
  });
}

/**
 * Shield ZEC - move from MPC-custody t-addr to local shielded pool.
 *
 * Flow:
 * 1. Build transparent tx: t-addr -> shielded address
 * 2. Compute sighash (DoubleSHA256)
 * 3. Sign via Ika MPC (secp256k1)
 * 4. Broadcast via Zebra
 * 5. Attest via ZAP1 as AGENT_ACTION
 *
 * After shielding, the ZEC is in the local Orchard wallet.
 * Private from that point forward.
 */
export async function shield(
  config: ZcashIkaConfig,
  wallet: HybridWallet,
  request: ShieldRequest,
): Promise<ShieldResult> {
  if (!wallet.shielded.initialized) {
    throw new Error("Shielded wallet not initialized. Provide a valid u1 address.");
  }

  if (!config.zebraRpcUrl) {
    throw new Error("shield() requires zebraRpcUrl for building and broadcasting the tx.");
  }

  // The full pipeline:
  // 1. z_listunspent on the t-addr to find UTXOs
  // 2. Build raw tx spending to the shielded address
  // 3. Extract sighash
  // 4. sign() via Ika MPC
  // 5. Attach signature
  // 6. sendrawtransaction
  // 7. Attest to ZAP1

  throw new Error(
    "shield() requires Zcash transparent tx builder (zcash-primitives or librustzcash). " +
      "Use sign() with a pre-built sighash for now. " +
      "The shielding tx is a standard t-addr -> Orchard spend."
  );
}

/**
 * Unshield ZEC - move from local shielded pool back to MPC-custody t-addr.
 *
 * Flow:
 * 1. Build Orchard tx: shielded -> t-addr (signed locally, RedPallas)
 * 2. Broadcast via Zebra
 * 3. Attest via ZAP1 as AGENT_ACTION
 *
 * After unshielding, the ZEC is back under MPC custody.
 * The MPC can then send it to BTC, ETH, or another t-addr.
 */
export async function unshield(
  config: ZcashIkaConfig,
  wallet: HybridWallet,
  request: UnshieldRequest,
): Promise<ShieldResult> {
  if (!config.zebraRpcUrl) {
    throw new Error("unshield() requires zebraRpcUrl.");
  }

  // Unshielding is done entirely locally - no MPC involved.
  // The Orchard wallet holds keys directly and signs with RedPallas.
  // z_sendmany from the shielded address to the t-addr.

  throw new Error(
    "unshield() requires connection to local Zebra wallet with Orchard spending keys. " +
      "Use z_sendmany via Zebra RPC directly for now."
  );
}

/**
 * Attest a custody operation to ZAP1.
 */
export async function attestCustodyOp(
  zap1ApiUrl: string,
  zap1ApiKey: string,
  op: {
    direction: "shield" | "unshield";
    txid: string;
    amount: number;
    walletId: string;
  },
): Promise<string | null> {
  try {
    const resp = await fetch(`${zap1ApiUrl}/attest`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${zap1ApiKey}`,
      },
      body: JSON.stringify({
        event_type: "AGENT_ACTION",
        wallet_hash: op.walletId,
        input_hash: op.txid,
        memo: JSON.stringify({
          action: op.direction,
          amount: op.amount,
          custody: op.direction === "shield" ? "mpc->local" : "local->mpc",
        }),
      }),
    });
    if (!resp.ok) return null;
    const data = (await resp.json()) as { leaf_hash?: string };
    return data.leaf_hash || null;
  } catch {
    return null;
  }
}
