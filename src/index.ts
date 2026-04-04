/**
 * @frontiercompute/zcash-ika
 *
 * Split-key custody for Zcash transparent, Bitcoin, and EVM chains.
 *
 * One secp256k1 dWallet signs for all three chain families.
 * Neither key half can sign alone. Policy enforced by Sui Move contract.
 * Every operation attested to Zcash via ZAP1.
 *
 * Built on Ika's 2PC-MPC network (Sui).
 *
 * NOTE: Zcash shielded (Orchard) uses RedPallas on the Pallas curve,
 * which Ika does not currently support. Only transparent ZEC (secp256k1)
 * is viable through this package today.
 */

export {
  Curve,
  Hash,
  SignatureAlgorithm,
  IkaClient,
  IkaTransaction,
  UserShareEncryptionKeys,
  getNetworkConfig,
  createClassGroupsKeypair,
  createRandomSessionIdentifier,
  prepareDKG,
  prepareDKGAsync,
  prepareDKGSecondRound,
  prepareDKGSecondRoundAsync,
  createDKGUserOutput,
  publicKeyFromDWalletOutput,
  parseSignatureFromSignOutput,
} from "@ika.xyz/sdk";

// Chain identifiers for wallet creation
// NOTE: "zcash-shielded" is aspirational. Orchard requires RedPallas (Pallas curve),
// not Ed25519. The Ed25519 dWallet exists on Ika but cannot sign Orchard transactions.
// Only "zcash-transparent" and "bitcoin" work today via secp256k1.
export type Chain = "zcash-transparent" | "bitcoin" | "ethereum";

export interface ZcashIkaConfig {
  /** Ika network: mainnet or testnet */
  network: "mainnet" | "testnet";
  /** Sui RPC URL (defaults to Ika's network config) */
  suiRpcUrl?: string;
  /** Zebra node RPC for broadcasting Zcash txs */
  zebraRpcUrl: string;
  /** ZAP1 API for attestation */
  zap1ApiUrl: string;
  /** ZAP1 API key for write operations */
  zap1ApiKey?: string;
}

/** Parameters for dWallet creation per chain.
 *
 * All chains use secp256k1 - one dWallet signs for all of them.
 * Zcash shielded (Orchard) requires RedPallas on the Pallas curve,
 * which is not available in Ika's current MPC. Transparent ZEC works. */
export const CHAIN_PARAMS = {
  "zcash-transparent": {
    curve: "SECP256K1" as const,
    algorithm: "ECDSASecp256k1" as const,
    hash: "DoubleSHA256" as const,
    description: "Zcash transparent t-address (secp256k1/ECDSA)",
  },
  bitcoin: {
    curve: "SECP256K1" as const,
    algorithm: "ECDSASecp256k1" as const,
    hash: "DoubleSHA256" as const,
    description: "Bitcoin (secp256k1/ECDSA, DoubleSHA256)",
  },
  ethereum: {
    curve: "SECP256K1" as const,
    algorithm: "ECDSASecp256k1" as const,
    hash: "KECCAK256" as const,
    description: "Ethereum/EVM (secp256k1/ECDSA, KECCAK256)",
  },
} as const;

export interface DWalletHandle {
  /** dWallet object ID on Sui */
  id: string;
  /** Raw public key bytes */
  publicKey: Uint8Array;
  /** Which chain this wallet targets */
  chain: Chain;
  /** Derived address for the target chain */
  address: string;
  /** Ika network (mainnet/testnet) */
  network: string;
}

export interface DualCustody {
  /** Zcash transparent + Bitcoin wallet (secp256k1 dWallet) */
  primary: DWalletHandle;
  /** Operator ID */
  operatorId: string;
}

export interface SpendPolicy {
  /** Max zatoshis (or satoshis) per single transaction */
  maxPerTx: number;
  /** Max per 24h window */
  maxDaily: number;
  /** Allowed recipient addresses (empty = any) */
  allowedRecipients: string[];
  /** Require operator approval above this amount */
  approvalThreshold: number;
}

export interface SpendRequest {
  /** Recipient address (t-addr, BTC address, or ETH address) */
  to: string;
  /** Amount in smallest unit (zatoshis or satoshis) */
  amount: number;
  /** Memo (ZAP1 structured or plain text, Zcash only) */
  memo?: string;
}

export interface SpendResult {
  /** Transaction ID on target chain */
  txid: string;
  /** ZAP1 attestation leaf hash */
  leafHash: string;
  /** Chain the spend was on */
  chain: Chain;
  /** Whether policy was checked */
  policyChecked: boolean;
}

export interface SignRequest {
  /** Raw message hash to sign (sighash) */
  messageHash: Uint8Array;
  /** Which dWallet to sign with */
  walletId: string;
  /** Chain determines signing params */
  chain: Chain;
}

export interface SignResult {
  /** DER-encoded ECDSA signature */
  signature: Uint8Array;
  /** Public key used */
  publicKey: Uint8Array;
}

/**
 * Create a split-key custody wallet.
 * One secp256k1 dWallet signs for Zcash transparent, Bitcoin, and EVM.
 *
 * Flow:
 * 1. Generate UserShareEncryptionKeys from operator seed
 * 2. Run DKG on Ika (2PC-MPC key generation, secp256k1)
 * 3. Extract public key, derive t-addr + BTC address + ETH address
 * 4. Attest wallet creation via ZAP1
 */
export async function createDualCustody(
  config: ZcashIkaConfig,
  operatorSeed: Uint8Array
): Promise<DualCustody> {
  throw new Error(
    "createDualCustody requires Ika network access. " +
      "secp256k1/ECDSA/DoubleSHA256 dWallet -> ZEC t-addr + BTC + ETH. " +
      "npm install @ika.xyz/sdk @mysten/sui && configure Sui wallet. " +
      "See https://docs.ika.xyz for DKG walkthrough."
  );
}

/**
 * Create a single dWallet for a specific chain.
 */
export async function createWallet(
  config: ZcashIkaConfig,
  chain: Chain,
  operatorSeed: Uint8Array
): Promise<DWalletHandle> {
  const params = CHAIN_PARAMS[chain];

  // The DKG flow:
  // 1. IkaClient.init({ network: config.network })
  // 2. UserShareEncryptionKeys from operatorSeed
  // 3. prepareDKG(curve, signatureAlgorithm, hash)
  // 4. Submit DKG round 1 to Ika via IkaTransaction
  // 5. prepareDKGSecondRound with network output
  // 6. Submit round 2 -> get dWallet object ID + public key
  // 7. Derive chain address from public key

  throw new Error(
    `createWallet(${chain}) requires Ika ${config.network} access. ` +
      `Params: ${params.curve}/${params.algorithm}/${params.hash}. ` +
      `${params.description}.`
  );
}

/**
 * Sign a message hash through Ika 2PC-MPC.
 *
 * The operator provides their seed, Ika provides the network share.
 * Neither party ever sees the full private key.
 *
 * Flow:
 * 1. Create presign session on Ika
 * 2. Compute partial user signature locally
 * 3. Submit to Ika coordinator
 * 4. Poll for completion
 * 5. Extract full signature from sign output
 */
export async function sign(
  config: ZcashIkaConfig,
  operatorSeed: Uint8Array,
  request: SignRequest
): Promise<SignResult> {
  const params = CHAIN_PARAMS[request.chain];

  // The sign flow:
  // 1. IkaClient.init({ network: config.network })
  // 2. RequestGlobalPresign for the dWallet
  // 3. createUserSignMessageWithCentralizedOutput(messageHash, userShare, ...)
  // 4. ApproveMessage on Sui (this is where Move policy gates)
  // 5. RequestSign -> poll SessionsManager for Completed status
  // 6. parseSignatureFromSignOutput(signOutput)

  throw new Error(
    `sign requires active dWallet + Ika ${config.network}. ` +
      `Chain: ${request.chain}, params: ${params.curve}/${params.algorithm}/${params.hash}.`
  );
}

/**
 * Set spending policy on the dWallet.
 * Policy enforced at Sui Move contract level.
 * The agent cannot bypass it - the contract holds the DWalletCap.
 */
export async function setPolicy(
  config: ZcashIkaConfig,
  walletId: string,
  policy: SpendPolicy
): Promise<string> {
  throw new Error(
    "setPolicy requires a deployed Move module on Sui. " +
      "The module gates approve_message() with spending constraints. " +
      "See docs/move-policy-template.move for the template."
  );
}

/**
 * Spend from a Zcash transparent wallet.
 *
 * 1. Build Zcash transparent transaction
 * 2. Compute sighash (DoubleSHA256)
 * 3. Sign via Ika 2PC-MPC (secp256k1/ECDSA)
 * 4. Attach signature to transaction
 * 5. Broadcast via Zebra sendrawtransaction
 * 6. Attest via ZAP1 as AGENT_ACTION
 *
 * NOTE: Zcash shielded (Orchard) requires RedPallas on the Pallas curve.
 * Ika does not support Pallas. Only transparent ZEC works through this path.
 */
export async function spendTransparent(
  config: ZcashIkaConfig,
  walletId: string,
  operatorSeed: Uint8Array,
  request: SpendRequest
): Promise<SpendResult> {
  throw new Error(
    "spendTransparent requires active secp256k1 dWallet + Zebra node. " +
      "secp256k1 dWallet created on Ika testnet. Signing pipeline in progress."
  );
}

/**
 * Spend from a Bitcoin wallet.
 *
 * 1. Build Bitcoin transaction
 * 2. Compute sighash (DoubleSHA256)
 * 3. Sign via Ika 2PC-MPC (secp256k1/ECDSA)
 * 4. Attach signature
 * 5. Broadcast to Bitcoin network
 * 6. Attest via ZAP1 as AGENT_ACTION
 */
export async function spendBitcoin(
  config: ZcashIkaConfig,
  walletId: string,
  operatorSeed: Uint8Array,
  request: SpendRequest
): Promise<SpendResult> {
  throw new Error(
    "spendBitcoin requires active secp256k1 dWallet + Bitcoin node. " +
      "Same MPC flow as Zcash transparent - DoubleSHA256 sighash, ECDSA signature."
  );
}

/**
 * Verify the wallet's attestation history via ZAP1.
 * Works today against the live API.
 */
export async function getHistory(
  config: ZcashIkaConfig,
  walletId: string
): Promise<{ leafHash: string; eventType: string; timestamp: string }[]> {
  const resp = await fetch(`${config.zap1ApiUrl}/lifecycle/${walletId}`);
  if (!resp.ok) return [];
  const data = (await resp.json()) as {
    leaves?: { leaf_hash: string; event_type: string; created_at: string }[];
  };
  return (data.leaves || []).map((l) => ({
    leafHash: l.leaf_hash,
    eventType: l.event_type,
    timestamp: l.created_at,
  }));
}

/**
 * Check wallet's policy compliance status via ZAP1.
 * Works today against the live API.
 */
export async function checkCompliance(
  config: ZcashIkaConfig,
  walletId: string
): Promise<{
  compliant: boolean;
  violations: number;
  bondDeposits: number;
}> {
  const resp = await fetch(
    `${config.zap1ApiUrl}/agent/${walletId}/policy/verify`
  );
  if (!resp.ok) return { compliant: false, violations: -1, bondDeposits: 0 };
  const data = (await resp.json()) as {
    compliant: boolean;
    violations: number;
    bond_deposits?: number;
  };
  return {
    compliant: data.compliant,
    violations: data.violations,
    bondDeposits: data.bond_deposits || 0,
  };
}
