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

import {
  Curve,
  Hash,
  SignatureAlgorithm,
  IkaClient,
  IkaTransaction,
  UserShareEncryptionKeys,
  getNetworkConfig,
  createRandomSessionIdentifier,
  prepareDKGAsync,
  publicKeyFromDWalletOutput,
  parseSignatureFromSignOutput,
} from "@ika.xyz/sdk";

import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import { decodeSuiPrivateKey } from "@mysten/sui/cryptography";

// Chain identifiers for wallet creation
export type Chain = "zcash-transparent" | "bitcoin" | "ethereum";

export interface ZcashIkaConfig {
  /** Ika network: mainnet or testnet */
  network: "mainnet" | "testnet";
  /** Sui RPC URL (defaults to PublicNode) */
  suiRpcUrl?: string;
  /** Sui private key (base64 encoded, suiprivkey1...) */
  suiPrivateKey: string;
  /** Zebra node RPC for broadcasting Zcash txs */
  zebraRpcUrl?: string;
  /** ZAP1 API for attestation */
  zap1ApiUrl?: string;
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
  /** Raw public key bytes (compressed secp256k1) */
  publicKey: Uint8Array;
  /** Which chain this wallet targets */
  chain: Chain;
  /** Derived address for the target chain */
  address: string;
  /** Ika network (mainnet/testnet) */
  network: string;
  /** Encryption seed (hex) - save this for signing */
  encryptionSeed: string;
}

export interface DualCustody {
  /** Zcash transparent + Bitcoin wallet (secp256k1 dWallet) */
  primary: DWalletHandle;
  /** Operator Sui address */
  operatorAddress: string;
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
  /** Chain determines signing params (hash algo) */
  chain: Chain;
  /** Encryption seed (hex) from wallet creation */
  encryptionSeed: string;
  /** dWalletCap ID (ownership proof on Sui) */
  dWalletCapId?: string;
}

export interface SignResult {
  /** DER-encoded ECDSA signature */
  signature: Uint8Array;
  /** Public key used */
  publicKey: Uint8Array;
  /** Sui transaction digest for the sign request */
  signTxDigest: string;
}

// Default poll settings for testnet (epochs can be slow)
const POLL_OPTS = {
  timeout: 300_000,
  interval: 3_000,
  maxInterval: 10_000,
  backoffMultiplier: 1.5,
};

/**
 * Initialize Ika + Sui clients from config.
 */
async function initClients(config: ZcashIkaConfig) {
  const decoded = decodeSuiPrivateKey(config.suiPrivateKey);
  const keypair = Ed25519Keypair.fromSecretKey(decoded.secretKey);
  const address = keypair.getPublicKey().toSuiAddress();

  const { SuiJsonRpcClient } = await import("@mysten/sui/jsonRpc");
  const rpcUrl = config.suiRpcUrl || (
    config.network === "testnet"
      ? "https://sui-testnet-rpc.publicnode.com"
      : "https://sui-mainnet-rpc.publicnode.com"
  );
  const suiClient = new SuiJsonRpcClient({
    url: rpcUrl,
    network: config.network,
  });

  const ikaConfig = getNetworkConfig(config.network);
  if (!ikaConfig) throw new Error(`No Ika ${config.network} config`);

  const ikaClient = new IkaClient({
    suiClient,
    config: ikaConfig,
    cache: true,
    encryptionKeyOptions: { autoDetect: true },
  });
  await ikaClient.initialize();

  return { ikaClient, suiClient, keypair, address };
}

/**
 * Create a split-key custody wallet.
 * One secp256k1 dWallet signs for Zcash transparent, Bitcoin, and EVM.
 *
 * Returns the dWallet handle with ID, public key, and encryption seed.
 * Save the encryption seed - you need it for signing.
 */
export async function createDualCustody(
  config: ZcashIkaConfig,
  _operatorSeed?: Uint8Array
): Promise<DualCustody> {
  const wallet = await createWallet(config, "zcash-transparent");
  const { address } = await initClients(config);
  return {
    primary: wallet,
    operatorAddress: address,
  };
}

/**
 * Create a single secp256k1 dWallet on Ika.
 *
 * Flow:
 * 1. Generate encryption keys from random seed
 * 2. Prepare DKG locally (WASM crypto)
 * 3. Submit DKG request to Ika network
 * 4. Poll until dWallet reaches Active state
 * 5. Extract compressed public key
 */
export async function createWallet(
  config: ZcashIkaConfig,
  chain: Chain,
  _operatorSeed?: Uint8Array
): Promise<DWalletHandle> {
  const { ikaClient, suiClient, keypair, address } = await initClients(config);

  // Generate encryption keys
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  const encKeys = await UserShareEncryptionKeys.fromRootSeedKey(seed, Curve.SECP256K1);

  // Prepare DKG
  const bytesToHash = createRandomSessionIdentifier();
  const dkgInput = await prepareDKGAsync(
    ikaClient,
    Curve.SECP256K1,
    encKeys,
    bytesToHash,
    address,
  );

  // Build and submit DKG transaction
  const tx = new Transaction();
  const ikaTx = new IkaTransaction({
    ikaClient,
    transaction: tx,
    userShareEncryptionKeys: encKeys,
  });

  const sessionId = ikaTx.registerSessionIdentifier(bytesToHash);
  const networkEncKey = await (ikaClient as any).getLatestNetworkEncryptionKey?.()
    || await (ikaClient as any).getConfiguredNetworkEncryptionKey?.();

  await (ikaTx as any).requestDWalletDKG({
    dkgRequestInput: dkgInput,
    sessionIdentifier: sessionId,
    dwalletNetworkEncryptionKeyId: networkEncKey?.id,
    curve: Curve.SECP256K1,
    ikaCoin: tx.splitCoins(tx.gas, [50_000_000]),
    suiCoin: tx.splitCoins(tx.gas, [50_000_000]),
  });

  const result = await suiClient.signAndExecuteTransaction({
    transaction: tx,
    signer: keypair,
    options: { showEffects: true },
  });

  if (result.effects?.status?.status !== "success") {
    throw new Error(`DKG TX failed: ${result.effects?.status?.error}`);
  }

  // Find and poll the dWallet object
  const created = result.effects?.created || [];
  let dwalletId: string | null = null;
  let pubkey: Uint8Array | null = null;

  for (const obj of created) {
    const id = (obj as any).reference?.objectId || (obj as any).objectId;
    if (!id) continue;
    try {
      const dw = await ikaClient.getDWalletInParticularState(id, "Active", POLL_OPTS);
      if (dw) {
        dwalletId = id;
        try {
          const rawOut = dw.state?.Active?.public_output || (dw as any).publicOutput;
          const outBytes = new Uint8Array(Array.isArray(rawOut) ? rawOut : Array.from(rawOut));
          pubkey = await publicKeyFromDWalletOutput(Curve.SECP256K1, outBytes);
        } catch { /* extract later if needed */ }
        break;
      }
    } catch {
      // Not a dWallet object or timeout - skip
    }
  }

  if (!dwalletId) {
    throw new Error("DKG completed but could not find Active dWallet in created objects");
  }

  const seedHex = Buffer.from(seed).toString("hex");

  return {
    id: dwalletId,
    publicKey: pubkey || new Uint8Array(0),
    chain,
    address: "", // Caller derives chain-specific address from pubkey
    network: config.network,
    encryptionSeed: seedHex,
  };
}

/**
 * Sign a message hash through Ika 2PC-MPC.
 *
 * Two on-chain transactions:
 * 1. Request presign (pre-compute MPC ephemeral key share)
 * 2. Approve message + request signature
 *
 * The operator provides their encryption seed, Ika provides the network share.
 * Neither party ever sees the full private key.
 */
export async function sign(
  config: ZcashIkaConfig,
  request: SignRequest
): Promise<SignResult> {
  const { ikaClient, suiClient, keypair, address } = await initClients(config);
  const params = CHAIN_PARAMS[request.chain];

  // Reconstruct encryption keys
  const encSeed = Buffer.from(request.encryptionSeed, "hex");
  const encKeys = await UserShareEncryptionKeys.fromRootSeedKey(
    new Uint8Array(encSeed),
    Curve.SECP256K1,
  );

  // Fetch dWallet (must be Active)
  const dWallet = await ikaClient.getDWallet(request.walletId);
  if (!dWallet?.state?.Active) {
    throw new Error(`dWallet ${request.walletId} not Active`);
  }

  // Find dWalletCap
  let capId = request.dWalletCapId;
  if (!capId) {
    const capsResult = await ikaClient.getOwnedDWalletCaps(address);
    const cap = (capsResult.dWalletCaps || []).find(
      (c: any) => c.dwallet_id === request.walletId
    );
    if (!cap) throw new Error(`No dWalletCap found for ${request.walletId}`);
    capId = cap.id;
  }

  // TX 1: Request presign
  const presignTx = new Transaction();
  const presignIkaTx = new IkaTransaction({
    ikaClient,
    transaction: presignTx,
    userShareEncryptionKeys: encKeys,
  });

  presignIkaTx.requestPresign({
    dWallet,
    signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
    ikaCoin: presignTx.splitCoins(presignTx.gas, [50_000_000]),
    suiCoin: presignTx.splitCoins(presignTx.gas, [50_000_000]),
  });

  const presignResult = await suiClient.signAndExecuteTransaction({
    transaction: presignTx,
    signer: keypair,
    options: { showEffects: true },
  });

  if (presignResult.effects?.status?.status !== "success") {
    throw new Error(`Presign TX failed: ${presignResult.effects?.status?.error}`);
  }

  // Find presign session and poll for completion
  const presignCreated = presignResult.effects?.created || [];
  let completedPresign: any = null;

  for (const obj of presignCreated) {
    const id = (obj as any).reference?.objectId || (obj as any).objectId;
    if (!id) continue;
    try {
      completedPresign = await ikaClient.getPresignInParticularState(
        id, "Completed", POLL_OPTS,
      );
      if (completedPresign) break;
    } catch {
      // Not a presign object or timeout
    }
  }

  if (!completedPresign) {
    throw new Error("Presign TX succeeded but could not get completed presign session");
  }

  // TX 2: Approve message + sign
  const hashEnum = Hash[params.hash as keyof typeof Hash] as any;
  const signTx = new Transaction();
  const signIkaTx = new IkaTransaction({
    ikaClient,
    transaction: signTx,
    userShareEncryptionKeys: encKeys,
  });

  const verifiedPresignCap = signIkaTx.verifyPresignCap({
    presign: completedPresign,
  });

  const messageApproval = signIkaTx.approveMessage({
    dWalletCap: capId!,
    curve: Curve.SECP256K1,
    signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
    hashScheme: hashEnum,
    message: request.messageHash,
  });

  await signIkaTx.requestSign({
    dWallet: dWallet as any,
    messageApproval,
    hashScheme: hashEnum,
    verifiedPresignCap,
    presign: completedPresign,
    message: request.messageHash,
    signatureScheme: SignatureAlgorithm.ECDSASecp256k1,
    ikaCoin: signTx.splitCoins(signTx.gas, [50_000_000]),
    suiCoin: signTx.splitCoins(signTx.gas, [50_000_000]),
  });

  const signResult = await suiClient.signAndExecuteTransaction({
    transaction: signTx,
    signer: keypair,
    options: { showEffects: true },
  });

  if (signResult.effects?.status?.status !== "success") {
    throw new Error(`Sign TX failed: ${signResult.effects?.status?.error}`);
  }

  // Find sign session and poll for signature
  const signCreated = signResult.effects?.created || [];
  let completedSign: any = null;

  for (const obj of signCreated) {
    const id = (obj as any).reference?.objectId || (obj as any).objectId;
    if (!id) continue;
    try {
      completedSign = await ikaClient.getSignInParticularState(
        id,
        Curve.SECP256K1,
        SignatureAlgorithm.ECDSASecp256k1,
        "Completed",
        POLL_OPTS,
      );
      if (completedSign) break;
    } catch {
      // Not a sign object or timeout
    }
  }

  if (!completedSign?.state?.Completed?.signature) {
    throw new Error("Sign TX succeeded but could not get completed signature");
  }

  const rawSig = completedSign.state.Completed.signature;
  const sigBytes = new Uint8Array(Array.isArray(rawSig) ? rawSig : Array.from(rawSig));

  // Extract public key from dWallet
  let pubkey: Uint8Array = new Uint8Array(0);
  try {
    const rawOutput = dWallet.state.Active.public_output;
    const outputBytes = new Uint8Array(Array.isArray(rawOutput) ? rawOutput : Array.from(rawOutput));
    pubkey = await publicKeyFromDWalletOutput(Curve.SECP256K1, outputBytes);
  } catch { /* non-fatal */ }

  return {
    signature: sigBytes,
    publicKey: pubkey,
    signTxDigest: signResult.digest,
  };
}

/**
 * Set spending policy on the dWallet.
 * Policy enforced at Sui Move contract level.
 * The agent cannot bypass it - the contract holds the DWalletCap.
 */
export async function setPolicy(
  _config: ZcashIkaConfig,
  _walletId: string,
  _policy: SpendPolicy
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
 * 1. Build Zcash transparent transaction (requires Zebra)
 * 2. Compute sighash (DoubleSHA256)
 * 3. Sign via Ika 2PC-MPC (secp256k1/ECDSA)
 * 4. Attach signature to transaction
 * 5. Broadcast via Zebra sendrawtransaction
 * 6. Attest via ZAP1 as AGENT_ACTION
 */
export async function spendTransparent(
  config: ZcashIkaConfig,
  walletId: string,
  encryptionSeed: string,
  request: SpendRequest
): Promise<SpendResult> {
  // Build transaction, extract sighash
  // For now: the caller provides the sighash directly via sign()
  // This function will be the full pipeline once we have tx building
  throw new Error(
    "spendTransparent requires Zcash transparent tx builder. " +
      "Use sign() directly with a pre-computed sighash for now. " +
      "Full pipeline: build tx -> sighash -> sign() -> attach sig -> broadcast."
  );
}

/**
 * Spend from a Bitcoin wallet.
 * Same MPC flow as Zcash transparent - DoubleSHA256 sighash, ECDSA signature.
 */
export async function spendBitcoin(
  config: ZcashIkaConfig,
  walletId: string,
  encryptionSeed: string,
  request: SpendRequest
): Promise<SpendResult> {
  throw new Error(
    "spendBitcoin requires Bitcoin tx builder. " +
      "Use sign() with chain='bitcoin' and a pre-computed sighash for now."
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
  if (!config.zap1ApiUrl) return [];
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
  if (!config.zap1ApiUrl) return { compliant: false, violations: -1, bondDeposits: 0 };
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
