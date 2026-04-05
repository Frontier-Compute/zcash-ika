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
import { createHash } from "node:crypto";

import {
  fetchUTXOs,
  selectUTXOs,
  buildUnsignedTx,
  attachSignatures,
  broadcastTx,
  estimateFee,
  BRANCH_ID,
} from "./tx-builder.js";

export {
  fetchUTXOs,
  selectUTXOs,
  buildUnsignedTx,
  attachSignatures,
  broadcastTx,
  estimateFee,
  BRANCH_ID,
} from "./tx-builder.js";
export type { UTXO } from "./tx-builder.js";

import {
  fetchBtcUTXOs,
  selectBtcUTXOs,
  buildUnsignedBtcTx,
  attachBtcSignatures,
  serializeBtcTx,
  broadcastBtcTx,
  estimateBtcFee,
  computeBtcSighash,
} from "./btc-tx-builder.js";

export {
  fetchBtcUTXOs,
  selectBtcUTXOs,
  buildUnsignedBtcTx,
  attachBtcSignatures,
  serializeBtcTx,
  broadcastBtcTx,
  estimateBtcFee,
  computeBtcSighash,
} from "./btc-tx-builder.js";
export type { BtcUTXO, BtcTxOutput, BtcNetwork } from "./btc-tx-builder.js";

// Chain identifiers for wallet creation
export type Chain = "zcash-transparent" | "bitcoin" | "ethereum";

export interface ZcashIkaConfig {
  /** Ika network: mainnet or testnet */
  network: "mainnet" | "testnet";
  /** Sui RPC URL (defaults to PublicNode) */
  suiRpcUrl?: string;
  /** Sui private key (base64 encoded, suiprivkey1...) */
  suiPrivateKey: string;
  /** IKA coin object ID (required for Ika transactions, separate from SUI gas) */
  ikaCoinId?: string;
  /** Zebra node RPC for broadcasting Zcash txs */
  zebraRpcUrl?: string;
  /** ZAP1 API for attestation */
  zap1ApiUrl?: string;
  /** ZAP1 API key for write operations */
  zap1ApiKey?: string;
}

const IKA_COIN_TYPE = "0x1f26bb2f711ff82dcda4d02c77d5123089cb7f8418751474b9fb744ce031526a::ika::IKA";

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

// Zcash t-address version bytes (2 bytes each)
const ZCASH_VERSION_BYTES = {
  mainnet: Uint8Array.from([0x1c, 0xb8]), // t1...
  testnet: Uint8Array.from([0x1d, 0x25]), // tm...
} as const;

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Encode(data: Uint8Array): string {
  // Count leading zeros
  let leadingZeros = 0;
  for (const b of data) {
    if (b !== 0) break;
    leadingZeros++;
  }
  // Convert to bigint for division
  let num = BigInt(0);
  for (const b of data) {
    num = num * 256n + BigInt(b);
  }
  const chars: string[] = [];
  while (num > 0n) {
    const rem = Number(num % 58n);
    num = num / 58n;
    chars.push(BASE58_ALPHABET[rem]);
  }
  // Prepend '1' for each leading zero byte
  for (let i = 0; i < leadingZeros; i++) {
    chars.push("1");
  }
  return chars.reverse().join("");
}

function sha256(data: Uint8Array): Buffer {
  return createHash("sha256").update(data).digest();
}

function hash160(data: Uint8Array): Buffer {
  return createHash("ripemd160").update(sha256(data)).digest();
}

/**
 * Derive a Zcash transparent address from a compressed secp256k1 public key.
 *
 * Same as Bitcoin P2PKH but with Zcash 2-byte version prefix:
 *   mainnet 0x1cb8 (t1...), testnet 0x1d25 (tm...)
 *
 * Steps:
 *   1. SHA256(pubkey) then RIPEMD160 = 20-byte hash
 *   2. Prepend 2-byte version
 *   3. Double-SHA256 checksum (first 4 bytes)
 *   4. Base58 encode (version + hash + checksum)
 */
export function deriveZcashAddress(
  publicKey: Uint8Array,
  network: "mainnet" | "testnet" = "mainnet"
): string {
  if (publicKey.length !== 33) {
    throw new Error(
      `Expected 33-byte compressed secp256k1 pubkey, got ${publicKey.length} bytes`
    );
  }
  const prefix = publicKey[0];
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new Error(
      `Invalid compressed pubkey prefix 0x${prefix.toString(16)}, expected 0x02 or 0x03`
    );
  }

  const pubkeyHash = hash160(publicKey); // 20 bytes
  const version = ZCASH_VERSION_BYTES[network];

  // version (2) + hash160 (20) = 22 bytes
  const payload = new Uint8Array(22);
  payload.set(version, 0);
  payload.set(pubkeyHash, 2);

  // checksum: first 4 bytes of SHA256(SHA256(payload))
  const checksum = sha256(sha256(payload)).subarray(0, 4);

  // final: payload (22) + checksum (4) = 26 bytes
  const full = new Uint8Array(26);
  full.set(payload, 0);
  full.set(checksum, 22);

  return base58Encode(full);
}

// Bitcoin P2PKH version bytes (1 byte each)
const BITCOIN_VERSION_BYTE = {
  mainnet: 0x00, // 1...
  testnet: 0x6f, // m... or n...
} as const;

/**
 * Derive a Bitcoin P2PKH address from a compressed secp256k1 public key.
 *
 * Same as Zcash transparent but with a 1-byte version prefix:
 *   mainnet 0x00 (1...), testnet 0x6f (m.../n...)
 *
 * Steps:
 *   1. SHA256(pubkey) then RIPEMD160 = 20-byte hash
 *   2. Prepend 1-byte version
 *   3. Double-SHA256 checksum (first 4 bytes)
 *   4. Base58 encode (version + hash + checksum)
 */
export function deriveBitcoinAddress(
  publicKey: Uint8Array,
  network: "mainnet" | "testnet" = "mainnet"
): string {
  if (publicKey.length !== 33) {
    throw new Error(
      `Expected 33-byte compressed secp256k1 pubkey, got ${publicKey.length} bytes`
    );
  }
  const prefix = publicKey[0];
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new Error(
      `Invalid compressed pubkey prefix 0x${prefix.toString(16)}, expected 0x02 or 0x03`
    );
  }

  const pubkeyHash = hash160(publicKey); // 20 bytes
  const version = BITCOIN_VERSION_BYTE[network];

  // version (1) + hash160 (20) = 21 bytes
  const payload = new Uint8Array(21);
  payload[0] = version;
  payload.set(pubkeyHash, 1);

  // checksum: first 4 bytes of SHA256(SHA256(payload))
  const checksum = sha256(sha256(payload)).subarray(0, 4);

  // final: payload (21) + checksum (4) = 25 bytes
  const full = new Uint8Array(25);
  full.set(payload, 0);
  full.set(checksum, 21);

  return base58Encode(full);
}

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
 * Find the IKA coin object ID for an address.
 * IKA is a separate token from SUI - needed for Ika transaction fees.
 */
async function findIkaCoin(rpcUrl: string, address: string): Promise<string> {
  const resp = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0", id: 1,
      method: "suix_getCoins",
      params: [address, IKA_COIN_TYPE, null, 5],
    }),
  });
  const data = (await resp.json()) as any;
  const coins = data.result?.data || [];
  if (coins.length === 0) {
    throw new Error("No IKA tokens found. Get them from https://faucet.ika.xyz");
  }
  return coins[0].coinObjectId;
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

  // IKA coin (separate token type) required for Ika fees
  const rpcUrl = config.suiRpcUrl || (
    config.network === "testnet"
      ? "https://sui-testnet-rpc.publicnode.com"
      : "https://sui-mainnet-rpc.publicnode.com"
  );
  const ikaCoinId = config.ikaCoinId || await findIkaCoin(rpcUrl, address);
  const ikaCoinObj = tx.object(ikaCoinId);

  const dkgReturn = await (ikaTx as any).requestDWalletDKG({
    dkgRequestInput: dkgInput,
    sessionIdentifier: sessionId,
    dwalletNetworkEncryptionKeyId: networkEncKey?.id,
    curve: Curve.SECP256K1,
    ikaCoin: tx.splitCoins(ikaCoinObj, [50_000_000]),
    suiCoin: tx.splitCoins(tx.gas, [50_000_000]),
  });
  if (dkgReturn) {
    tx.transferObjects([dkgReturn], address);
  }

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

  // Derive chain-specific address from compressed pubkey
  let derivedAddress = "";
  if (pubkey && pubkey.length === 33 && chain === "zcash-transparent") {
    derivedAddress = deriveZcashAddress(pubkey, config.network);
  } else if (pubkey && pubkey.length === 33 && chain === "bitcoin") {
    derivedAddress = deriveBitcoinAddress(pubkey, config.network);
  }

  return {
    id: dwalletId,
    publicKey: pubkey || new Uint8Array(0),
    chain,
    address: derivedAddress,
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

  // Find IKA coin for fees
  const rpcUrl = config.suiRpcUrl || (
    config.network === "testnet"
      ? "https://sui-testnet-rpc.publicnode.com"
      : "https://sui-mainnet-rpc.publicnode.com"
  );
  const ikaCoinId = config.ikaCoinId || await findIkaCoin(rpcUrl, address);

  // TX 1: Request presign
  const presignTx = new Transaction();
  const presignIkaTx = new IkaTransaction({
    ikaClient,
    transaction: presignTx,
    userShareEncryptionKeys: encKeys,
  });

  const presignIkaCoin = presignTx.object(ikaCoinId);
  const presignSuiCoin = presignTx.splitCoins(presignTx.gas, [50_000_000]);
  presignIkaTx.requestGlobalPresign({
    dwalletNetworkEncryptionKeyId: dWallet.dwallet_network_encryption_key_id,
    curve: Curve.SECP256K1,
    signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
    ikaCoin: presignIkaCoin,
    suiCoin: presignSuiCoin,
  });

  const presignResult = await suiClient.signAndExecuteTransaction({
    transaction: presignTx,
    signer: keypair,
    options: { showEffects: true },
  });

  if (presignResult.effects?.status?.status !== "success") {
    throw new Error(`Presign TX failed: ${presignResult.effects?.status?.error}`);
  }

  // Find presign session and poll for completion.
  // Poll manually instead of using getPresignInParticularState so we can
  // detect NetworkRejected early rather than burning the full timeout.
  const presignCreated = presignResult.effects?.created || [];
  let completedPresign: any = null;

  for (const obj of presignCreated) {
    const id = (obj as any).reference?.objectId || (obj as any).objectId;
    if (!id) continue;
    try {
      const startTime = Date.now();
      let interval = POLL_OPTS.interval || 3_000;
      while (Date.now() - startTime < (POLL_OPTS.timeout || 300_000)) {
        const presign = await ikaClient.getPresign(id);
        const kind = presign?.state?.$kind;
        if (kind === "Completed") {
          completedPresign = presign;
          break;
        }
        if (kind === "NetworkRejected") {
          throw new Error(
            `Presign ${id} rejected by network (state: NetworkRejected). ` +
            `This usually means the MPC round was aborted by validators. ` +
            `Retry or check Ika network status.`
          );
        }
        await new Promise(r => setTimeout(r, interval));
        interval = Math.min(
          interval * (POLL_OPTS.backoffMultiplier || 1.5),
          POLL_OPTS.maxInterval || 10_000
        );
      }
      if (completedPresign) break;
    } catch (e: any) {
      if (e.message?.includes("NetworkRejected")) throw e;
      // Not a presign object or fetch error, try next created object
    }
  }

  if (!completedPresign) {
    throw new Error("Presign TX succeeded but timed out waiting for completion. Check Ika network status.");
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
    ikaCoin: signTx.splitCoins(signTx.object(ikaCoinId), [50_000_000]),
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

  // Find sign session and poll for signature.
  // Same manual polling as presign to detect NetworkRejected early.
  const signCreated = signResult.effects?.created || [];
  let completedSign: any = null;

  for (const obj of signCreated) {
    const id = (obj as any).reference?.objectId || (obj as any).objectId;
    if (!id) continue;
    try {
      const startTime = Date.now();
      let interval = POLL_OPTS.interval || 3_000;
      while (Date.now() - startTime < (POLL_OPTS.timeout || 300_000)) {
        const sign = await ikaClient.getSign(
          id, Curve.SECP256K1, SignatureAlgorithm.ECDSASecp256k1
        );
        const kind = sign?.state?.$kind;
        if (kind === "Completed") {
          completedSign = sign;
          break;
        }
        if (kind === "NetworkRejected") {
          throw new Error(
            `Sign ${id} rejected by network (state: NetworkRejected). ` +
            `MPC signing round aborted. Retry or check Ika network status.`
          );
        }
        await new Promise(r => setTimeout(r, interval));
        interval = Math.min(
          interval * (POLL_OPTS.backoffMultiplier || 1.5),
          POLL_OPTS.maxInterval || 10_000
        );
      }
      if (completedSign) break;
    } catch (e: any) {
      if (e.message?.includes("NetworkRejected")) throw e;
      // Not a sign object or fetch error, try next created object
    }
  }

  if (!completedSign?.state?.Completed?.signature) {
    throw new Error("Sign TX succeeded but timed out waiting for signature. Check Ika network status.");
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

export interface PolicyResult {
  /** SpendPolicy shared object ID on Sui */
  policyId: string;
  /** PolicyCap object ID (owner holds this to manage policy) */
  capId: string;
  /** Sui transaction digest */
  txDigest: string;
}

export interface PolicyState {
  policyId: string;
  dwalletId: string;
  owner: string;
  maxPerTx: number;
  maxDaily: number;
  dailySpent: number;
  windowStart: number;
  allowedRecipients: string[];
  frozen: boolean;
}

// Published package ID - set after sui client publish
// Override via POLICY_PACKAGE_ID env var or pass directly
const DEFAULT_POLICY_PACKAGE_ID = "0x0";

function getPolicyPackageId(): string {
  return process.env.POLICY_PACKAGE_ID || DEFAULT_POLICY_PACKAGE_ID;
}

/**
 * Set spending policy on a dWallet.
 * Creates a SpendPolicy shared object and PolicyCap on Sui.
 * The PolicyCap is transferred to the caller.
 */
export async function setPolicy(
  config: ZcashIkaConfig,
  walletId: string,
  policy: SpendPolicy
): Promise<PolicyResult> {
  const packageId = getPolicyPackageId();
  if (packageId === "0x0") {
    throw new Error(
      "Policy Move module not deployed. Set POLICY_PACKAGE_ID env var " +
      "after running: sui client publish --path move/"
    );
  }

  const { suiClient, keypair } = await initClients(config);

  const tx = new Transaction();

  // 0x6 is the shared Clock object on Sui
  const cap = tx.moveCall({
    target: `${packageId}::policy::create_policy`,
    arguments: [
      tx.pure.address(walletId),
      tx.pure.u64(policy.maxPerTx),
      tx.pure.u64(policy.maxDaily),
      tx.object("0x6"),
    ],
  });

  // Transfer the returned PolicyCap to sender
  const sender = keypair.getPublicKey().toSuiAddress();
  tx.transferObjects([cap], sender);

  // Add allowed recipients if any
  // Done in separate calls after creation since create_policy starts with empty list

  const result = await suiClient.signAndExecuteTransaction({
    transaction: tx,
    signer: keypair,
    options: { showEffects: true, showObjectChanges: true },
  });

  if (result.effects?.status?.status !== "success") {
    throw new Error(`setPolicy TX failed: ${result.effects?.status?.error}`);
  }

  // Extract created object IDs
  let policyId = "";
  let capId = "";

  const changes = (result as any).objectChanges || [];
  for (const change of changes) {
    if (change.type !== "created") continue;
    const objType = change.objectType || "";
    if (objType.includes("::policy::SpendPolicy")) {
      policyId = change.objectId;
    } else if (objType.includes("::policy::PolicyCap")) {
      capId = change.objectId;
    }
  }

  if (!policyId || !capId) {
    // Fallback: scan created effects
    const created = result.effects?.created || [];
    for (const obj of created) {
      const id = (obj as any).reference?.objectId || (obj as any).objectId;
      if (id && !policyId) policyId = id;
      else if (id && !capId) capId = id;
    }
  }

  // Add recipients in a second tx if needed
  if (policy.allowedRecipients.length > 0 && policyId && capId) {
    const tx2 = new Transaction();
    for (const addr of policy.allowedRecipients) {
      const addrBytes = new TextEncoder().encode(addr);
      tx2.moveCall({
        target: `${packageId}::policy::add_recipient_entry`,
        arguments: [
          tx2.object(policyId),
          tx2.object(capId),
          tx2.pure.vector("u8", Array.from(addrBytes)),
        ],
      });
    }
    await suiClient.signAndExecuteTransaction({
      transaction: tx2,
      signer: keypair,
      options: { showEffects: true },
    });
  }

  return { policyId, capId, txDigest: result.digest };
}

/**
 * Query a SpendPolicy object and check if a spend would be allowed.
 * Returns the full policy state plus a boolean for the specific check.
 */
export async function checkPolicy(
  config: ZcashIkaConfig,
  policyId: string,
  amount?: number,
  recipient?: string,
): Promise<PolicyState & { allowed: boolean }> {
  const { suiClient } = await initClients(config);

  const obj = await suiClient.getObject({
    id: policyId,
    options: { showContent: true },
  });

  const content = (obj.data?.content as any);
  if (!content || content.dataType !== "moveObject") {
    throw new Error(`Policy object ${policyId} not found or not a Move object`);
  }

  const fields = content.fields;

  const state: PolicyState = {
    policyId,
    dwalletId: fields.dwallet_id,
    owner: fields.owner,
    maxPerTx: Number(fields.max_per_tx),
    maxDaily: Number(fields.max_daily),
    dailySpent: Number(fields.daily_spent),
    windowStart: Number(fields.window_start),
    allowedRecipients: (fields.allowed_recipients || []).map((r: number[]) =>
      new TextDecoder().decode(new Uint8Array(r))
    ),
    frozen: fields.frozen,
  };

  // Client-side policy check (mirrors Move logic)
  let allowed = true;
  if (state.frozen) {
    allowed = false;
  } else if (amount !== undefined) {
    if (amount > state.maxPerTx) {
      allowed = false;
    } else {
      const now = Date.now();
      const daily = (now >= state.windowStart + 86_400_000) ? 0 : state.dailySpent;
      if (daily + amount > state.maxDaily) {
        allowed = false;
      }
    }
    if (allowed && recipient && state.allowedRecipients.length > 0) {
      allowed = state.allowedRecipients.includes(recipient);
    }
  }

  return { ...state, allowed };
}

/**
 * Spend from a Zcash transparent wallet.
 *
 * Full pipeline:
 * 1. Fetch UTXOs from Zebra
 * 2. Build unsigned TX, compute ZIP 244 sighashes
 * 3. Sign each sighash via Ika 2PC-MPC
 * 4. Attach signatures, serialize signed TX
 * 5. Broadcast via Zebra sendrawtransaction
 * 6. Attest to ZAP1 as AGENT_ACTION
 */
export async function spendTransparent(
  config: ZcashIkaConfig,
  walletId: string,
  encryptionSeed: string,
  request: SpendRequest
): Promise<SpendResult> {
  const zebraUrl = config.zebraRpcUrl;
  if (!zebraUrl) {
    throw new Error("zebraRpcUrl required for transparent spend");
  }

  // Fetch the dWallet to get the public key
  const { ikaClient } = await initClients(config);
  const dWallet = await ikaClient.getDWallet(walletId);
  if (!dWallet?.state?.Active) {
    throw new Error(`dWallet ${walletId} not Active`);
  }

  const rawOutput = dWallet.state.Active.public_output;
  const outputBytes = new Uint8Array(
    Array.isArray(rawOutput) ? rawOutput : Array.from(rawOutput)
  );
  const pubkey = await publicKeyFromDWalletOutput(Curve.SECP256K1, outputBytes);
  if (!pubkey || pubkey.length !== 33) {
    throw new Error("Could not extract 33-byte compressed pubkey from dWallet");
  }

  // Derive our t-address from the pubkey
  const ourAddress = deriveZcashAddress(pubkey, config.network);

  // Step 1: Fetch UTXOs
  const allUtxos = await fetchUTXOs(zebraUrl, ourAddress);
  if (allUtxos.length === 0) {
    throw new Error(`No UTXOs found for ${ourAddress}`);
  }

  // Step 2: Select UTXOs and build unsigned TX
  const fee = estimateFee(
    Math.min(allUtxos.length, 3), // estimate input count
    2 // recipient + change
  );
  const { selected } = selectUTXOs(allUtxos, request.amount, fee);

  // Recompute fee with actual input count
  const actualFee = estimateFee(selected.length, 2);
  const { unsignedTx, sighashes, txid } = buildUnsignedTx(
    selected,
    request.to,
    request.amount,
    actualFee,
    ourAddress, // change back to our address
    BRANCH_ID.NU5
  );

  // Step 3: Sign each sighash via MPC
  const signatures: Buffer[] = [];
  for (const sighash of sighashes) {
    const signResult = await sign(config, {
      messageHash: new Uint8Array(sighash),
      walletId,
      chain: "zcash-transparent",
      encryptionSeed,
    });
    signatures.push(Buffer.from(signResult.signature));
  }

  // Step 4: Attach signatures
  const txHex = attachSignatures(
    selected,
    request.to,
    request.amount,
    actualFee,
    ourAddress,
    signatures,
    Buffer.from(pubkey),
    BRANCH_ID.NU5
  );

  // Step 5: Broadcast
  const broadcastTxid = await broadcastTx(zebraUrl, txHex);

  // Step 6: Attest to ZAP1
  let leafHash = "";
  if (config.zap1ApiUrl && config.zap1ApiKey) {
    try {
      const attestResp = await fetch(`${config.zap1ApiUrl}/attest`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${config.zap1ApiKey}`,
        },
        body: JSON.stringify({
          event_type: "AGENT_ACTION",
          agent_id: walletId,
          action: "transparent_spend",
          chain_txid: broadcastTxid,
          recipient: request.to,
          amount: request.amount,
          fee: actualFee,
          memo: request.memo || "",
        }),
      });
      if (attestResp.ok) {
        const attestData = (await attestResp.json()) as { leaf_hash?: string };
        leafHash = attestData.leaf_hash || "";
      }
    } catch {
      // Attestation failure is non-fatal - tx already broadcast
    }
  }

  return {
    txid: broadcastTxid,
    leafHash,
    chain: "zcash-transparent",
    policyChecked: false, // policy enforcement via Move module is separate
  };
}

/**
 * Spend from a Bitcoin wallet.
 *
 * Full pipeline:
 * 1. Fetch UTXOs from Blockstream API
 * 2. Build unsigned TX, compute legacy P2PKH sighashes
 * 3. Sign each sighash via Ika 2PC-MPC
 * 4. Attach signatures, serialize signed TX
 * 5. Broadcast via Blockstream API
 * 6. Attest to ZAP1 as AGENT_ACTION
 */
export async function spendBitcoin(
  config: ZcashIkaConfig,
  walletId: string,
  encryptionSeed: string,
  request: SpendRequest
): Promise<SpendResult> {
  // Fetch the dWallet to get the public key
  const { ikaClient } = await initClients(config);
  const dWallet = await ikaClient.getDWallet(walletId);
  if (!dWallet?.state?.Active) {
    throw new Error(`dWallet ${walletId} not Active`);
  }

  const rawOutput = dWallet.state.Active.public_output;
  const outputBytes = new Uint8Array(
    Array.isArray(rawOutput) ? rawOutput : Array.from(rawOutput)
  );
  const pubkey = await publicKeyFromDWalletOutput(Curve.SECP256K1, outputBytes);
  if (!pubkey || pubkey.length !== 33) {
    throw new Error("Could not extract 33-byte compressed pubkey from dWallet");
  }

  const btcNetwork = config.network === "mainnet" ? "mainnet" : "testnet";

  // Derive our BTC address from the pubkey
  const ourAddress = deriveBitcoinAddress(pubkey, btcNetwork);

  // Step 1: Fetch UTXOs
  const allUtxos = await fetchBtcUTXOs(ourAddress, btcNetwork);
  if (allUtxos.length === 0) {
    throw new Error(`No UTXOs found for ${ourAddress}`);
  }

  // Step 2: Select UTXOs and build unsigned TX
  const feeRate = 10; // sat/vbyte, conservative default
  const { selected, fee } = selectBtcUTXOs(allUtxos, request.amount, feeRate);

  const { sighashes, inputs, outputs } = buildUnsignedBtcTx(
    selected,
    [{ address: request.to, value: request.amount }],
    ourAddress, // change back to our address
    fee
  );

  // Step 3: Sign each sighash via MPC
  const signatures: Buffer[] = [];
  for (const sighash of sighashes) {
    const signResult = await sign(config, {
      messageHash: new Uint8Array(sighash),
      walletId,
      chain: "bitcoin",
      encryptionSeed,
    });
    signatures.push(Buffer.from(signResult.signature));
  }

  // Step 4: Attach signatures and serialize
  const signedTx = attachBtcSignatures(
    inputs,
    outputs,
    signatures,
    Buffer.from(pubkey)
  );
  const txHex = signedTx.toString("hex");

  // Step 5: Broadcast
  const broadcastTxid = await broadcastBtcTx(txHex, btcNetwork);

  // Step 6: Attest to ZAP1
  let leafHash = "";
  if (config.zap1ApiUrl && config.zap1ApiKey) {
    try {
      const attestResp = await fetch(`${config.zap1ApiUrl}/attest`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${config.zap1ApiKey}`,
        },
        body: JSON.stringify({
          event_type: "AGENT_ACTION",
          agent_id: walletId,
          action: "bitcoin_spend",
          chain_txid: broadcastTxid,
          recipient: request.to,
          amount: request.amount,
          fee,
          memo: request.memo || "",
        }),
      });
      if (attestResp.ok) {
        const attestData = (await attestResp.json()) as { leaf_hash?: string };
        leafHash = attestData.leaf_hash || "";
      }
    } catch {
      // Attestation failure is non-fatal - tx already broadcast
    }
  }

  return {
    txid: broadcastTxid,
    leafHash,
    chain: "bitcoin",
    policyChecked: false,
  };
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
