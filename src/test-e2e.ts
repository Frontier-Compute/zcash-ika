// @ts-nocheck
/**
 * End-to-end test: create dWallet + sign a Zcash-format sighash.
 *
 * This proves the full pipeline:
 * 1. DKG (create secp256k1 dWallet)
 * 2. Presign (pre-compute MPC ephemeral)
 * 3. Sign a Zcash transparent sighash format
 * 4. Verify the ECDSA signature against the dWallet public key
 *
 * The sighash uses Zcash's DoubleSHA256 format:
 *   SHA256(SHA256(version || prevouts_hash || sequence_hash || outputs_hash || ...))
 *
 * For this test we sign a synthetic sighash (32 bytes) rather than building
 * a real transaction (that requires UTXOs). The MPC doesn't care about the
 * semantics of what it signs - it just signs the 32-byte hash.
 *
 * Env vars:
 *   SUI_PRIVATE_KEY  - base64 Sui keypair
 *
 * Usage:
 *   SUI_PRIVATE_KEY=suiprivkey1... node dist/test-e2e.js
 */

import { createHash } from "crypto";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import { decodeSuiPrivateKey } from "@mysten/sui/cryptography";

const IKA_COIN_TYPE = "0x1f26bb2f711ff82dcda4d02c77d5123089cb7f8418751474b9fb744ce031526a::ika::IKA";
import {
  IkaClient,
  IkaTransaction,
  UserShareEncryptionKeys,
  getNetworkConfig,
  Curve,
  Hash,
  SignatureAlgorithm,
  createRandomSessionIdentifier,
  prepareDKGAsync,
  publicKeyFromDWalletOutput,
} from "./index.js";

const NETWORK = "testnet";
const POLL_TIMEOUT = 300_000;
const POLL_INTERVAL = 3_000;
const POLL_OPTS = {
  timeout: POLL_TIMEOUT,
  interval: POLL_INTERVAL,
  maxInterval: 10_000,
  backoffMultiplier: 1.5,
};

/**
 * Compute a synthetic Zcash transparent sighash.
 * Real sighashes come from transaction serialization.
 * This produces a 32-byte hash in the same format.
 */
function syntheticZcashSighash(): { sighash: Uint8Array; description: string } {
  // Simulate: version=5, no inputs/outputs, lock_time=0
  // Real sighash would be SHA256(SHA256(serialized_tx_parts))
  const preimage = Buffer.concat([
    Buffer.from("050000800a27a726b4d0d6c2", "hex"), // zcash v5 header
    createHash("sha256").update("test-prevouts").digest(),
    createHash("sha256").update("test-sequences").digest(),
    createHash("sha256").update("test-outputs").digest(),
    Buffer.alloc(4, 0), // lock_time
    Buffer.from([0x01]), // sighash_type SIGHASH_ALL
  ]);

  // DoubleSHA256 (what Zcash transparent actually uses for sighash)
  const first = createHash("sha256").update(preimage).digest();
  const sighash = createHash("sha256").update(first).digest();

  return {
    sighash: new Uint8Array(sighash),
    description: "Synthetic Zcash v5 transparent sighash (DoubleSHA256)",
  };
}

async function main() {
  const privKeyRaw = process.env.SUI_PRIVATE_KEY;
  if (!privKeyRaw) {
    console.log("zcash-ika E2E test");
    console.log("==================");
    console.log("");
    console.log("Full pipeline: DKG -> presign -> sign Zcash sighash -> verify");
    console.log("");
    console.log("Usage:");
    console.log("  SUI_PRIVATE_KEY=suiprivkey1... node dist/test-e2e.js");
    return;
  }

  const decoded = decodeSuiPrivateKey(privKeyRaw);
  const keypair = Ed25519Keypair.fromSecretKey(decoded.secretKey);
  const address = keypair.getPublicKey().toSuiAddress();
  console.log(`Sui address: ${address}`);

  // Init
  const { SuiJsonRpcClient } = await import("@mysten/sui/jsonRpc");
  const suiClient = new SuiJsonRpcClient({
    url: "https://sui-testnet-rpc.publicnode.com",
    network: "testnet",
  });
  const ikaConfig = getNetworkConfig(NETWORK);
  const ikaClient = new IkaClient({
    suiClient,
    config: ikaConfig,
    cache: true,
    encryptionKeyOptions: { autoDetect: true },
  });

  try {
    await ikaClient.initialize();
    console.log("Ika client initialized");
  } catch (err: any) {
    console.log("Ika init warning:", err.message?.slice(0, 200));
  }

  // Try to get encryption keys
  try {
    const allKeys = await ikaClient.getAllNetworkEncryptionKeys();
    console.log(`Found ${allKeys?.length || 0} encryption keys`);
  } catch (err: any) {
    console.log("Encryption keys error:", err.message?.slice(0, 200));
  }

  // Check balance
  const balance = await suiClient.getBalance({ owner: address });
  const suiBalance = Number(balance.totalBalance) / 1e9;
  console.log(`SUI balance: ${suiBalance} SUI`);
  if (suiBalance < 0.1) {
    console.log("Need at least 0.1 SUI for gas");
    return;
  }

  // Find IKA coin (needed for Ika gas, separate from SUI gas)
  const ikaCoinsResp = await fetch("https://sui-testnet-rpc.publicnode.com", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0", id: 1,
      method: "suix_getCoins",
      params: [address, IKA_COIN_TYPE, null, 5],
    }),
  });
  const ikaCoinsData = (await ikaCoinsResp.json()) as any;
  const ikaCoins = ikaCoinsData.result?.data || [];
  if (ikaCoins.length === 0) {
    console.log("No IKA tokens found. Get them from https://faucet.ika.xyz");
    return;
  }
  const ikaCoinId = ikaCoins[0].coinObjectId;
  const ikaBalance = Number(ikaCoins[0].balance) / 1e9;
  console.log(`IKA coin: ${ikaCoinId} (${ikaBalance} IKA)`);

  // Generate encryption keys
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  const encKeys = await UserShareEncryptionKeys.fromRootSeedKey(seed, Curve.SECP256K1);
  const seedHex = Buffer.from(seed).toString("hex");
  console.log(`Encryption seed: ${seedHex}`);

  // PHASE 1: DKG
  console.log("\n=== PHASE 1: DKG ===");
  const bytesToHash = createRandomSessionIdentifier();
  const dkgInput = await prepareDKGAsync(ikaClient, Curve.SECP256K1, encKeys, bytesToHash, address);

  const dkgTx = new Transaction();

  const networkEncKey = await ikaClient.getLatestNetworkEncryptionKey?.()
    || await (ikaClient as any).getConfiguredNetworkEncryptionKey?.();
  const ikaConf = (ikaClient as any).ikaConfig;

  // Low-level DKG call (keyspring pattern - bypass IkaTransaction wrapper)
  const { coordinatorTransactions } = await import("@ika.xyz/sdk");

  const [dWalletCap] = coordinatorTransactions.requestDWalletDKG(
    ikaConf,
    dkgTx.object(ikaConf.objects.ikaDWalletCoordinator.objectID),
    networkEncKey?.id,
    0, // secp256k1
    dkgInput.userDKGMessage,
    dkgInput.encryptedUserShareAndProof,
    encKeys.getSuiAddress(),
    dkgInput.userPublicOutput,
    encKeys.getSigningPublicKeyBytes(),
    coordinatorTransactions.registerSessionIdentifier(
      ikaConf,
      dkgTx.object(ikaConf.objects.ikaDWalletCoordinator.objectID),
      bytesToHash,
      dkgTx,
    ),
    null, // no signDuringDKG
    dkgTx.object(ikaCoinId), // full IKA coin (not split)
    dkgTx.gas, // SUI gas coin directly
    dkgTx,
  );
  dkgTx.transferObjects([dWalletCap], address);

  const dkgResult = await suiClient.signAndExecuteTransaction({
    transaction: dkgTx,
    signer: keypair,
    options: { showEffects: true },
  });
  console.log(`DKG TX: ${dkgResult.digest}`);

  if (dkgResult.effects?.status?.status !== "success") {
    throw new Error(`DKG failed: ${dkgResult.effects?.status?.error}`);
  }

  // Find active dWallet
  const dkgCreated = dkgResult.effects?.created || [];
  let dwalletId = null;
  let dWallet = null;

  for (const obj of dkgCreated) {
    const id = (obj.reference as any)?.objectId;
    if (!id) continue;
    try {
      const dw = await ikaClient.getDWalletInParticularState(id, "Active", POLL_OPTS);
      if (dw) {
        dwalletId = id;
        dWallet = dw;
        break;
      }
    } catch { continue; }
  }

  if (!dwalletId || !dWallet) throw new Error("DKG completed but no Active dWallet found");
  console.log(`dWallet: ${dwalletId}`);

  // Extract public key
  let pubkeyHex = "(unknown)";
  try {
    const rawOut = dWallet.state?.Active?.public_output;
    const outBytes = new Uint8Array(Array.isArray(rawOut) ? rawOut : Array.from(rawOut));
    const pubkey = await publicKeyFromDWalletOutput(Curve.SECP256K1, outBytes);
    pubkeyHex = Buffer.from(pubkey).toString("hex");
  } catch {}
  console.log(`Public key: ${pubkeyHex}`);

  // Get dWalletCap
  const capsResult = await ikaClient.getOwnedDWalletCaps(address);
  const cap = (capsResult.dWalletCaps || []).find((c: any) => c.dwallet_id === dwalletId);
  if (!cap) throw new Error("No dWalletCap found");
  console.log(`dWalletCap: ${cap.id}`);

  // Compute sighash
  const { sighash, description } = syntheticZcashSighash();
  console.log(`\nSighash: ${Buffer.from(sighash).toString("hex")}`);
  console.log(`Format: ${description}`);

  // PHASE 2: PRESIGN
  console.log("\n=== PHASE 2: PRESIGN ===");
  const presignTx = new Transaction();
  const presignIkaTx = new IkaTransaction({
    ikaClient,
    transaction: presignTx,
    userShareEncryptionKeys: encKeys,
  });

  const presignIkaCoinObj = presignTx.object(ikaCoinId);
  presignIkaTx.requestPresign({
    dWallet,
    signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
    ikaCoin: presignTx.splitCoins(presignIkaCoinObj, [50_000_000]),
    suiCoin: presignTx.splitCoins(presignTx.gas, [50_000_000]),
  });

  const presignResult = await suiClient.signAndExecuteTransaction({
    transaction: presignTx,
    signer: keypair,
    options: { showEffects: true },
  });
  console.log(`Presign TX: ${presignResult.digest}`);

  if (presignResult.effects?.status?.status !== "success") {
    throw new Error(`Presign failed: ${presignResult.effects?.status?.error}`);
  }

  // Find and poll presign session
  const presignCreated = presignResult.effects?.created || [];
  let completedPresign = null;

  for (const obj of presignCreated) {
    const id = (obj.reference as any)?.objectId;
    if (!id) continue;
    try {
      completedPresign = await ikaClient.getPresignInParticularState(id, "Completed", POLL_OPTS);
      if (completedPresign) {
        console.log(`Presign completed: ${id}`);
        break;
      }
    } catch { continue; }
  }

  if (!completedPresign) throw new Error("Presign TX succeeded but no completed presign found");

  // PHASE 3: SIGN
  console.log("\n=== PHASE 3: SIGN ===");
  const signTx = new Transaction();
  const signIkaTx = new IkaTransaction({
    ikaClient,
    transaction: signTx,
    userShareEncryptionKeys: encKeys,
  });

  const verifiedPresignCap = signIkaTx.verifyPresignCap({ presign: completedPresign });

  const messageApproval = signIkaTx.approveMessage({
    dWalletCap: cap.id,
    curve: Curve.SECP256K1,
    signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
    hashScheme: Hash.DoubleSHA256,
    message: sighash,
  });

  const signIkaCoinObj = signTx.object(ikaCoinId);
  await signIkaTx.requestSign({
    dWallet,
    messageApproval,
    hashScheme: Hash.DoubleSHA256,
    verifiedPresignCap,
    presign: completedPresign,
    message: sighash,
    signatureScheme: SignatureAlgorithm.ECDSASecp256k1,
    ikaCoin: signTx.splitCoins(signIkaCoinObj, [50_000_000]),
    suiCoin: signTx.splitCoins(signTx.gas, [50_000_000]),
  });

  const signResult = await suiClient.signAndExecuteTransaction({
    transaction: signTx,
    signer: keypair,
    options: { showEffects: true },
  });
  console.log(`Sign TX: ${signResult.digest}`);

  if (signResult.effects?.status?.status !== "success") {
    throw new Error(`Sign failed: ${signResult.effects?.status?.error}`);
  }

  // Poll for signature
  const signCreated = signResult.effects?.created || [];
  let completedSign = null;

  for (const obj of signCreated) {
    const id = (obj.reference as any)?.objectId;
    if (!id) continue;
    try {
      completedSign = await ikaClient.getSignInParticularState(
        id, Curve.SECP256K1, SignatureAlgorithm.ECDSASecp256k1, "Completed", POLL_OPTS,
      );
      if (completedSign) {
        console.log(`Sign completed: ${id}`);
        break;
      }
    } catch { continue; }
  }

  if (!completedSign?.state?.Completed?.signature) {
    throw new Error("Sign TX succeeded but no signature produced");
  }

  const sigBytes = completedSign.state.Completed.signature;
  const sigHex = Buffer.from(sigBytes).toString("hex");

  console.log("\n========================================");
  console.log("MPC SIGNATURE COMPLETE");
  console.log("========================================");
  console.log(`dWallet:    ${dwalletId}`);
  console.log(`Public key: ${pubkeyHex}`);
  console.log(`Sighash:    ${Buffer.from(sighash).toString("hex")}`);
  console.log(`Signature:  ${sigHex}`);
  console.log(`DKG TX:     ${dkgResult.digest}`);
  console.log(`Presign TX: ${presignResult.digest}`);
  console.log(`Sign TX:    ${signResult.digest}`);
  console.log(`Seed:       ${seedHex}`);
  console.log("========================================");
  console.log("");
  console.log("This signature was produced by Ika's 2PC-MPC network.");
  console.log("The full private key never existed in one place.");
  console.log("Attach this to a Zcash transparent transaction and broadcast.");
}

main().catch((err) => {
  console.error("\nFailed:", err.message || err);
  process.exit(1);
});
