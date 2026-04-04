// @ts-nocheck
/**
 * Ika MPC sign test - sign a message through the 2PC-MPC network.
 *
 * Takes an existing secp256k1 dWallet (from test-dkg) and signs a test
 * message through Ika's threshold MPC. Two transactions:
 *   1. Request presign (pre-compute MPC ephemeral)
 *   2. Approve message + request sign + poll for signature
 *
 * Env vars:
 *   SUI_PRIVATE_KEY  - base64 Sui keypair (same one that created the dWallet)
 *   DWALLET_ID       - dWallet object ID from test-dkg output
 *   ENC_SEED         - hex-encoded 32-byte seed from test-dkg (encryption keys)
 *
 * Usage:
 *   SUI_PRIVATE_KEY=... DWALLET_ID=0x... ENC_SEED=... node dist/test-sign.js
 */

import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import { decodeSuiPrivateKey } from "@mysten/sui/cryptography";
import {
  IkaClient,
  IkaTransaction,
  UserShareEncryptionKeys,
  getNetworkConfig,
  Curve,
  Hash,
  SignatureAlgorithm,
  parseSignatureFromSignOutput,
} from "./index.js";

const NETWORK = "testnet";
const POLL_TIMEOUT = 300_000; // 5 min - testnet epochs can be slow
const POLL_INTERVAL = 3_000;

async function main() {
  const privKeyRaw = process.env.SUI_PRIVATE_KEY;
  const dwalletId = process.env.DWALLET_ID;
  const encSeedHex = process.env.ENC_SEED;

  if (!privKeyRaw || !dwalletId || !encSeedHex) {
    console.log("zcash-ika sign test");
    console.log("===================");
    console.log("");
    console.log("Signs a test message through Ika 2PC-MPC on testnet.");
    console.log("Requires a secp256k1 dWallet from test-dkg.");
    console.log("");
    console.log("Env vars:");
    console.log("  SUI_PRIVATE_KEY  - Sui keypair (created the dWallet)");
    console.log("  DWALLET_ID       - dWallet object ID");
    console.log("  ENC_SEED         - 32-byte hex seed (from test-dkg)");
    console.log("");
    console.log("Usage:");
    console.log("  SUI_PRIVATE_KEY=... DWALLET_ID=0x... ENC_SEED=abcd... node dist/test-sign.js");
    return;
  }

  // Decode keypair
  const decoded = decodeSuiPrivateKey(privKeyRaw);
  const keypair = Ed25519Keypair.fromSecretKey(decoded.secretKey);
  const address = keypair.getPublicKey().toSuiAddress();
  console.log(`Sui address: ${address}`);

  // Init clients
  const { SuiJsonRpcClient } = await import("@mysten/sui/jsonRpc");
  const suiClient = new SuiJsonRpcClient({ url: "https://sui-testnet-rpc.publicnode.com" });
  const ikaConfig = getNetworkConfig(NETWORK);
  if (!ikaConfig) throw new Error("No Ika testnet config");

  const ikaClient = new IkaClient({
    suiClient,
    config: ikaConfig,
    cache: true,
    encryptionKeyOptions: { autoDetect: true },
  });
  await ikaClient.initialize();
  console.log("Ika client initialized");

  // Reconstruct encryption keys from seed
  const encSeed = Buffer.from(encSeedHex, "hex");
  const encKeys = await UserShareEncryptionKeys.fromRootSeedKey(
    new Uint8Array(encSeed),
    Curve.SECP256K1,
  );
  console.log("Encryption keys reconstructed");

  // Fetch the dWallet
  console.log(`\nFetching dWallet ${dwalletId}...`);
  const dWallet = await ikaClient.getDWallet(dwalletId);
  if (!dWallet) throw new Error(`dWallet ${dwalletId} not found`);

  const stateKey = Object.keys(dWallet.state || {})[0];
  console.log(`dWallet state: ${stateKey}`);
  console.log(`dWallet curve: ${dWallet.curve}`);
  console.log(`dWallet kind: ${dWallet.kind || "unknown"}`);

  if (stateKey !== "Active") {
    throw new Error(`dWallet not Active (state: ${stateKey}). Run test-dkg first.`);
  }

  // Get dWalletCap - use DWALLET_CAP env var or scan owned objects
  let capId = process.env.DWALLET_CAP;
  if (!capId) {
    console.log("\nScanning owned objects for DWalletCap...");
    const { SuiJsonRpcClient: Rpc } = await import("@mysten/sui/jsonRpc");
    const rpc = new Rpc({ url: "https://sui-testnet-rpc.publicnode.com" });
    const owned = await rpc.getOwnedObjects({
      owner: address,
      filter: { StructType: "0xf02f5960c94fce1899a3795b5d11fd076bc70a8d0e20a2b19923d990ed490730::coordinator_inner::DWalletCap" },
      options: { showContent: true },
    });
    const caps = owned.data || [];
    const cap = caps.find((c: any) => {
      const fields = c.data?.content?.fields;
      return fields?.dwallet_id === dwalletId;
    });
    if (!cap) {
      console.log(`Found ${caps.length} caps, none match dWallet ${dwalletId}`);
      for (const c of caps) {
        const f = (c.data?.content as any)?.fields;
        console.log(`  cap ${c.data?.objectId} -> dWallet ${f?.dwallet_id}`);
      }
      throw new Error(`No DWalletCap found for ${dwalletId}`);
    }
    capId = cap.data?.objectId;
  }
  console.log(`Using dWalletCap: ${capId}`);

  // Test message - in production this would be a Zcash sighash
  const testMessage = new TextEncoder().encode("zcash-ika-sign-test-v1");
  console.log(`\nTest message: "${new TextDecoder().decode(testMessage)}"`);
  console.log(`Message bytes: ${Buffer.from(testMessage).toString("hex")}`);

  // Fetch IKA coins - IKA is a separate token from SUI, can't split from gas
  const IKA_COIN_TYPE = "0x1f26bb2f711ff82dcda4d02c77d5123089cb7f8418751474b9fb744ce031526a::ika::IKA";
  const ikaResp = await fetch("https://sui-testnet-rpc.publicnode.com", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "suix_getCoins", params: [address, IKA_COIN_TYPE, null, 5] }),
  });
  const ikaData = (await ikaResp.json()) as any;
  const ikaCoins = ikaData.result?.data || [];
  if (ikaCoins.length === 0) {
    console.log("No IKA tokens. Get them from https://faucet.ika.xyz");
    return;
  }
  const ikaCoinId = ikaCoins[0].coinObjectId;
  console.log(`IKA coin: ${ikaCoinId} (${Number(ikaCoins[0].balance) / 1e9} IKA)`);

  // STEP 1: Request presign
  console.log("\n--- Step 1: Presign ---");
  const presignTx = new Transaction();
  const presignIkaTx = new IkaTransaction({
    ikaClient,
    transaction: presignTx,
    userShareEncryptionKeys: encKeys,
  });

  // IKA coin passed as object ref (Move takes &mut, coin survives the call)
  const presignIkaCoin = presignTx.object(ikaCoinId);
  const presignSuiCoin = presignTx.splitCoins(presignTx.gas, [50_000_000]);

  const unverifiedPresignCap = presignIkaTx.requestPresign({
    dWallet,
    signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
    ikaCoin: presignIkaCoin,
    suiCoin: presignSuiCoin,
  });

  // Transfer split SUI coin back and presign cap to ourselves
  presignTx.transferObjects([presignSuiCoin], address);
  if (unverifiedPresignCap) {
    presignTx.transferObjects([unverifiedPresignCap], address);
  }

  console.log("Submitting presign request...");
  const presignResult = await suiClient.signAndExecuteTransaction({
    transaction: presignTx,
    signer: keypair,
    options: { showEffects: true, showEvents: true },
  });
  console.log(`Presign TX: ${presignResult.digest}`);

  if (presignResult.effects?.status?.status !== "success") {
    throw new Error(`Presign TX failed: ${presignResult.effects?.status?.error}`);
  }

  // Extract presign session ID from created objects
  const presignCreated = presignResult.effects?.created || [];
  console.log(`Created ${presignCreated.length} objects`);

  // The presign session is one of the created objects - find it by polling each
  let presignId: string | null = null;
  for (const obj of presignCreated) {
    const id = (obj.reference as any)?.objectId;
    if (!id) continue;
    try {
      const p = await ikaClient.getPresign(id);
      if (p) {
        presignId = id;
        console.log(`Presign session: ${id}`);
        break;
      }
    } catch {
      // Not a presign object
    }
  }

  if (!presignId) {
    console.log("Created objects:");
    for (const obj of presignCreated) {
      console.log(`  ${(obj.reference as any)?.objectId}`);
    }
    throw new Error("Could not identify presign session from created objects");
  }

  // Poll for presign completion
  console.log(`Polling for presign completion (up to ${POLL_TIMEOUT / 1000}s)...`);
  const completedPresign = await ikaClient.getPresignInParticularState(
    presignId,
    "Completed",
    {
      timeout: POLL_TIMEOUT,
      interval: POLL_INTERVAL,
      maxInterval: 10_000,
      backoffMultiplier: 1.5,
    },
  );
  console.log("Presign completed");

  // STEP 2: Approve message + sign
  console.log("\n--- Step 2: Sign ---");
  const signTx = new Transaction();
  const signIkaTx = new IkaTransaction({
    ikaClient,
    transaction: signTx,
    userShareEncryptionKeys: encKeys,
  });

  // Verify the presign capability
  const verifiedPresignCap = signIkaTx.verifyPresignCap({
    presign: completedPresign,
  });

  // Approve the message (this is where Move policy would gate in production)
  const messageApproval = signIkaTx.approveMessage({
    dWalletCap: capId,
    curve: Curve.SECP256K1,
    signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
    hashScheme: Hash.DoubleSHA256,
    message: testMessage,
  });

  // Re-fetch IKA coins (version may have changed after presign tx)
  const ikaResp2 = await fetch("https://sui-testnet-rpc.publicnode.com", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "suix_getCoins", params: [address, IKA_COIN_TYPE, null, 5] }),
  });
  const ikaData2 = (await ikaResp2.json()) as any;
  const ikaCoins2 = ikaData2.result?.data || [];
  if (ikaCoins2.length === 0) throw new Error("No IKA coins for sign tx");
  const signIkaCoinId = ikaCoins2[0].coinObjectId;

  // IKA coin as object ref, SUI split from gas
  const signIkaCoin = signTx.object(signIkaCoinId);
  const signSuiCoin = signTx.splitCoins(signTx.gas, [50_000_000]);

  // Request the actual signature
  const signatureId = await signIkaTx.requestSign({
    dWallet,
    messageApproval,
    hashScheme: Hash.DoubleSHA256,
    verifiedPresignCap,
    presign: completedPresign,
    encryptedUserSecretKeyShare: undefined,
    message: testMessage,
    signatureScheme: SignatureAlgorithm.ECDSASecp256k1,
    ikaCoin: signIkaCoin,
    suiCoin: signSuiCoin,
  });

  // Transfer split SUI coin back
  signTx.transferObjects([signSuiCoin], address);

  console.log("Submitting sign request...");
  const signResult = await suiClient.signAndExecuteTransaction({
    transaction: signTx,
    signer: keypair,
    options: { showEffects: true, showEvents: true },
  });
  console.log(`Sign TX: ${signResult.digest}`);

  if (signResult.effects?.status?.status !== "success") {
    throw new Error(`Sign TX failed: ${signResult.effects?.status?.error}`);
  }

  // Extract sign session ID
  const signCreated = signResult.effects?.created || [];
  let signSessionId: string | null = null;
  for (const obj of signCreated) {
    const id = (obj.reference as any)?.objectId;
    if (!id) continue;
    try {
      const s = await ikaClient.getSign(id, Curve.SECP256K1, SignatureAlgorithm.ECDSASecp256k1);
      if (s) {
        signSessionId = id;
        console.log(`Sign session: ${id}`);
        break;
      }
    } catch {
      // Not a sign object
    }
  }

  if (!signSessionId) {
    console.log("Created objects:");
    for (const obj of signCreated) {
      console.log(`  ${(obj.reference as any)?.objectId}`);
    }
    throw new Error("Could not identify sign session from created objects");
  }

  // Poll for sign completion
  console.log(`Polling for signature (up to ${POLL_TIMEOUT / 1000}s)...`);
  const completedSign = await ikaClient.getSignInParticularState(
    signSessionId,
    Curve.SECP256K1,
    SignatureAlgorithm.ECDSASecp256k1,
    "Completed",
    {
      timeout: POLL_TIMEOUT,
      interval: POLL_INTERVAL,
      maxInterval: 10_000,
      backoffMultiplier: 1.5,
    },
  );

  // The signature is already parsed by getSign (which getSignInParticularState calls)
  const signatureBytes = completedSign.state?.Completed?.signature;
  if (!signatureBytes) {
    console.log("Sign state:", JSON.stringify(completedSign.state, null, 2));
    throw new Error("No signature in completed sign output");
  }

  const sigHex = Buffer.from(signatureBytes).toString("hex");
  console.log("\n=== MPC SIGNATURE ===");
  console.log(`Signature (${signatureBytes.length} bytes): ${sigHex}`);
  console.log(`dWallet: ${dwalletId}`);
  console.log(`Message: ${Buffer.from(testMessage).toString("hex")}`);
  console.log(`Hash: DoubleSHA256`);
  console.log(`Algorithm: ECDSASecp256k1`);
  console.log(`Sign TX: ${signResult.digest}`);
  console.log("=====================");

  console.log("\nDone. Signature produced through Ika 2PC-MPC.");
  console.log("Neither key half ever existed in one place.");
}

main().catch((err) => {
  console.error("Fatal:", err.message || err);
  process.exit(1);
});
