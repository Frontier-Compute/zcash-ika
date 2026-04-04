// @ts-nocheck
/**
 * Ika DKG test - create secp256k1 dWallet on testnet.
 *
 * One secp256k1 dWallet signs for:
 *   - Zcash transparent (t-addr, DoubleSHA256)
 *   - Bitcoin (DoubleSHA256)
 *   - Ethereum/EVM (KECCAK256)
 *
 * Requires: SUI_PRIVATE_KEY env var (base64 Sui keypair)
 * Get testnet SUI: https://faucet.sui.io
 *
 * Usage:
 *   SUI_PRIVATE_KEY=suiprivkey1... node dist/test-dkg.js
 */

import { CoreClient } from "@mysten/sui/client";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import { decodeSuiPrivateKey } from "@mysten/sui/cryptography";
import {
  IkaClient,
  IkaTransaction,
  UserShareEncryptionKeys,
  getNetworkConfig,
  Curve,
  prepareDKGAsync,
  publicKeyFromDWalletOutput,
  createRandomSessionIdentifier,
  CHAIN_PARAMS,
} from "./index.js";

const NETWORK = "testnet";

async function main() {
  const privKeyRaw = process.env.SUI_PRIVATE_KEY;
  if (!privKeyRaw) {
    console.log("zcash-ika DKG test");
    console.log("==================");
    console.log("");
    console.log("Creates a secp256k1 dWallet on Ika testnet.");
    console.log("One key signs for Zcash transparent, Bitcoin, and Ethereum.");
    console.log("");
    console.log("Chain params:");
    for (const [chain, params] of Object.entries(CHAIN_PARAMS)) {
      console.log(`  ${chain}: ${params.curve}/${params.algorithm}/${params.hash}`);
    }
    console.log("");
    console.log("Usage:");
    console.log("  SUI_PRIVATE_KEY=suiprivkey1... node dist/test-dkg.js");
    console.log("  Get testnet SUI: https://faucet.sui.io");
    return;
  }

  // Decode Sui keypair
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
  console.log("Ika client initialized on testnet");

  // Check balance
  const balance = await suiClient.getBalance({ owner: address });
  const suiBalance = Number(balance.totalBalance) / 1e9;
  console.log(`SUI balance: ${suiBalance} SUI`);

  if (suiBalance < 0.2) {
    console.log("Need at least 0.2 SUI for gas.");
    console.log("Get testnet SUI: https://faucet.sui.io");
    return;
  }

  // Generate encryption keys for secp256k1
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  const encKeys = await UserShareEncryptionKeys.fromRootSeedKey(seed, Curve.SECP256K1);
  console.log("secp256k1 encryption keys generated");

  // Save seed for later signing (in production, derive from operator's master key)
  console.log("Encryption seed (save this for signing):", Buffer.from(seed).toString("hex"));

  // Prepare DKG
  const bytesToHash = createRandomSessionIdentifier();
  const dkgInput = await prepareDKGAsync(
    ikaClient,
    Curve.SECP256K1,
    encKeys,
    bytesToHash,
    address,
  );
  console.log("DKG prepared locally");

  // Build transaction
  const tx = new Transaction();
  const ikaTx = new IkaTransaction({
    ikaClient,
    transaction: tx,
    userShareEncryptionKeys: encKeys,
  });

  const sessionId = ikaTx.registerSessionIdentifier(bytesToHash);

  // Get network encryption key
  const networkEncKey = await ikaClient.getLatestNetworkEncryptionKey?.()
    || await (ikaClient as any).getConfiguredNetworkEncryptionKey?.();

  // Submit DKG request
  const dkgResult = await (ikaTx as any).requestDWalletDKG({
    dkgRequestInput: dkgInput,
    sessionIdentifier: sessionId,
    dwalletNetworkEncryptionKeyId: networkEncKey?.id,
    curve: Curve.SECP256K1,
    ikaCoin: tx.splitCoins(tx.gas, [50_000_000]),
    suiCoin: tx.splitCoins(tx.gas, [50_000_000]),
  });

  console.log("Submitting DKG to Ika network...");
  const result = await suiClient.signAndExecuteTransaction({
    transaction: tx,
    signer: keypair,
    options: { showEffects: true, showEvents: true },
  });
  console.log("TX digest:", result.digest);

  if (result.effects?.status?.status !== "success") {
    console.error("TX failed:", result.effects?.status?.error);
    return;
  }

  // Extract created objects
  const created = result.effects?.created || [];
  console.log(`Created ${created.length} objects`);
  for (const obj of created) {
    const id = (obj.reference as any)?.objectId || obj;
    console.log(`  ${id}`);
  }

  // Poll for dWallet to become Active (testnet can be slow)
  console.log("\nPolling for dWallet completion (up to 5 min)...");
  for (const obj of created) {
    const id = (obj.reference as any)?.objectId;
    if (!id) continue;
    try {
      const dw = await ikaClient.getDWalletInParticularState(id, "Active", {
        timeout: 300_000,
        interval: 3000,
        maxInterval: 10_000,
        backoffMultiplier: 1.5,
      });
      if (dw) {
        console.log(`\ndWallet Active: ${id}`);
        // Extract public key
        try {
          const pubkey = await publicKeyFromDWalletOutput(
            Curve.SECP256K1,
            dw.state?.Active?.public_output || dw.publicOutput,
          );
          console.log("Public key:", Buffer.from(pubkey).toString("hex"));
        } catch {
          console.log("(could not extract public key from output)");
        }
        console.log("\nSave this dWallet ID for signing:");
        console.log(`  DWALLET_ID=${id}`);
        break;
      }
    } catch (err: any) {
      // Not a dWallet object, skip
      if (!err.message?.includes("timeout")) continue;
      console.log(`Timeout waiting for ${id} - testnet may need longer`);
    }
  }

  console.log("\nDone.");
}

main().catch(console.error);
