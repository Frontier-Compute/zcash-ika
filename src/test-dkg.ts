// @ts-nocheck
/**
 * Ika DKG test - create dWallets on testnet.
 *
 * Creates:
 * 1. Ed25519 dWallet (Zcash Orchard shielded)
 * 2. secp256k1 dWallet (Bitcoin + USDC + USDT + any EVM)
 *
 * One operator, split-key custody across all chains.
 * Swiss bank in your pocket. Jailbroken but legal tender.
 *
 * Requires: SUI_PRIVATE_KEY env var (base64 Sui keypair)
 * Get testnet SUI: https://faucet.sui.io
 *
 * Usage:
 *   SUI_PRIVATE_KEY=... node dist/test-dkg.js
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
  type Chain,
} from "./index.js";

const NETWORK = "testnet";

async function createDWallet(
  ikaClient: IkaClient,
  suiClient: CoreClient,
  keypair: Ed25519Keypair,
  encKeys: UserShareEncryptionKeys,
  chain: Chain,
  address: string,
) {
  const params = CHAIN_PARAMS[chain];
  console.log(`\n--- ${params.description} ---`);
  console.log(`Params: ${params.curve}/${params.algorithm}/${params.hash}`);

  // Prepare DKG (async fetches protocol public params from network)
  const bytesToHash = createRandomSessionIdentifier();
  const dkgInput = await prepareDKGAsync(
    ikaClient,
    Curve[params.curve],
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
  const networkEncKey = await (ikaClient as any).getLatestNetworkEncryptionKey?.()
    || await (ikaClient as any).getConfiguredNetworkEncryptionKey?.();

  if (!networkEncKey) {
    // Try without - some SDK versions auto-detect
    console.log("No explicit encryption key method found, trying auto-detect...");
  }

  // Submit DKG request
  const dkgResult = await (ikaTx as any).requestDWalletDKG({
    dkgRequestInput: dkgInput,
    sessionIdentifier: sessionId,
    dwalletNetworkEncryptionKeyId: networkEncKey?.id,
    curve: Curve[params.curve],
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
    return null;
  }

  console.log("DKG submitted. Poll for completion...");

  // Extract dWallet ID from events/created objects
  const created = result.effects?.created || [];
  console.log(`Created ${created.length} objects`);
  for (const obj of created) {
    console.log(`  ${(obj.reference as any)?.objectId || obj}`);
  }

  return result;
}

async function main() {
  const privKeyRaw = process.env.SUI_PRIVATE_KEY;
  if (!privKeyRaw) {
    console.log("zcash-ika DKG test");
    console.log("==================");
    console.log("");
    console.log("Chain params (what Ika signs for each chain):");
    for (const [chain, params] of Object.entries(CHAIN_PARAMS)) {
      console.log(`  ${chain}: ${params.curve}/${params.algorithm}/${params.hash}`);
    }
    console.log("");
    console.log("secp256k1/ECDSA/DoubleSHA256 signs for:");
    console.log("  - Bitcoin (BTC)");
    console.log("  - Zcash transparent (t-addr)");
    console.log("  - Ethereum/Base (USDC, USDT) via KECCAK256 variant");
    console.log("");
    console.log("Ed25519/EdDSA/SHA512 signs for:");
    console.log("  - Zcash Orchard (shielded ZEC)");
    console.log("");
    console.log("One operator. Split-key custody. Every chain.");
    console.log("");
    console.log("To run DKG:");
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
  // PublicNode doesn't rate limit like Mysten's public RPC
  const { SuiJsonRpcClient } = await import("@mysten/sui/jsonRpc");
  const suiClient = new SuiJsonRpcClient({ url: "https://sui-testnet-rpc.publicnode.com" });
  const ikaConfig = getNetworkConfig(NETWORK);
  if (!ikaConfig) throw new Error("No Ika testnet config");

  const ikaClient = new IkaClient({ suiClient, config: ikaConfig });
  await ikaClient.initialize();
  console.log("Ika client initialized on testnet");

  // Check balance
  const balance = await suiClient.getBalance({ owner: address });
  const suiBalance = Number(balance.totalBalance) / 1e9;
  console.log(`SUI balance: ${suiBalance} SUI`);

  if (suiBalance < 0.2) {
    console.log("Need at least 0.2 SUI for gas (two DKG operations).");
    console.log("Get testnet SUI: https://faucet.sui.io");
    return;
  }

  // Generate encryption keys - one per curve
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);

  // Ed25519 encryption keys for shielded ZEC wallet
  const edEncKeys = await UserShareEncryptionKeys.fromRootSeedKey(seed, Curve.ED25519);
  console.log("Ed25519 encryption keys generated");

  // secp256k1 encryption keys for BTC/stablecoin wallet
  const secpEncKeys = await UserShareEncryptionKeys.fromRootSeedKey(seed, Curve.SECP256K1);
  console.log("secp256k1 encryption keys generated");

  // Create Ed25519 dWallet (Zcash Orchard)
  try {
    await createDWallet(ikaClient, suiClient, keypair, edEncKeys, "zcash-shielded", address);
  } catch (err) {
    console.error("Ed25519 DKG error:", (err as Error).message);
  }

  // Create secp256k1 dWallet (Bitcoin + stablecoins)
  try {
    await createDWallet(ikaClient, suiClient, keypair, secpEncKeys, "bitcoin", address);
  } catch (err) {
    console.error("secp256k1 DKG error:", (err as Error).message);
  }

  console.log("\nDone.");
}

main().catch(console.error);
