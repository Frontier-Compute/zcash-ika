#!/usr/bin/env node
/**
 * quick-demo.cjs - Ika RFP demo script
 *
 * Derives ZEC + BTC addresses from a known dWallet pubkey.
 * No network calls. Pure local crypto. Runs in <2 seconds.
 *
 * Usage: node demo/quick-demo.cjs
 */

const { createHash } = require("node:crypto");

// Known dWallet public key (compressed secp256k1, from DKG on Ika testnet)
const PUBKEY_HEX = "03d691c837d008538ffbbb60438dad338b9b6a1a732b1b17096f890c9abdc12cb7";
const DWALLET_ID = "0x108c8e98d0384d3eef7e65e6abd4613fdc23ca3fca2fe1badd60d54ab8e84c90";

// Zcash version bytes (2 bytes)
const ZEC_MAINNET = Buffer.from([0x1c, 0xb8]);
const ZEC_TESTNET = Buffer.from([0x1d, 0x25]);

// Bitcoin version bytes (1 byte)
const BTC_MAINNET = 0x00;
const BTC_TESTNET = 0x6f;

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function sha256(data) {
  return createHash("sha256").update(data).digest();
}

function hash160(data) {
  return createHash("ripemd160").update(sha256(data)).digest();
}

function base58Encode(data) {
  let leadingZeros = 0;
  for (const b of data) {
    if (b !== 0) break;
    leadingZeros++;
  }
  let num = BigInt(0);
  for (const b of data) {
    num = num * 256n + BigInt(b);
  }
  const chars = [];
  while (num > 0n) {
    chars.push(BASE58[Number(num % 58n)]);
    num = num / 58n;
  }
  for (let i = 0; i < leadingZeros; i++) {
    chars.push("1");
  }
  return chars.reverse().join("");
}

function deriveZcashAddr(pubkeyBuf, versionBytes) {
  const h = hash160(pubkeyBuf);
  const payload = Buffer.alloc(22);
  versionBytes.copy(payload, 0);
  h.copy(payload, 2);
  const checksum = sha256(sha256(payload)).subarray(0, 4);
  const full = Buffer.alloc(26);
  payload.copy(full, 0);
  checksum.copy(full, 22);
  return base58Encode(full);
}

function deriveBitcoinAddr(pubkeyBuf, versionByte) {
  const h = hash160(pubkeyBuf);
  const payload = Buffer.alloc(21);
  payload[0] = versionByte;
  h.copy(payload, 1);
  const checksum = sha256(sha256(payload)).subarray(0, 4);
  const full = Buffer.alloc(25);
  payload.copy(full, 0);
  checksum.copy(full, 21);
  return base58Encode(full);
}

// Derive addresses
const pubkey = Buffer.from(PUBKEY_HEX, "hex");

const zecMainnet = deriveZcashAddr(pubkey, ZEC_MAINNET);
const zecTestnet = deriveZcashAddr(pubkey, ZEC_TESTNET);
const btcMainnet = deriveBitcoinAddr(pubkey, BTC_MAINNET);
const btcTestnet = deriveBitcoinAddr(pubkey, BTC_TESTNET);

console.log("");
console.log("--- zcash-ika address derivation ---");
console.log("");
console.log("dWallet pubkey: " + PUBKEY_HEX);
console.log("dWallet ID:     " + DWALLET_ID);
console.log("");
console.log("ZEC t-addr (mainnet): " + zecMainnet);
console.log("ZEC t-addr (testnet): " + zecTestnet);
console.log("BTC addr   (mainnet): " + btcMainnet);
console.log("BTC addr   (testnet): " + btcTestnet);
console.log("");
console.log("Same secp256k1 key. Two chains. One dWallet controls both.");
console.log("");

// Mainnet proof
console.log("--- mainnet proof ---");
console.log("");
console.log("ZEC mainnet TX: 9ced54f695258ca0ead4e7188ad6e1eee489dbf8c7b89571e27ddca793bf239b");
console.log("Explorer:       https://zcashblockexplorer.com/transactions/9ced54f695258ca0ead4e7188ad6e1eee489dbf8c7b89571e27ddca793bf239b");
console.log("Ika sign TX:    Hcn1cW27nELwPog7xwfedNE1kGAsSzSmFy5whGALw77b");
console.log("");

// Move package
console.log("--- on-chain policy ---");
console.log("");
console.log("Sui Move package: 0xb0468033d854e95ad89de4b6fec8f6d8e8187778c9d8337a6aa30a5c24775a77");
console.log("Explorer:         https://testnet.suivision.xyz/package/0xb0468033d854e95ad89de4b6fec8f6d8e8187778c9d8337a6aa30a5c24775a77");
console.log("Modules:          policy, custody");
console.log("");

// Verify
console.log("--- verification ---");
console.log("");
console.log("5-chain verify: https://verify.frontiercompute.cash");
console.log("ZAP1 API:       https://pay.frontiercompute.io");
console.log("Chains:         Arbitrum, Base, Hyperliquid, Solana, NEAR");
console.log("");

// npm package info
console.log("--- npm package ---");
console.log("");
console.log("Package: @frontiercompute/zcash-ika");
console.log("npm:     https://www.npmjs.com/package/@frontiercompute/zcash-ika");
console.log("");

// List exports from the actual package via dynamic import
async function listExports() {
  try {
    const mod = await import("@frontiercompute/zcash-ika");
    const names = Object.keys(mod).sort();
    console.log("Exports (" + names.length + "):");
    // Print in columns
    const cols = 3;
    const rows = Math.ceil(names.length / cols);
    for (let r = 0; r < rows; r++) {
      const parts = [];
      for (let c = 0; c < cols; c++) {
        const idx = r + c * rows;
        if (idx < names.length) {
          parts.push(names[idx].padEnd(28));
        }
      }
      console.log("  " + parts.join(""));
    }
  } catch (e) {
    // Fallback: list known exports if package not installed locally
    console.log("Exports (65 named): deriveZcashAddress, deriveBitcoinAddress, createWallet,");
    console.log("  sign, setPolicy, checkPolicy, spendTransparent, spendBitcoin,");
    console.log("  createVault, registerAgent, requestSpend, freezeVault, unfreezeVault,");
    console.log("  buildUnsignedTx, attachSignatures, broadcastTx, fetchUTXOs, selectUTXOs,");
    console.log("  buildUnsignedBtcTx, attachBtcSignatures, broadcastBtcTx, fetchBtcUTXOs,");
    console.log("  CHAIN_PARAMS, BRANCH_ID, IkaClient, IkaTransaction, Curve, Hash, ...");
    console.log("  (install package locally and re-run for full list)");
  }
  console.log("");
}

listExports();
