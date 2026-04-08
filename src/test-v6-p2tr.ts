/**
 * Tests for ZIP 246 v6 sighash and P2TR Taproot support.
 *
 * Validates structural correctness of both features.
 * Run: node dist/test-v6-p2tr.js
 */

import {
  computeSighashV6,
  BRANCH_ID,
  buildUnsignedTx,
} from "./index.js";

import {
  deriveTaprootAddress,
  p2trScript,
  buildTaprootTx,
  serializeTaprootTx,
} from "./btc-tx-builder.js";

let passed = 0;
let failed = 0;

function assert(condition: boolean, msg: string) {
  if (condition) {
    passed++;
    console.log(`  PASS: ${msg}`);
  } else {
    failed++;
    console.error(`  FAIL: ${msg}`);
  }
}

// ---------------------------------------------------------------------------
// Track 3: ZIP 246 v6 sighash tests
// ---------------------------------------------------------------------------
console.log("\n=== ZIP 246 v6 sighash ===\n");

// Test 1: computeSighashV6 produces 32-byte sighashes
{
  const utxos = [{
    txid: "a".repeat(64),
    outputIndex: 0,
    script: "76a914" + "bb".repeat(20) + "88ac",
    satoshis: 100000,
  }];

  const result = computeSighashV6({
    utxos,
    recipient: "t1N9mwrrhJbfpiZgM8mR2hNRjxbUKcdHN1u",
    amount: 50000,
    fee: 10000,
    changeAddress: "t1N9mwrrhJbfpiZgM8mR2hNRjxbUKcdHN1u",
  });

  assert(result.sighashes.length === 1, "v6 sighash: 1 input = 1 sighash");
  assert(result.sighashes[0].length === 32, "v6 sighash: sighash is 32 bytes");
  assert(result.txid.length === 32, "v6 sighash: txid is 32 bytes");
}

// Test 2: v6 sighash differs from v5 sighash (different header digest)
{
  const utxos = [{
    txid: "a".repeat(64),
    outputIndex: 0,
    script: "76a914" + "bb".repeat(20) + "88ac",
    satoshis: 100000,
  }];

  const v6 = computeSighashV6({
    utxos,
    recipient: "t1N9mwrrhJbfpiZgM8mR2hNRjxbUKcdHN1u",
    amount: 50000,
    fee: 10000,
    changeAddress: "t1N9mwrrhJbfpiZgM8mR2hNRjxbUKcdHN1u",
  });

  const v5 = buildUnsignedTx(
    utxos,
    "t1N9mwrrhJbfpiZgM8mR2hNRjxbUKcdHN1u",
    50000,
    10000,
    "t1N9mwrrhJbfpiZgM8mR2hNRjxbUKcdHN1u",
  );

  assert(
    !v6.sighashes[0].equals(v5.sighashes[0]),
    "v6 sighash differs from v5 (header includes fee + nsm)"
  );
}

// Test 3: zip233Amount affects the sighash
{
  const utxos = [{
    txid: "a".repeat(64),
    outputIndex: 0,
    script: "76a914" + "bb".repeat(20) + "88ac",
    satoshis: 100000,
  }];

  const noNsm = computeSighashV6({
    utxos,
    recipient: "t1N9mwrrhJbfpiZgM8mR2hNRjxbUKcdHN1u",
    amount: 50000,
    fee: 10000,
    changeAddress: "t1N9mwrrhJbfpiZgM8mR2hNRjxbUKcdHN1u",
    zip233Amount: 0,
  });

  const withNsm = computeSighashV6({
    utxos,
    recipient: "t1N9mwrrhJbfpiZgM8mR2hNRjxbUKcdHN1u",
    amount: 50000,
    fee: 10000,
    changeAddress: "t1N9mwrrhJbfpiZgM8mR2hNRjxbUKcdHN1u",
    zip233Amount: 5000,
  });

  assert(
    !noNsm.sighashes[0].equals(withNsm.sighashes[0]),
    "zip233Amount=5000 produces different sighash than 0"
  );
}

// Test 4: multiple inputs produce correct number of sighashes
{
  const utxos = [
    { txid: "a".repeat(64), outputIndex: 0, script: "76a914" + "bb".repeat(20) + "88ac", satoshis: 50000 },
    { txid: "c".repeat(64), outputIndex: 1, script: "76a914" + "dd".repeat(20) + "88ac", satoshis: 60000 },
  ];

  const result = computeSighashV6({
    utxos,
    recipient: "t1N9mwrrhJbfpiZgM8mR2hNRjxbUKcdHN1u",
    amount: 80000,
    fee: 10000,
    changeAddress: "t1N9mwrrhJbfpiZgM8mR2hNRjxbUKcdHN1u",
  });

  assert(result.sighashes.length === 2, "v6 sighash: 2 inputs = 2 sighashes");
  assert(
    !result.sighashes[0].equals(result.sighashes[1]),
    "v6 sighash: different inputs produce different sighashes"
  );
}

// ---------------------------------------------------------------------------
// Track 4: P2TR Taproot tests
// ---------------------------------------------------------------------------
console.log("\n=== P2TR Taproot ===\n");

// Test 5: deriveTaprootAddress produces bc1p... address
{
  // Use a known x-only pubkey (32 bytes of 0x79)
  const xOnlyPubKey = new Uint8Array(32).fill(0x79);
  const addr = deriveTaprootAddress(xOnlyPubKey, "mainnet");

  assert(addr.startsWith("bc1p"), "taproot address starts with bc1p");
  assert(addr.length === 62, "taproot address is 62 chars (bech32m)");
}

// Test 6: testnet address starts with tb1p
{
  const xOnlyPubKey = new Uint8Array(32).fill(0x42);
  const addr = deriveTaprootAddress(xOnlyPubKey, "testnet");

  assert(addr.startsWith("tb1p"), "testnet taproot address starts with tb1p");
}

// Test 7: deriveTaprootAddress rejects wrong-size key
{
  try {
    deriveTaprootAddress(new Uint8Array(33), "mainnet");
    assert(false, "should reject 33-byte key");
  } catch {
    assert(true, "rejects 33-byte key for taproot address");
  }
}

// Test 8: p2trScript produces correct scriptPubKey
{
  const xOnly = new Uint8Array(32).fill(0xab);
  const script = p2trScript(xOnly);

  assert(script.length === 34, "P2TR scriptPubKey is 34 bytes");
  assert(script[0] === 0x51, "P2TR script starts with OP_1");
  assert(script[1] === 0x20, "P2TR script has push 32 opcode");
  assert(script.subarray(2).every((b, i) => b === 0xab), "P2TR script contains x-only pubkey");
}

// Test 9: buildTaprootTx produces sighashes
{
  const xOnly = new Uint8Array(32).fill(0x11);
  const p2trSPK = p2trScript(xOnly).toString("hex");

  const result = buildTaprootTx({
    inputs: [{
      prevTxid: "b".repeat(64),
      prevIndex: 0,
      value: 100000,
      scriptPubKey: p2trSPK,
    }],
    outputs: [{ address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", value: 80000 }],
    fee: 1000,
    changeXOnlyPubKey: xOnly,
  });

  assert(result.sighashes.length === 1, "taproot tx: 1 input = 1 sighash");
  assert(result.sighashes[0].length === 32, "taproot sighash is 32 bytes");
  assert(result.outputs.length === 2, "taproot tx: 1 payment + 1 change output");
}

// Test 10: serializeTaprootTx produces valid segwit transaction
{
  const xOnly = new Uint8Array(32).fill(0x22);
  const p2trSPK = p2trScript(xOnly).toString("hex");

  const { inputs, outputs } = buildTaprootTx({
    inputs: [{
      prevTxid: "d".repeat(64),
      prevIndex: 0,
      value: 50000,
      scriptPubKey: p2trSPK,
    }],
    outputs: [{ address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", value: 40000 }],
    fee: 500,
    changeXOnlyPubKey: xOnly,
  });

  // Fake 64-byte schnorr signature
  const fakeSig = Buffer.alloc(64, 0xff);
  const txBytes = serializeTaprootTx(inputs, outputs, [fakeSig]);

  assert(txBytes.length > 0, "serialized taproot tx is non-empty");
  // Check segwit marker
  assert(txBytes[4] === 0x00 && txBytes[5] === 0x01, "segwit marker+flag present");
  // Version 2
  assert(txBytes.readUInt32LE(0) === 2, "tx version is 2");
}

// Test 11: serializeTaprootTx rejects wrong signature size
{
  const xOnly = new Uint8Array(32).fill(0x33);
  const p2trSPK = p2trScript(xOnly).toString("hex");

  const { inputs, outputs } = buildTaprootTx({
    inputs: [{
      prevTxid: "e".repeat(64),
      prevIndex: 0,
      value: 50000,
      scriptPubKey: p2trSPK,
    }],
    outputs: [{ address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", value: 40000 }],
    fee: 500,
    changeXOnlyPubKey: xOnly,
  });

  try {
    serializeTaprootTx(inputs, outputs, [Buffer.alloc(72, 0xff)]);
    assert(false, "should reject non-64-byte signature");
  } catch {
    assert(true, "rejects non-64-byte schnorr signature");
  }
}

// Test 12: deterministic address derivation
{
  const xOnly = new Uint8Array(32);
  for (let i = 0; i < 32; i++) xOnly[i] = i;
  const addr1 = deriveTaprootAddress(xOnly, "mainnet");
  const addr2 = deriveTaprootAddress(xOnly, "mainnet");
  assert(addr1 === addr2, "taproot address derivation is deterministic");
}

// Summary
console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
if (failed > 0) process.exit(1);
