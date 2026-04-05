/**
 * Bitcoin P2PKH transaction builder.
 *
 * Builds legacy (non-segwit) P2PKH transactions for MPC-signed spends.
 * The signing itself happens via Ika dWallet (secp256k1 ECDSA).
 * This module handles UTXO fetch, TX structure, sighash computation,
 * signature attachment, and broadcast via Blockstream API.
 */

import { createHash } from "node:crypto";

// SIGHASH flags
const SIGHASH_ALL = 0x01;

// Script opcodes for P2PKH
const OP_DUP = 0x76;
const OP_HASH160 = 0xa9;
const OP_EQUALVERIFY = 0x88;
const OP_CHECKSIG = 0xac;

// Bitcoin address version bytes
const BTC_ADDR_VERSION: Record<string, number> = {
  mainnet: 0x00,
  testnet: 0x6f,
};

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export type BtcNetwork = "mainnet" | "testnet";

export interface BtcUTXO {
  txid: string;
  vout: number;
  scriptPubKey: string; // hex
  value: number;        // satoshis
}

export interface BtcTxOutput {
  address: string;
  value: number; // satoshis
}

// Internal types
interface BtcInput {
  prevTxid: Buffer;   // 32 bytes, reversed
  prevIndex: number;
  scriptPubKey: Buffer;
  value: number;
  sequence: number;
}

interface BtcOutput {
  value: number;
  script: Buffer;
}

function sha256(data: Uint8Array): Buffer {
  return createHash("sha256").update(data).digest();
}

function doubleSha256(data: Uint8Array): Buffer {
  return sha256(sha256(data));
}

function hash160(data: Uint8Array): Buffer {
  return createHash("ripemd160").update(sha256(data)).digest();
}

// Write uint32 little-endian
function writeU32LE(buf: Buffer, value: number, offset: number): void {
  buf.writeUInt32LE(value >>> 0, offset);
}

// Write int64 little-endian (as two uint32s, safe for values < 2^53)
function writeI64LE(buf: Buffer, value: number, offset: number): void {
  buf.writeUInt32LE(value & 0xffffffff, offset);
  buf.writeUInt32LE(Math.floor(value / 0x100000000) & 0xffffffff, offset + 4);
}

// Compact size encoding (Bitcoin varint)
function compactSize(n: number): Buffer {
  if (n < 0xfd) {
    return Buffer.from([n]);
  } else if (n <= 0xffff) {
    const buf = Buffer.alloc(3);
    buf[0] = 0xfd;
    buf.writeUInt16LE(n, 1);
    return buf;
  } else {
    const buf = Buffer.alloc(5);
    buf[0] = 0xfe;
    buf.writeUInt32LE(n, 1);
    return buf;
  }
}

// Reverse a hex-encoded txid (Bitcoin internal byte order is reversed)
function reverseTxid(txid: string): Buffer {
  const buf = Buffer.from(txid, "hex");
  if (buf.length !== 32) throw new Error(`Invalid txid length: ${buf.length}`);
  return Buffer.from(buf.reverse());
}

// Decode a Bitcoin base58check address to its 20-byte pubkey hash
function decodeBtcAddress(addr: string): { pubkeyHash: Buffer; network: BtcNetwork } {
  let num = BigInt(0);
  for (const c of addr) {
    const idx = BASE58_ALPHABET.indexOf(c);
    if (idx < 0) throw new Error(`Invalid base58 character: ${c}`);
    num = num * 58n + BigInt(idx);
  }

  // 25 bytes: 1 version + 20 hash + 4 checksum
  const bytes = new Uint8Array(25);
  for (let i = 24; i >= 0; i--) {
    bytes[i] = Number(num & 0xffn);
    num = num >> 8n;
  }

  // Verify checksum
  const payload = bytes.subarray(0, 21);
  const checksum = doubleSha256(payload).subarray(0, 4);
  for (let i = 0; i < 4; i++) {
    if (bytes[21 + i] !== checksum[i]) {
      throw new Error(`Invalid address checksum: ${addr}`);
    }
  }

  const version = bytes[0];
  let network: BtcNetwork;
  if (version === BTC_ADDR_VERSION.mainnet) {
    network = "mainnet";
  } else if (version === BTC_ADDR_VERSION.testnet) {
    network = "testnet";
  } else {
    throw new Error(`Unknown address version byte: 0x${version.toString(16)}`);
  }

  return {
    pubkeyHash: Buffer.from(bytes.subarray(1, 21)),
    network,
  };
}

// Build a P2PKH scriptPubKey from a 20-byte pubkey hash
function p2pkhScript(pubkeyHash: Buffer): Buffer {
  const script = Buffer.alloc(25);
  script[0] = OP_DUP;
  script[1] = OP_HASH160;
  script[2] = 0x14; // push 20 bytes
  pubkeyHash.copy(script, 3);
  script[23] = OP_EQUALVERIFY;
  script[24] = OP_CHECKSIG;
  return script;
}

// Build P2PKH scriptPubKey from a Bitcoin address string
function scriptFromAddress(addr: string): Buffer {
  const { pubkeyHash } = decodeBtcAddress(addr);
  return p2pkhScript(pubkeyHash);
}

// Blockstream API base URL
function apiBase(network: BtcNetwork): string {
  return network === "mainnet"
    ? "https://blockstream.info/api"
    : "https://blockstream.info/testnet/api";
}

/**
 * Fetch UTXOs for a Bitcoin P2PKH address from Blockstream API.
 */
export async function fetchBtcUTXOs(
  address: string,
  network: BtcNetwork = "mainnet"
): Promise<BtcUTXO[]> {
  const base = apiBase(network);
  const resp = await fetch(`${base}/address/${address}/utxo`);
  if (!resp.ok) {
    throw new Error(`Blockstream API error: ${resp.status} ${resp.statusText}`);
  }

  const data = (await resp.json()) as any[];

  // Blockstream returns {txid, vout, status, value} but no scriptPubKey.
  // For P2PKH we can derive scriptPubKey from the address.
  const { pubkeyHash } = decodeBtcAddress(address);
  const script = p2pkhScript(pubkeyHash).toString("hex");

  return data.map((u: any) => ({
    txid: u.txid,
    vout: u.vout,
    scriptPubKey: script,
    value: u.value,
  }));
}

/**
 * Estimate transaction size in bytes for P2PKH.
 * ~148 bytes per input, ~34 bytes per output, 10 bytes overhead.
 */
export function estimateBtcFee(
  numInputs: number,
  numOutputs: number,
  feeRate: number // sat/vbyte
): number {
  const size = 10 + numInputs * 148 + numOutputs * 34;
  return Math.ceil(size * feeRate);
}

/**
 * Select UTXOs to cover the target amount + estimated fee.
 * Greedy largest-first selection. Re-estimates fee after selection.
 */
export function selectBtcUTXOs(
  utxos: BtcUTXO[],
  targetAmount: number,
  feeRate: number // sat/vbyte
): { selected: BtcUTXO[]; fee: number; totalInput: number } {
  const sorted = [...utxos].sort((a, b) => b.value - a.value);

  const selected: BtcUTXO[] = [];
  let total = 0;

  // Initial estimate: 1 output + 1 change output
  for (const u of sorted) {
    selected.push(u);
    total += u.value;
    const fee = estimateBtcFee(selected.length, 2, feeRate);
    if (total >= targetAmount + fee) break;
  }

  const fee = estimateBtcFee(selected.length, 2, feeRate);
  if (total < targetAmount + fee) {
    throw new Error(
      `Insufficient funds: have ${total} sats, need ${targetAmount + fee} (${targetAmount} + ${fee} fee)`
    );
  }

  return { selected, fee, totalInput: total };
}

/**
 * Compute the legacy P2PKH sighash for a specific input.
 *
 * For each input being signed:
 * 1. Copy the transaction
 * 2. Set all input scriptSigs to empty
 * 3. Set the current input's scriptSig to the previous output's scriptPubKey
 * 4. Append SIGHASH_ALL (0x01000000) as 4 bytes LE
 * 5. Double-SHA256 the result
 */
export function computeBtcSighash(
  inputs: BtcInput[],
  outputs: BtcOutput[],
  inputIndex: number,
  hashType: number = SIGHASH_ALL
): Buffer {
  const parts: Buffer[] = [];

  // version
  const ver = Buffer.alloc(4);
  writeU32LE(ver, 1, 0);
  parts.push(ver);

  // input count
  parts.push(compactSize(inputs.length));

  // inputs
  for (let i = 0; i < inputs.length; i++) {
    const inp = inputs[i];
    // prevout (txid + vout)
    const outpoint = Buffer.alloc(36);
    inp.prevTxid.copy(outpoint, 0);
    writeU32LE(outpoint, inp.prevIndex, 32);
    parts.push(outpoint);

    // scriptSig: empty for all inputs except the one being signed
    if (i === inputIndex) {
      parts.push(compactSize(inp.scriptPubKey.length));
      parts.push(inp.scriptPubKey);
    } else {
      parts.push(compactSize(0));
    }

    // sequence
    const seq = Buffer.alloc(4);
    writeU32LE(seq, inp.sequence, 0);
    parts.push(seq);
  }

  // output count
  parts.push(compactSize(outputs.length));

  // outputs
  for (const out of outputs) {
    const valueBuf = Buffer.alloc(8);
    writeI64LE(valueBuf, out.value, 0);
    parts.push(valueBuf);
    parts.push(compactSize(out.script.length));
    parts.push(out.script);
  }

  // locktime
  const lt = Buffer.alloc(4);
  writeU32LE(lt, 0, 0);
  parts.push(lt);

  // Append hash type as 4 bytes LE
  const ht = Buffer.alloc(4);
  writeU32LE(ht, hashType, 0);
  parts.push(ht);

  return doubleSha256(Buffer.concat(parts));
}

/**
 * Build an unsigned Bitcoin P2PKH transaction.
 *
 * Returns the per-input sighashes that need to be signed via MPC,
 * plus the internal tx structure needed for signature attachment.
 */
export function buildUnsignedBtcTx(
  utxos: BtcUTXO[],
  txOutputs: BtcTxOutput[],
  changeAddress: string,
  fee: number
): { sighashes: Buffer[]; inputs: BtcInput[]; outputs: BtcOutput[] } {
  if (utxos.length === 0) throw new Error("No UTXOs provided");

  // Build inputs
  const inputs: BtcInput[] = utxos.map((u) => ({
    prevTxid: reverseTxid(u.txid),
    prevIndex: u.vout,
    scriptPubKey: Buffer.from(u.scriptPubKey, "hex"),
    value: u.value,
    sequence: 0xffffffff,
  }));

  // Build outputs
  const totalInput = utxos.reduce((s, u) => s + u.value, 0);
  const totalOutput = txOutputs.reduce((s, o) => s + o.value, 0);
  const change = totalInput - totalOutput - fee;

  const outputs: BtcOutput[] = txOutputs.map((o) => ({
    value: o.value,
    script: scriptFromAddress(o.address),
  }));

  if (change > 0) {
    // Dust threshold: skip change if below 546 satoshis
    if (change >= 546) {
      outputs.push({ value: change, script: scriptFromAddress(changeAddress) });
    }
  } else if (change < 0) {
    throw new Error(
      `UTXOs total ${totalInput} < outputs ${totalOutput} + fee ${fee}`
    );
  }

  // Compute per-input sighashes
  const sighashes: Buffer[] = [];
  for (let i = 0; i < inputs.length; i++) {
    sighashes.push(computeBtcSighash(inputs, outputs, i, SIGHASH_ALL));
  }

  return { sighashes, inputs, outputs };
}

/**
 * Build a P2PKH scriptSig from a DER signature and compressed pubkey.
 *
 * Format: <sig_length> <DER_sig + SIGHASH_ALL_byte> <pubkey_length> <compressed_pubkey>
 */
function buildScriptSig(derSig: Buffer, pubkey: Buffer): Buffer {
  const sigWithHashType = Buffer.concat([derSig, Buffer.from([SIGHASH_ALL])]);
  const parts: Buffer[] = [
    Buffer.from([sigWithHashType.length]),
    sigWithHashType,
    Buffer.from([pubkey.length]),
    pubkey,
  ];
  return Buffer.concat(parts);
}

/**
 * Attach DER signatures to an unsigned transaction.
 * Returns the fully serialized signed transaction as a Buffer.
 */
export function attachBtcSignatures(
  inputs: BtcInput[],
  outputs: BtcOutput[],
  signatures: Buffer[],
  pubkey: Buffer
): Buffer {
  if (signatures.length !== inputs.length) {
    throw new Error(
      `Expected ${inputs.length} signatures, got ${signatures.length}`
    );
  }
  if (pubkey.length !== 33) {
    throw new Error(`Expected 33-byte compressed pubkey, got ${pubkey.length}`);
  }

  const scriptSigs = signatures.map((sig) => buildScriptSig(sig, pubkey));
  return serializeBtcTx(inputs, outputs, scriptSigs);
}

/**
 * Serialize a Bitcoin transaction (version 1, no witness).
 * If scriptSigs is provided, inputs get signed scriptSigs.
 * Otherwise inputs get empty scriptSigs (unsigned).
 */
export function serializeBtcTx(
  inputs: BtcInput[],
  outputs: BtcOutput[],
  scriptSigs?: Buffer[]
): Buffer {
  const parts: Buffer[] = [];

  // version: 4 bytes LE
  const ver = Buffer.alloc(4);
  writeU32LE(ver, 1, 0);
  parts.push(ver);

  // input count
  parts.push(compactSize(inputs.length));

  // inputs
  for (let i = 0; i < inputs.length; i++) {
    const inp = inputs[i];
    // prevout
    const outpoint = Buffer.alloc(36);
    inp.prevTxid.copy(outpoint, 0);
    writeU32LE(outpoint, inp.prevIndex, 32);
    parts.push(outpoint);

    // scriptSig
    const sig = scriptSigs ? scriptSigs[i] : Buffer.alloc(0);
    parts.push(compactSize(sig.length));
    if (sig.length > 0) parts.push(sig);

    // sequence
    const seq = Buffer.alloc(4);
    writeU32LE(seq, inp.sequence, 0);
    parts.push(seq);
  }

  // output count
  parts.push(compactSize(outputs.length));

  // outputs
  for (const out of outputs) {
    const valueBuf = Buffer.alloc(8);
    writeI64LE(valueBuf, out.value, 0);
    parts.push(valueBuf);
    parts.push(compactSize(out.script.length));
    parts.push(out.script);
  }

  // locktime: 4 bytes LE
  const lt = Buffer.alloc(4);
  writeU32LE(lt, 0, 0);
  parts.push(lt);

  return Buffer.concat(parts);
}

/**
 * Broadcast a signed transaction via Blockstream API.
 * Returns the txid on success.
 */
export async function broadcastBtcTx(
  rawHex: string,
  network: BtcNetwork = "mainnet"
): Promise<string> {
  const base = apiBase(network);
  const resp = await fetch(`${base}/tx`, {
    method: "POST",
    headers: { "Content-Type": "text/plain" },
    body: rawHex,
  });

  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`Broadcast failed: ${resp.status} ${body}`);
  }

  // Blockstream returns the txid as plain text
  return (await resp.text()).trim();
}
