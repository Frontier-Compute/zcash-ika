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
  if (fee < 0) throw new Error("Fee must be non-negative");

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

  // Warn on dust outputs (let the network reject them)
  for (const out of outputs) {
    if (out.value < 546) {
      console.warn(`Warning: output value ${out.value} sats is below dust threshold (546)`);
    }
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


// ---------------------------------------------------------------------------
// P2TR (Taproot) key-path spend support (BIP 340/341/350)
// ---------------------------------------------------------------------------

// Bech32m charset
const BECH32M_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST = 0x2bc830a3;

function bech32mPolymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((b >> i) & 1) chk ^= GEN[i];
    }
  }
  return chk;
}

function bech32mHrpExpand(hrp: string): number[] {
  const ret: number[] = [];
  for (const c of hrp) ret.push(c.charCodeAt(0) >> 5);
  ret.push(0);
  for (const c of hrp) ret.push(c.charCodeAt(0) & 31);
  return ret;
}

function bech32mCreateChecksum(hrp: string, data: number[]): number[] {
  const values = bech32mHrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
  const polymod = bech32mPolymod(values) ^ BECH32M_CONST;
  const ret: number[] = [];
  for (let i = 0; i < 6; i++) {
    ret.push((polymod >> (5 * (5 - i))) & 31);
  }
  return ret;
}

function bech32mEncode(hrp: string, data: number[]): string {
  const checksum = bech32mCreateChecksum(hrp, data);
  const combined = data.concat(checksum);
  let ret = hrp + "1";
  for (const d of combined) ret += BECH32M_CHARSET[d];
  return ret;
}

function convertBits(data: Uint8Array, fromBits: number, toBits: number, pad: boolean): number[] {
  let acc = 0;
  let bits = 0;
  const ret: number[] = [];
  const maxv = (1 << toBits) - 1;
  for (const value of data) {
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) ret.push((acc << (toBits - bits)) & maxv);
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) {
    throw new Error("Invalid bit conversion");
  }
  return ret;
}

/**
 * Derive a P2TR (Taproot) bech32m address from an x-only public key.
 *
 * BIP 341 defines P2TR output as: OP_1 <32-byte-x-only-pubkey>
 * The address is bech32m encoded with witness version 1.
 *
 * For key-path-only spending (no script tree), the output key equals
 * the internal key tweaked with an empty merkle root:
 *   Q = P + H("TapTweak", P) * G
 *
 * This function takes the already-tweaked x-only pubkey (32 bytes).
 * If using an MPC-derived key, perform the taptweak externally before
 * calling this function.
 */
export function deriveTaprootAddress(
  xOnlyPubKey: Uint8Array,
  network: BtcNetwork = "mainnet"
): string {
  if (xOnlyPubKey.length !== 32) {
    throw new Error("Expected 32-byte x-only pubkey, got " + xOnlyPubKey.length);
  }
  const hrp = network === "mainnet" ? "bc" : "tb";
  const witnessVersion = 1;
  const data5bit = convertBits(xOnlyPubKey, 8, 5, true);
  return bech32mEncode(hrp, [witnessVersion].concat(data5bit));
}

/**
 * Build a P2TR scriptPubKey from a 32-byte x-only public key.
 * Format: OP_1 <0x20> <32-byte-x-only-pubkey>
 */
export function p2trScript(xOnlyPubKey: Uint8Array): Buffer {
  if (xOnlyPubKey.length !== 32) {
    throw new Error("Expected 32-byte x-only pubkey, got " + xOnlyPubKey.length);
  }
  const script = Buffer.alloc(34);
  script[0] = 0x51; // OP_1 (witness v1)
  script[1] = 0x20; // push 32 bytes
  Buffer.from(xOnlyPubKey).copy(script, 2);
  return script;
}

// BIP 340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
function taggedHash(tag: string, ...msgs: Uint8Array[]): Buffer {
  const tagHash = sha256(Buffer.from(tag, "utf8"));
  const parts: Uint8Array[] = [tagHash, tagHash, ...msgs];
  return sha256(Buffer.concat(parts));
}

export interface TaprootInput {
  prevTxid: string;     // hex txid (display order)
  prevIndex: number;
  value: number;        // satoshis
  scriptPubKey: string; // hex P2TR scriptPubKey of the UTXO
}

export interface TaprootTxParams {
  inputs: TaprootInput[];
  outputs: BtcTxOutput[];
  changeAddress?: string;
  fee: number;
  /** x-only pubkey for change output P2TR script (32 bytes) */
  changeXOnlyPubKey?: Uint8Array;
}

/**
 * Compute BIP 341 taproot sighash for key-path spending.
 * Uses SIGHASH_DEFAULT (0x00) which commits to all inputs and outputs.
 * The epoch byte (0x00) is prepended per BIP 341.
 */
function computeTaprootSighash(
  inputs: { prevTxid: Buffer; prevIndex: number; value: number; scriptPubKey: Buffer; sequence: number }[],
  outputs: BtcOutput[],
  inputIndex: number,
  hashType: number = 0x00
): Buffer {
  const parts: Buffer[] = [];

  // Epoch
  parts.push(Buffer.from([0x00]));
  // Hash type
  parts.push(Buffer.from([hashType]));

  // Transaction version: 2
  const ver = Buffer.alloc(4);
  writeU32LE(ver, 2, 0);
  parts.push(ver);

  // nLockTime
  const lt = Buffer.alloc(4);
  writeU32LE(lt, 0, 0);
  parts.push(lt);

  // sha_prevouts
  const prevoutsData: Buffer[] = [];
  for (const inp of inputs) {
    const outpoint = Buffer.alloc(36);
    inp.prevTxid.copy(outpoint, 0);
    writeU32LE(outpoint, inp.prevIndex, 32);
    prevoutsData.push(outpoint);
  }
  parts.push(sha256(Buffer.concat(prevoutsData)));

  // sha_amounts
  const amountsData = Buffer.alloc(inputs.length * 8);
  for (let i = 0; i < inputs.length; i++) {
    writeI64LE(amountsData, inputs[i].value, i * 8);
  }
  parts.push(sha256(amountsData));

  // sha_scriptpubkeys
  const scriptsData: Buffer[] = [];
  for (const inp of inputs) {
    scriptsData.push(compactSize(inp.scriptPubKey.length));
    scriptsData.push(inp.scriptPubKey);
  }
  parts.push(sha256(Buffer.concat(scriptsData)));

  // sha_sequences
  const seqData = Buffer.alloc(inputs.length * 4);
  for (let i = 0; i < inputs.length; i++) {
    writeU32LE(seqData, inputs[i].sequence, i * 4);
  }
  parts.push(sha256(seqData));

  // sha_outputs
  const outsData: Buffer[] = [];
  for (const out of outputs) {
    const valueBuf = Buffer.alloc(8);
    writeI64LE(valueBuf, out.value, 0);
    outsData.push(valueBuf);
    outsData.push(compactSize(out.script.length));
    outsData.push(out.script);
  }
  parts.push(sha256(Buffer.concat(outsData)));

  // spend_type: 0x00 (key-path, no annex)
  parts.push(Buffer.from([0x00]));

  // Input index
  const idxBuf = Buffer.alloc(4);
  writeU32LE(idxBuf, inputIndex, 0);
  parts.push(idxBuf);

  return taggedHash("TapSighash", Buffer.concat(parts));
}

/**
 * Build an unsigned P2TR (Taproot) key-path spend transaction.
 *
 * Returns per-input sighashes for BIP 340 Schnorr signing.
 * The witness for key-path spend is a single 64-byte Schnorr signature
 * (no sighash type byte appended for SIGHASH_DEFAULT).
 *
 * Transaction version is 2 (segwit). Uses witness serialization.
 */
export function buildTaprootTx(params: TaprootTxParams): {
  sighashes: Buffer[];
  inputs: { prevTxid: Buffer; prevIndex: number; value: number; scriptPubKey: Buffer; sequence: number }[];
  outputs: BtcOutput[];
} {
  const { inputs: rawInputs, outputs: txOutputs, fee, changeAddress, changeXOnlyPubKey } = params;

  if (rawInputs.length === 0) throw new Error("No inputs provided");

  const inputs = rawInputs.map((inp) => ({
    prevTxid: reverseTxid(inp.prevTxid),
    prevIndex: inp.prevIndex,
    value: inp.value,
    scriptPubKey: Buffer.from(inp.scriptPubKey, "hex"),
    sequence: 0xfffffffd, // RBF-enabled default
  }));

  const totalInput = rawInputs.reduce((s, u) => s + u.value, 0);
  const totalOutput = txOutputs.reduce((s, o) => s + o.value, 0);
  const change = totalInput - totalOutput - fee;

  const outputs: BtcOutput[] = txOutputs.map((o) => ({
    value: o.value,
    script: scriptFromAddress(o.address),
  }));

  if (change > 0 && change >= 546) {
    if (changeXOnlyPubKey) {
      outputs.push({ value: change, script: p2trScript(changeXOnlyPubKey) });
    } else if (changeAddress) {
      outputs.push({ value: change, script: scriptFromAddress(changeAddress) });
    }
  } else if (change < 0) {
    throw new Error("Inputs total " + totalInput + " < outputs " + totalOutput + " + fee " + fee);
  }

  const sighashes: Buffer[] = [];
  for (let i = 0; i < inputs.length; i++) {
    sighashes.push(computeTaprootSighash(inputs, outputs, i));
  }

  return { sighashes, inputs, outputs };
}

/**
 * Serialize a signed Taproot transaction (segwit v1 with witness).
 *
 * Each input witness is a single stack item: the 64-byte Schnorr signature
 * (for SIGHASH_DEFAULT, no sighash byte is appended).
 */
export function serializeTaprootTx(
  inputs: { prevTxid: Buffer; prevIndex: number; value: number; scriptPubKey: Buffer; sequence: number }[],
  outputs: BtcOutput[],
  schnorrSigs: Buffer[]
): Buffer {
  if (schnorrSigs.length !== inputs.length) {
    throw new Error("Expected " + inputs.length + " signatures, got " + schnorrSigs.length);
  }

  const parts: Buffer[] = [];

  // Version: 2
  const ver = Buffer.alloc(4);
  writeU32LE(ver, 2, 0);
  parts.push(ver);

  // Segwit marker + flag
  parts.push(Buffer.from([0x00, 0x01]));

  // Input count
  parts.push(compactSize(inputs.length));

  // Inputs (empty scriptSig for segwit)
  for (const inp of inputs) {
    const outpoint = Buffer.alloc(36);
    inp.prevTxid.copy(outpoint, 0);
    writeU32LE(outpoint, inp.prevIndex, 32);
    parts.push(outpoint);
    parts.push(compactSize(0));
    const seq = Buffer.alloc(4);
    writeU32LE(seq, inp.sequence, 0);
    parts.push(seq);
  }

  // Output count
  parts.push(compactSize(outputs.length));

  // Outputs
  for (const out of outputs) {
    const valueBuf = Buffer.alloc(8);
    writeI64LE(valueBuf, out.value, 0);
    parts.push(valueBuf);
    parts.push(compactSize(out.script.length));
    parts.push(out.script);
  }

  // Witness data
  for (const sig of schnorrSigs) {
    if (sig.length !== 64) {
      throw new Error("Schnorr signature must be 64 bytes, got " + sig.length);
    }
    parts.push(Buffer.from([0x01])); // 1 witness item
    parts.push(compactSize(sig.length));
    parts.push(sig);
  }

  // Locktime
  const lt = Buffer.alloc(4);
  writeU32LE(lt, 0, 0);
  parts.push(lt);

  return Buffer.concat(parts);
}
