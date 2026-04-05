/**
 * Zcash v5 transparent transaction builder with ZIP 244 sighash.
 *
 * Builds P2PKH transactions for MPC-signed transparent spends.
 * The signing itself happens via Ika dWallet (secp256k1 ECDSA).
 * This module handles everything else: UTXO fetch, TX structure,
 * sighash computation, signature attachment, and broadcast.
 */

import blakejs from "blakejs";
const { blake2bInit, blake2bUpdate, blake2bFinal } = blakejs;
import { createHash } from "node:crypto";

// Zcash v5 transaction constants
const TX_VERSION = 5;
const TX_VERSION_GROUP_ID = 0x26a7270a;

// Consensus branch IDs
export const BRANCH_ID = {
  NU5: 0xc2d6d0b4,
  NU6: 0xc8e71055,
  NU61: 0x4dec4df0,
} as const;

// SIGHASH flags
const SIGHASH_ALL = 0x01;

// Script opcodes for P2PKH
const OP_DUP = 0x76;
const OP_HASH160 = 0xa9;
const OP_EQUALVERIFY = 0x88;
const OP_CHECKSIG = 0xac;

// Zcash t-address version prefixes (for decoding)
const T_ADDR_VERSIONS: Record<string, { mainnet: boolean }> = {
  "1cb8": { mainnet: true },   // t1...
  "1d25": { mainnet: false },  // tm...
};

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export interface UTXO {
  txid: string;
  outputIndex: number;
  script: string;   // hex-encoded scriptPubKey
  satoshis: number;
}

export interface TxOutput {
  address: string;
  amount: number;  // satoshis (zatoshis)
}

function sha256(data: Uint8Array): Buffer {
  return createHash("sha256").update(data).digest();
}

function hash160(data: Uint8Array): Buffer {
  return createHash("ripemd160").update(sha256(data)).digest();
}

// BLAKE2b-256 with personalization
// blakejs types don't expose the personal param on blake2bInit, but the JS does
function blake2b256(data: Uint8Array, personal: Uint8Array): Buffer {
  const ctx = (blake2bInit as any)(32, undefined, undefined, personal);
  blake2bUpdate(ctx, data);
  return Buffer.from(blake2bFinal(ctx));
}

// Write uint32 little-endian into buffer
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

// Decode a Zcash t-address to its 20-byte pubkey hash
function decodeTAddress(addr: string): { pubkeyHash: Buffer; mainnet: boolean } {
  // Base58 decode
  let num = BigInt(0);
  for (const c of addr) {
    const idx = BASE58_ALPHABET.indexOf(c);
    if (idx < 0) throw new Error(`Invalid base58 character: ${c}`);
    num = num * 58n + BigInt(idx);
  }

  // Convert to bytes (26 bytes: 2 version + 20 hash + 4 checksum)
  const bytes = new Uint8Array(26);
  for (let i = 25; i >= 0; i--) {
    bytes[i] = Number(num & 0xffn);
    num = num >> 8n;
  }

  // Verify checksum
  const payload = bytes.subarray(0, 22);
  const checksum = sha256(sha256(payload)).subarray(0, 4);
  for (let i = 0; i < 4; i++) {
    if (bytes[22 + i] !== checksum[i]) {
      throw new Error(`Invalid t-address checksum: ${addr}`);
    }
  }

  const versionHex = Buffer.from(bytes.subarray(0, 2)).toString("hex");
  const info = T_ADDR_VERSIONS[versionHex];
  if (!info) {
    throw new Error(`Unknown t-address version: 0x${versionHex}`);
  }

  return {
    pubkeyHash: Buffer.from(bytes.subarray(2, 22)),
    mainnet: info.mainnet,
  };
}

// Build a P2PKH scriptPubKey from a 20-byte pubkey hash
function p2pkhScript(pubkeyHash: Buffer): Buffer {
  // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
  const script = Buffer.alloc(25);
  script[0] = OP_DUP;
  script[1] = OP_HASH160;
  script[2] = 0x14; // push 20 bytes
  pubkeyHash.copy(script, 3);
  script[23] = OP_EQUALVERIFY;
  script[24] = OP_CHECKSIG;
  return script;
}

// Build P2PKH scriptPubKey from a t-address string
function scriptFromAddress(addr: string): Buffer {
  const { pubkeyHash } = decodeTAddress(addr);
  return p2pkhScript(pubkeyHash);
}

// Reverse a hex-encoded txid (internal byte order is reversed)
function reverseTxid(txid: string): Buffer {
  const buf = Buffer.from(txid, "hex");
  if (buf.length !== 32) throw new Error(`Invalid txid length: ${buf.length}`);
  return Buffer.from(buf.reverse());
}

// Consensus branch ID as 4-byte LE buffer
function branchIdBytes(branchId: number): Buffer {
  const buf = Buffer.alloc(4);
  writeU32LE(buf, branchId, 0);
  return buf;
}

// ZIP 244 sighash computation for v5 transparent transactions

// Personalization string as bytes, padded/truncated to 16 bytes
function personalization(tag: string, suffix?: Buffer): Uint8Array {
  const tagBytes = Buffer.from(tag, "ascii");
  if (suffix) {
    const result = Buffer.alloc(16);
    tagBytes.copy(result, 0, 0, Math.min(tagBytes.length, 12));
    suffix.copy(result, 12, 0, 4);
    return result;
  }
  // Pad to 16 bytes with zeros
  const result = Buffer.alloc(16);
  tagBytes.copy(result, 0, 0, Math.min(tagBytes.length, 16));
  return result;
}

interface TransparentInput {
  prevTxid: Buffer;     // 32 bytes, internal byte order
  prevIndex: number;
  script: Buffer;       // scriptPubKey of the UTXO being spent
  value: number;        // satoshis
  sequence: number;
}

interface TransparentOutput {
  value: number;
  script: Buffer;
}

// Hash of all prevouts (txid + index) for transparent inputs
function hashPrevouts(inputs: TransparentInput[], branchId: number): Buffer {
  const parts: Buffer[] = [];
  for (const inp of inputs) {
    const outpoint = Buffer.alloc(36);
    inp.prevTxid.copy(outpoint, 0);
    writeU32LE(outpoint, inp.prevIndex, 32);
    parts.push(outpoint);
  }
  const data = Buffer.concat(parts);
  return blake2b256(data, personalization("ZTxIdPrevoutHash"));
}

// Hash of all input amounts
function hashAmounts(inputs: TransparentInput[], branchId: number): Buffer {
  const data = Buffer.alloc(inputs.length * 8);
  for (let i = 0; i < inputs.length; i++) {
    writeI64LE(data, inputs[i].value, i * 8);
  }
  return blake2b256(data, personalization("ZTxTrAmountsHash"));
}

// Hash of all input scriptPubKeys
function hashScriptPubKeys(inputs: TransparentInput[], branchId: number): Buffer {
  const parts: Buffer[] = [];
  for (const inp of inputs) {
    parts.push(compactSize(inp.script.length));
    parts.push(inp.script);
  }
  const data = Buffer.concat(parts);
  return blake2b256(data, personalization("ZTxTrScriptsHash"));
}

// Hash of all sequences
function hashSequences(inputs: TransparentInput[], branchId: number): Buffer {
  const data = Buffer.alloc(inputs.length * 4);
  for (let i = 0; i < inputs.length; i++) {
    writeU32LE(data, inputs[i].sequence, i * 4);
  }
  return blake2b256(data, personalization("ZTxIdSequencHash"));
}

// Hash of all transparent outputs
function hashOutputs(outputs: TransparentOutput[], branchId: number): Buffer {
  const parts: Buffer[] = [];
  for (const out of outputs) {
    const valueBuf = Buffer.alloc(8);
    writeI64LE(valueBuf, out.value, 0);
    parts.push(valueBuf);
    parts.push(compactSize(out.script.length));
    parts.push(out.script);
  }
  const data = Buffer.concat(parts);
  return blake2b256(data, personalization("ZTxIdOutputsHash"));
}

// Full transparent digest for txid (ZIP 244 T.2)
// transparent_digest = BLAKE2b("ZTxIdTranspaHash", prevouts || sequences || outputs)
function transparentDigest(
  inputs: TransparentInput[],
  outputs: TransparentOutput[],
  branchId: number
): Buffer {
  if (inputs.length === 0 && outputs.length === 0) {
    return blake2b256(Buffer.alloc(0), personalization("ZTxIdTranspaHash"));
  }
  const prevoutsDigest = hashPrevouts(inputs, branchId);
  const sequenceDigest = hashSequences(inputs, branchId);
  const outputsDigest = hashOutputs(outputs, branchId);
  return blake2b256(
    Buffer.concat([prevoutsDigest, sequenceDigest, outputsDigest]),
    personalization("ZTxIdTranspaHash")
  );
}

// Sapling digest (empty bundle)
function emptyBundleDigest(tag: string): Buffer {
  return blake2b256(Buffer.alloc(0), personalization(tag));
}

// Header digest (ZIP 244 T.1)
function headerDigest(
  version: number,
  versionGroupId: number,
  branchId: number,
  lockTime: number,
  expiryHeight: number
): Buffer {
  const data = Buffer.alloc(4 + 4 + 4 + 4 + 4);
  writeU32LE(data, (version | (1 << 31)) >>> 0, 0);
  writeU32LE(data, versionGroupId, 4);
  writeU32LE(data, branchId, 8);
  writeU32LE(data, lockTime, 12);
  writeU32LE(data, expiryHeight, 16);
  return blake2b256(data, personalization("ZTxIdHeadersHash"));
}

// Transaction digest for txid (ZIP 244 T)
function txidDigest(
  inputs: TransparentInput[],
  outputs: TransparentOutput[],
  branchId: number,
  lockTime: number,
  expiryHeight: number
): Buffer {
  const hdrDigest = headerDigest(TX_VERSION, TX_VERSION_GROUP_ID, branchId, lockTime, expiryHeight);
  const txpDigest = transparentDigest(inputs, outputs, branchId);
  const sapDigest = emptyBundleDigest("ZTxIdSaplingHash");
  const orchDigest = emptyBundleDigest("ZTxIdOrchardHash");
  return blake2b256(
    Buffer.concat([hdrDigest, txpDigest, sapDigest, orchDigest]),
    personalization("ZcashTxHash__", branchIdBytes(branchId))
  );
}

// Per-input sighash for signing (ZIP 244 signature_digest)
// Structure: BLAKE2b("ZcashTxHash_" || BRANCH_ID,
//   S.1: header_digest
//   S.2: transparent_sig_digest (NOT the txid transparent digest)
//   S.3: sapling_digest
//   S.4: orchard_digest
// )
function transparentSighash(
  inputs: TransparentInput[],
  outputs: TransparentOutput[],
  branchId: number,
  lockTime: number,
  expiryHeight: number,
  inputIndex: number,
  hashType: number
): Buffer {
  // S.1: header digest (same as T.1)
  const hdrDigest = headerDigest(TX_VERSION, TX_VERSION_GROUP_ID, branchId, lockTime, expiryHeight);

  // S.2: transparent_sig_digest
  // For SIGHASH_ALL without ANYONECANPAY:
  // S.2a: hash_type (1 byte)
  // S.2b: prevouts_sig_digest = prevouts_digest (same as T.2a)
  // S.2c: amounts_sig_digest
  // S.2d: scriptpubkeys_sig_digest
  // S.2e: sequence_sig_digest = sequence_digest (same as T.2b)
  // S.2f: outputs_sig_digest = outputs_digest (same as T.2c)
  // S.2g: txin_sig_digest (per-input)
  const prevoutsSigDigest = hashPrevouts(inputs, branchId);
  const amountsSigDigest = hashAmounts(inputs, branchId);
  const scriptpubkeysSigDigest = hashScriptPubKeys(inputs, branchId);
  const sequenceSigDigest = hashSequences(inputs, branchId);
  const outputsSigDigest = hashOutputs(outputs, branchId);

  // S.2g: txin_sig_digest for the input being signed
  const inp = inputs[inputIndex];
  const prevout = Buffer.alloc(36);
  inp.prevTxid.copy(prevout, 0);
  writeU32LE(prevout, inp.prevIndex, 32);
  const valueBuf = Buffer.alloc(8);
  writeI64LE(valueBuf, inp.value, 0);
  const seqBuf = Buffer.alloc(4);
  writeU32LE(seqBuf, inp.sequence, 0);

  const txinSigDigest = blake2b256(
    Buffer.concat([prevout, valueBuf, compactSize(inp.script.length), inp.script, seqBuf]),
    personalization("Zcash___TxInHash")
  );

  // S.2: transparent_sig_digest
  const transparentSigDigest = blake2b256(
    Buffer.concat([
      Buffer.from([hashType]),
      prevoutsSigDigest,
      amountsSigDigest,
      scriptpubkeysSigDigest,
      sequenceSigDigest,
      outputsSigDigest,
      txinSigDigest,
    ]),
    personalization("ZTxIdTranspaHash")
  );

  // S.3: sapling digest (empty)
  const sapDigest = emptyBundleDigest("ZTxIdSaplingHash");

  // S.4: orchard digest (empty)
  const orchDigest = emptyBundleDigest("ZTxIdOrchardHash");

  // Final signature_digest
  return blake2b256(
    Buffer.concat([hdrDigest, transparentSigDigest, sapDigest, orchDigest]),
    personalization("ZcashTxHash_", branchIdBytes(branchId))
  );
}

// Serialize a v5 transparent-only transaction to raw bytes.
// If scriptSigs is provided, inputs get signed scriptSigs.
// Otherwise inputs get empty scriptSigs (unsigned).
function serializeTx(
  inputs: TransparentInput[],
  outputs: TransparentOutput[],
  branchId: number,
  lockTime: number,
  expiryHeight: number,
  scriptSigs?: Buffer[]
): Buffer {
  const parts: Buffer[] = [];

  // Header
  const header = Buffer.alloc(4);
  // v5: version field encodes (version | fOverwintered flag)
  // fOverwintered = 1 << 31
  writeU32LE(header, (TX_VERSION | (1 << 31)) >>> 0, 0);
  parts.push(header);

  // nVersionGroupId
  const vgid = Buffer.alloc(4);
  writeU32LE(vgid, TX_VERSION_GROUP_ID, 0);
  parts.push(vgid);

  // nConsensusBranchId
  parts.push(branchIdBytes(branchId));

  // nLockTime
  const lt = Buffer.alloc(4);
  writeU32LE(lt, lockTime, 0);
  parts.push(lt);

  // nExpiryHeight
  const eh = Buffer.alloc(4);
  writeU32LE(eh, expiryHeight, 0);
  parts.push(eh);

  // Transparent bundle
  // tx_in_count
  parts.push(compactSize(inputs.length));

  // tx_in
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

  // tx_out_count
  parts.push(compactSize(outputs.length));

  // tx_out
  for (const out of outputs) {
    const valueBuf = Buffer.alloc(8);
    writeI64LE(valueBuf, out.value, 0);
    parts.push(valueBuf);
    parts.push(compactSize(out.script.length));
    parts.push(out.script);
  }

  // Sapling bundle (empty)
  parts.push(compactSize(0)); // nSpendsSapling
  parts.push(compactSize(0)); // nOutputsSapling

  // Orchard bundle (empty)
  parts.push(Buffer.from([0x00])); // nActionsOrchard = 0

  return Buffer.concat(parts);
}

/**
 * Fetch UTXOs for a transparent address from Zebra RPC.
 * Uses getaddressutxos (requires Zebra with -indexer flag).
 */
export async function fetchUTXOs(
  zebraRpcUrl: string,
  tAddress: string
): Promise<UTXO[]> {
  const resp = await fetch(zebraRpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "getaddressutxos",
      params: [{ addresses: [tAddress] }],
    }),
  });

  if (!resp.ok) {
    throw new Error(`Zebra RPC error: ${resp.status} ${resp.statusText}`);
  }

  const data = (await resp.json()) as any;
  if (data.error) {
    throw new Error(`Zebra RPC: ${data.error.message || JSON.stringify(data.error)}`);
  }

  const utxos: UTXO[] = (data.result || []).map((u: any) => ({
    txid: u.txid,
    outputIndex: u.outputIndex ?? u.vout ?? u.index,
    script: u.script ?? u.scriptPubKey,
    satoshis: u.satoshis ?? u.value ?? u.amount,
  }));

  return utxos;
}

/**
 * Select UTXOs to cover the target amount + fee.
 * Simple largest-first selection. Returns selected UTXOs and total value.
 */
export function selectUTXOs(
  utxos: UTXO[],
  targetAmount: number,
  fee: number
): { selected: UTXO[]; totalInput: number } {
  const needed = targetAmount + fee;
  // Sort descending by value
  const sorted = [...utxos].sort((a, b) => b.satoshis - a.satoshis);

  const selected: UTXO[] = [];
  let total = 0;
  for (const u of sorted) {
    selected.push(u);
    total += u.satoshis;
    if (total >= needed) break;
  }

  if (total < needed) {
    throw new Error(
      `Insufficient funds: have ${total} zatoshis, need ${needed} (${targetAmount} + ${fee} fee)`
    );
  }

  return { selected, totalInput: total };
}

/**
 * Build an unsigned Zcash v5 transparent transaction.
 *
 * Returns the unsigned serialized TX and per-input sighashes
 * that need to be signed via MPC.
 */
export function buildUnsignedTx(
  utxos: UTXO[],
  recipient: string,
  amount: number,
  fee: number = 10000,
  changeAddress: string,
  branchId: number = BRANCH_ID.NU61
): { unsignedTx: Buffer; sighashes: Buffer[]; txid: Buffer } {
  if (utxos.length === 0) throw new Error("No UTXOs provided");
  if (amount <= 0) throw new Error("Amount must be positive");

  // Build inputs
  const inputs: TransparentInput[] = utxos.map((u) => ({
    prevTxid: reverseTxid(u.txid),
    prevIndex: u.outputIndex,
    script: Buffer.from(u.script, "hex"),
    value: u.satoshis,
    sequence: 0xffffffff,
  }));

  // Build outputs
  const totalInput = utxos.reduce((s, u) => s + u.satoshis, 0);
  const change = totalInput - amount - fee;

  const outputs: TransparentOutput[] = [
    { value: amount, script: scriptFromAddress(recipient) },
  ];

  if (change > 0) {
    // Dust threshold: skip change if below 546 zatoshis
    if (change >= 546) {
      outputs.push({ value: change, script: scriptFromAddress(changeAddress) });
    }
  } else if (change < 0) {
    throw new Error(
      `UTXOs total ${totalInput} < amount ${amount} + fee ${fee}`
    );
  }

  const lockTime = 0;
  const expiryHeight = 0;

  // Serialize unsigned TX
  const unsignedTx = serializeTx(inputs, outputs, branchId, lockTime, expiryHeight);

  // Compute per-input sighashes
  const sighashes: Buffer[] = [];
  for (let i = 0; i < inputs.length; i++) {
    const sh = transparentSighash(
      inputs, outputs, branchId, lockTime, expiryHeight, i, SIGHASH_ALL
    );
    sighashes.push(sh);
  }

  // Compute txid (hash of unsigned TX structure per ZIP 244)
  const txid = txidDigest(inputs, outputs, branchId, lockTime, expiryHeight);

  return { unsignedTx, sighashes, txid };
}

/**
 * Build a P2PKH scriptSig from a DER signature and compressed pubkey.
 *
 * Format: <sig_length> <DER_sig + SIGHASH_ALL_byte> <pubkey_length> <compressed_pubkey>
 */
function buildScriptSig(derSig: Buffer, pubkey: Buffer): Buffer {
  // Append SIGHASH_ALL byte to signature
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
 * Attach MPC signatures to an unsigned transaction.
 *
 * Takes the original UTXO list (to reconstruct inputs/outputs),
 * DER-encoded signatures from MPC, and the compressed pubkey.
 * Returns hex-encoded signed transaction ready for broadcast.
 */
export function attachSignatures(
  utxos: UTXO[],
  recipient: string,
  amount: number,
  fee: number,
  changeAddress: string,
  signatures: Buffer[],
  pubkey: Buffer,
  branchId: number = BRANCH_ID.NU61
): string {
  if (signatures.length !== utxos.length) {
    throw new Error(
      `Expected ${utxos.length} signatures, got ${signatures.length}`
    );
  }
  if (pubkey.length !== 33) {
    throw new Error(`Expected 33-byte compressed pubkey, got ${pubkey.length}`);
  }

  // Rebuild inputs/outputs (same as buildUnsignedTx)
  const inputs: TransparentInput[] = utxos.map((u) => ({
    prevTxid: reverseTxid(u.txid),
    prevIndex: u.outputIndex,
    script: Buffer.from(u.script, "hex"),
    value: u.satoshis,
    sequence: 0xffffffff,
  }));

  const totalInput = utxos.reduce((s, u) => s + u.satoshis, 0);
  const change = totalInput - amount - fee;

  const outputs: TransparentOutput[] = [
    { value: amount, script: scriptFromAddress(recipient) },
  ];

  if (change >= 546) {
    outputs.push({ value: change, script: scriptFromAddress(changeAddress) });
  }

  // Build scriptSigs
  const scriptSigs = signatures.map((sig) => buildScriptSig(sig, pubkey));

  // Serialize signed TX
  const signedTx = serializeTx(
    inputs, outputs, branchId, 0, 0, scriptSigs
  );

  return signedTx.toString("hex");
}

/**
 * Broadcast a signed transaction via Zebra RPC.
 * Returns the txid on success.
 */
export async function broadcastTx(
  zebraRpcUrl: string,
  txHex: string
): Promise<string> {
  const resp = await fetch(zebraRpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "sendrawtransaction",
      params: [txHex],
    }),
  });

  if (!resp.ok) {
    throw new Error(`Zebra RPC error: ${resp.status} ${resp.statusText}`);
  }

  const data = (await resp.json()) as any;
  if (data.error) {
    throw new Error(`Broadcast failed: ${data.error.message || JSON.stringify(data.error)}`);
  }

  return data.result as string;
}

/**
 * Estimate fee for a transparent P2PKH transaction.
 *
 * ZIP 317 marginal fee: max(grace_actions, logical_actions) * 5000
 * For simple P2PKH: 1 input + 2 outputs = 2 logical actions = 10000 zatoshis
 * Each additional input adds 1 logical action = +5000 zatoshis
 */
export function estimateFee(numInputs: number, numOutputs: number): number {
  const logicalActions = Math.max(numInputs, numOutputs);
  const graceActions = 2;
  return Math.max(graceActions, logicalActions) * 5000;
}
