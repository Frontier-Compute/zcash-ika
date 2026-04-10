# zcash-ika

Split-key custody for Zcash, Bitcoin, and EVM chains. The private key never exists whole. Spend policy enforced on-chain. Every action attested to Zcash.

[![npm](https://img.shields.io/npm/v/@frontiercompute/zcash-ika)](https://www.npmjs.com/package/@frontiercompute/zcash-ika)
[![downloads](https://img.shields.io/npm/dw/@frontiercompute/zcash-ika)](https://www.npmjs.com/package/@frontiercompute/zcash-ika)
[![license](https://img.shields.io/npm/l/@frontiercompute/zcash-ika)](https://github.com/Frontier-Compute/zcash-ika/blob/main/LICENSE)

## What this does

One secp256k1 dWallet on [Ika's 2PC-MPC network](https://ika.xyz) signs for three chain families. Your device holds half the key. Ika's nodes hold the other half. Neither can spend alone.

- **Spend policy** enforced by Sui Move contract (per-tx limits, daily caps, recipient whitelist, emergency freeze)
- **Transparent TX builder** for Zcash v5 transactions (ZIP 244 sighash, P2PKH, UTXO selection)
- **Attestation** of every operation to Zcash mainnet via [ZAP1](https://pay.frontiercompute.io)
- **6-chain verification of attestation proofs (Ethereum, Arbitrum, Base, Hyperliquid, NEAR, Sui)

## Chain support

| Chain | Curve | Algorithm | Hash | Status |
|-------|-------|-----------|------|--------|
| Zcash transparent | secp256k1 | ECDSA | DoubleSHA256 | TX builder + signing live |
| Bitcoin | secp256k1 | ECDSA | DoubleSHA256 | Same dWallet, signing live |
| Ethereum/EVM | secp256k1 | ECDSA | KECCAK256 | Same dWallet, signing live |

One dWallet. Three chain families. Split custody on all of them.

## What does NOT work

**Zcash shielded (Orchard)** requires RedPallas on the Pallas curve. Ika supports secp256k1 and Ed25519, not Pallas. No path from Ika to Orchard signing today. For shielded, use the [embedded wallet](https://github.com/Frontier-Compute/zap1) which holds Orchard keys directly.

## Install

```bash
npm install @frontiercompute/zcash-ika
```

## Quick start

```typescript
import {
  createWallet,
  sign,
  setPolicy,
  spendTransparent,
  checkPolicy,
  deriveZcashAddress,
} from "@frontiercompute/zcash-ika";

const config = {
  network: "testnet",
  suiPrivateKey: "suiprivkey1...",
  zap1ApiUrl: "https://pay.frontiercompute.io",
};

// 1. Create split-key wallet
const wallet = await createWallet(config);
console.log("dWallet:", wallet.id);
console.log("t-addr:", wallet.address);
console.log("Save this seed:", wallet.encryptionSeed);

// 2. Set spend policy (Sui Move contract)
const policy = await setPolicy(config, wallet.id, {
  maxPerTx: 100_000_000,       // 1 ZEC max per transaction
  maxDaily: 500_000_000,       // 5 ZEC daily cap
  allowedRecipients: [],       // empty = any recipient
  approvalThreshold: 50_000_000, // flag above 0.5 ZEC
});
console.log("Policy:", policy.policyId);

// 3. Check if a spend is allowed
const check = await checkPolicy(config, policy.policyId, {
  amount: 10_000_000,
  recipient: "t1SomeAddress...",
});
console.log("Allowed:", check.allowed);

// 4. Spend from the transparent address
const spend = await spendTransparent(config, {
  walletId: wallet.id,
  encryptionSeed: wallet.encryptionSeed,
  recipient: "t1RecipientAddr...",
  amount: 10_000_000,   // 0.1 ZEC
  zebraRpcUrl: "http://localhost:8232",
});
console.log("Txid:", spend.txid);
```

## Architecture

```
Operator (device / HSM)
  |
  | user key share (encryption seed from DKG)
  |
Ika MPC Network (2PC-MPC on Sui)
  |
  | network key share (distributed across nodes)
  |
  +-- Spend Policy (Sui Move contract)
  |     max per tx, daily cap, recipient whitelist, freeze
  |
  +-- Sign ZEC transparent  (secp256k1 / ECDSA / DoubleSHA256)
  +-- Sign BTC              (secp256k1 / ECDSA / DoubleSHA256)
  +-- Sign ETH/EVM          (secp256k1 / ECDSA / KECCAK256)
  |
TX Builder (Zcash v5, ZIP 244)
  +-- UTXO fetch from Zebra
  +-- Sighash computation
  +-- Signature attachment
  +-- Broadcast + attestation
  |
ZAP1 Attestation (Zcash mainnet)
  +-- every spend recorded in Merkle tree
  +-- anchored to Zcash blockchain
  +-- verified on 6 mainnet chains
```

## Sign flow

1. **Presign** - pre-compute MPC ephemeral key share (Sui TX 1, poll for completion)
2. **Sign** - approve message + request signature (Sui TX 2, poll for completion)

Both transactions on Sui. The user partial is computed locally via WASM. Neither party sees the full private key.

## Spend flow (transparent)

1. Fetch UTXOs from Zebra RPC (`getaddressutxos`)
2. Build unsigned v5 TX with ZIP 244 sighash per input
3. Sign each sighash through Ika MPC (presign + sign)
4. Attach DER signatures to scriptSig fields
5. Broadcast via `sendrawtransaction`
6. Attest spend to ZAP1

## Policy enforcement

The Sui Move contract (`zap1_policy::policy`) stores:
- Per-transaction limit (zatoshis)
- 24-hour rolling daily cap
- Allowed recipient whitelist (empty = any)
- Emergency freeze toggle

Policy is checked before every MPC sign request. The contract owns the approval gate - you can't bypass it from the client.

Deploy: `sui client publish --path move/` then set `POLICY_PACKAGE_ID`.

## On-chain proof

secp256k1 dWallet on Ika testnet:

- dWalletId: `0xd9055400c88aeae675413b78143aa54e25eca7061ab659f54a42167cbfdd7aec`
- TX: [`CYrS5X1S3itHUtux4qS35AJz5AAyUaJYeWZuqm1CcX2L`](https://testnet.suivision.xyz/txblock/CYrS5X1S3itHUtux4qS35AJz5AAyUaJYeWZuqm1CcX2L)
- Compressed pubkey: `03ba9e85a85674df494520c2e80b804656fac54fe68668266f33fee9b03ad4b069`
- Derived ZEC t-addr: `t1Rqh1TKqXsSiaV4wrSDandEPccucpHEudn`

Attestation anchors verified on Ethereum, Arbitrum, Base, Hyperliquid, NEAR, Sui.

## Environment variables

```
SUI_PRIVATE_KEY         - Sui keypair for signing transactions
POLICY_PACKAGE_ID       - Published Move package address (after sui client publish)
ZAP1_API_URL            - ZAP1 attestation API (default: https://pay.frontiercompute.io)
ZAP1_API_KEY            - API key for attestation
ZEBRA_RPC_URL           - Zebra JSON-RPC endpoint for UTXO queries and broadcast
```

## Test scripts

```bash
# Create a new dWallet
SUI_PRIVATE_KEY=suiprivkey1... node dist/test-dkg.js

# Sign a test message through MPC
SUI_PRIVATE_KEY=... DWALLET_ID=0x... ENC_SEED=... node dist/test-sign.js

# End-to-end: DKG + presign + sign
SUI_PRIVATE_KEY=... node dist/test-e2e.js
```

## Stack

- [Ika](https://ika.xyz) - 2PC-MPC threshold signing on Sui
- [ZAP1](https://pay.frontiercompute.io) - on-chain attestation protocol
- [Zebra](https://github.com/ZcashFoundation/zebra) - Zcash node
- [Sui Move](https://docs.sui.io/concepts/sui-move-concepts) - policy enforcement

## Related Packages

| Package | What it does |
|---------|-------------|
| [@frontiercompute/zcash-mcp](https://www.npmjs.com/package/@frontiercompute/zcash-mcp) | MCP server for Zcash (12 tools) |
| [@frontiercompute/openclaw-zap1](https://www.npmjs.com/package/@frontiercompute/openclaw-zap1) | OpenClaw skill for ZAP1 attestation |
| [@frontiercompute/zap1](https://www.npmjs.com/package/@frontiercompute/zap1) | ZAP1 attestation client |
| [@frontiercompute/silo-zap1](https://www.npmjs.com/package/@frontiercompute/silo-zap1) | Silo agent attestation via ZAP1 |

## License

MIT

## quickstart

```bash
npm i @frontiercompute/zcash-ika
```

```typescript
import { IkaClient, SignatureAlgorithm } from "@frontiercompute/zcash-ika";

// create a split-key wallet via Ika 2PC-MPC
const client = new IkaClient({ network: "testnet" });
const wallet = await client.createWallet(SignatureAlgorithm.Secp256k1);

// sign a zcash transaction (neither party sees the full key)
const sig = await client.sign(wallet.id, txHash);
```

54 exports.  BTC + ZEC + EVM signing.  honest-majority MPC custody.

