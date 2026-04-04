# zcash-ika

Split-key custody for Zcash, Bitcoin, and EVM chains. The private key never exists whole.

[![npm](https://img.shields.io/npm/v/@frontiercompute/zcash-ika)](https://www.npmjs.com/package/@frontiercompute/zcash-ika)

## What this is

One secp256k1 dWallet on [Ika's 2PC-MPC network](https://ika.xyz) signs for Zcash transparent, Bitcoin, and Ethereum. Your device holds half the key. Ika's nodes hold the other half. Spending policy enforced by Sui Move contract. Every action attested on Zcash via [ZAP1](https://pay.frontiercompute.io).

## What works today

| Chain | Curve | Algorithm | Hash | Status |
|-------|-------|-----------|------|--------|
| Zcash transparent | secp256k1 | ECDSA | DoubleSHA256 | dWallet on testnet, signing wired |
| Bitcoin | secp256k1 | ECDSA | DoubleSHA256 | Same dWallet, same key |
| Ethereum/EVM | secp256k1 | ECDSA | KECCAK256 | Same dWallet, different hash |

One dWallet. Three chain families. Split custody on all of them.

## What does NOT work

**Zcash shielded (Orchard)** requires RedPallas signatures on the Pallas curve. Ika's MPC supports secp256k1 and Ed25519, but not Pallas. There is no path from Ika to Orchard signing today. Same for Sapling (RedJubjub on Jubjub).

For shielded operations, use the [embedded Orchard wallet](https://github.com/Frontier-Compute/zap1) which holds keys directly. The hybrid architecture: MPC custody for transparent + cross-chain, local wallet for shielded.

## Install

```bash
npm install @frontiercompute/zcash-ika
```

## Usage

```typescript
import {
  createWallet,
  sign,
  createDualCustody,
  getHistory,
  checkCompliance,
  CHAIN_PARAMS,
} from "@frontiercompute/zcash-ika";

const config = {
  network: "testnet",
  suiPrivateKey: "suiprivkey1...",
  zap1ApiUrl: "https://pay.frontiercompute.io",
};

// Create split-key wallet (secp256k1 - signs for ZEC + BTC + ETH)
const custody = await createDualCustody(config);
console.log("dWallet:", custody.primary.id);
console.log("Save this seed:", custody.primary.encryptionSeed);

// Sign a Zcash transparent sighash through MPC
const result = await sign(config, {
  messageHash: sighashBytes, // DoubleSHA256 of the tx
  walletId: custody.primary.id,
  chain: "zcash-transparent",
  encryptionSeed: custody.primary.encryptionSeed,
});
console.log("Signature:", Buffer.from(result.signature).toString("hex"));

// Sign Bitcoin (same dWallet, same MPC, same seed)
const btcSig = await sign(config, {
  messageHash: btcSighash,
  walletId: custody.primary.id,
  chain: "bitcoin",
  encryptionSeed: custody.primary.encryptionSeed,
});

// Compliance check (works now against live ZAP1 API)
const compliance = await checkCompliance(config, custody.primary.id);
```

## How it works

```
Operator (phone / hardware wallet)
  |
  | user key share (encryption seed)
  |
Ika MPC Network (2PC-MPC on Sui)
  |
  | network key share (distributed across nodes)
  |
  +-- Spending Policy (Sui Move contract)
  |     max per tx, daily cap, approved recipients
  |
  +-- Sign ZEC transparent tx (secp256k1/ECDSA/DoubleSHA256)
  +-- Sign BTC tx             (secp256k1/ECDSA/DoubleSHA256)
  +-- Sign ETH tx             (secp256k1/ECDSA/KECCAK256)
  |
ZAP1 Attestation (Zcash mainnet)
  +-- every spend recorded
  +-- policy violations on-chain
  +-- full audit trail
```

## Sign flow (two transactions)

1. **Presign** - pre-compute MPC ephemeral key share (TX 1, poll for completion)
2. **Sign** - approve message + request signature (TX 2, poll for completion)

Both transactions on Sui. The user partial signature is computed locally via WASM. Neither party ever sees the full private key.

## On-chain proof

secp256k1 dWallet created on Ika testnet:

- dWalletId: `0xd9055400c88aeae675413b78143aa54e25eca7061ab659f54a42167cbfdd7aec`
- TX: [`CYrS5X1S3itHUtux4qS35AJz5AAyUaJYeWZuqm1CcX2L`](https://testnet.suivision.xyz/txblock/CYrS5X1S3itHUtux4qS35AJz5AAyUaJYeWZuqm1CcX2L)
- Public key: `03ba9e85a85674df494520c2e80b804656fac54fe68668266f33fee9b03ad4b069`
- Derived BTC: `moV3JAzgNa6NkxVfdaNqUjLoDxKEwNAnkX`
- Derived ZEC t-addr: `t1Rqh1TKqXsSiaV4wrSDandEPccucpHEudn`

## Test scripts

```bash
# Create a new dWallet (saves encryption seed)
SUI_PRIVATE_KEY=suiprivkey1... node dist/test-dkg.js

# Sign a test message through MPC
SUI_PRIVATE_KEY=... DWALLET_ID=0x... ENC_SEED=... node dist/test-sign.js
```

## Stack

- [Ika](https://ika.xyz) - 2PC-MPC threshold signing on Sui
- [ZAP1](https://pay.frontiercompute.io) - on-chain attestation protocol
- [Zebra](https://github.com/ZcashFoundation/zebra) - Zcash node

## License

MIT
