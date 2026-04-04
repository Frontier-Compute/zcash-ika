# zcash-ika

Split-key custody for Zcash, Bitcoin, and EVM chains. The private key never exists whole.

[![npm](https://img.shields.io/npm/v/@frontiercompute/zcash-ika)](https://www.npmjs.com/package/@frontiercompute/zcash-ika)

## What this is

One secp256k1 dWallet on [Ika's 2PC-MPC network](https://ika.xyz) signs for Zcash transparent, Bitcoin, and Ethereum. Your device holds half the key. Ika's nodes hold the other half. Spending policy enforced by Sui Move contract. Every action attested on Zcash via [ZAP1](https://pay.frontiercompute.io).

secp256k1 dWallet live on Ika testnet. Presign and signing pipeline verified.

## What works today

| Chain | Curve | Algorithm | Hash | Status |
|-------|-------|-----------|------|--------|
| Zcash transparent | secp256k1 | ECDSA | DoubleSHA256 | dWallet on testnet, signing in progress |
| Bitcoin | secp256k1 | ECDSA | DoubleSHA256 | Same dWallet, same key |
| Ethereum/EVM | secp256k1 | ECDSA | KECCAK256 | Same dWallet, different hash |

One dWallet. Three chain families. Split custody on all of them.

## What does NOT work

**Zcash shielded (Orchard)** requires RedPallas signatures on the Pallas curve. Ika's MPC supports secp256k1 and Ed25519, but not Pallas. There is no path from Ika to Orchard signing today. Same limitation applies to Sapling (RedJubjub on the Jubjub curve).

Transparent ZEC is the viable path. For shielded operations, use our [embedded Orchard wallet](https://github.com/Frontier-Compute/zap1) which holds keys directly.

## Install

```bash
npm install @frontiercompute/zcash-ika
```

## Usage

```typescript
import {
  createDualCustody,
  spendTransparent,
  spendBitcoin,
  setPolicy,
  getHistory,
  checkCompliance,
  CHAIN_PARAMS,
} from "@frontiercompute/zcash-ika";

const config = {
  network: "mainnet",
  zebraRpcUrl: "http://127.0.0.1:8232",
  zap1ApiUrl: "https://pay.frontiercompute.io",
  zap1ApiKey: "your-key",
};

// Create split-key wallet (secp256k1 - signs for ZEC + BTC + ETH)
const custody = await createDualCustody(config, operatorSeed);

// Set spending policy (enforced by Sui contract, not by trust)
await setPolicy(config, custody.primary.id, {
  maxPerTx: 100_000,
  maxDaily: 1_000_000,
  allowedRecipients: [],
  approvalThreshold: 500_000,
});

// Transparent ZEC spend
const result = await spendTransparent(config, custody.primary.id, operatorSeed, {
  to: "t1abc...",
  amount: 50_000,
  memo: "payment for API access",
});

// Bitcoin spend (same dWallet, same MPC flow)
const btcResult = await spendBitcoin(config, custody.primary.id, operatorSeed, {
  to: "bc1q...",
  amount: 100_000,
});

// Compliance check (works now against live ZAP1 API)
const compliance = await checkCompliance(config, custody.primary.id);
```

## How it works

```
Operator (phone / hardware wallet)
  |
  | user key share
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

## On-chain proof

secp256k1 dWallet created on Ika testnet:

- dWalletId: `0xd9055400c88aeae675413b78143aa54e25eca7061ab659f54a42167cbfdd7aec`
- TX: [`CYrS5X1S3itHUtux4qS35AJz5AAyUaJYeWZuqm1CcX2L`](https://testnet.suivision.xyz/txblock/CYrS5X1S3itHUtux4qS35AJz5AAyUaJYeWZuqm1CcX2L)
- Public key: `03ba9e85a85674df494520c2e80b804656fac54fe68668266f33fee9b03ad4b069`
- Derived BTC: `moV3JAzgNa6NkxVfdaNqUjLoDxKEwNAnkX`
- Derived ZEC t-addr: `t1Rqh1TKqXsSiaV4wrSDandEPccucpHEudn`

Ed25519 dWallet also exists on testnet but cannot sign Orchard transactions (RedPallas required, not Ed25519).

## Stack

- [Ika](https://ika.xyz) - 2PC-MPC threshold signing on Sui
- [ZAP1](https://pay.frontiercompute.io) - on-chain attestation protocol
- [Zebra](https://github.com/ZcashFoundation/zebra) - Zcash node

## License

MIT
