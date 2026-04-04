# zcash-ika

Hold ZEC. Hold BTC. Neither key ever exists whole.

Split-key custody for Zcash and Bitcoin via [Ika's 2PC-MPC network](https://ika.xyz). Your phone holds half the key. The Ika network holds the other half. A compromised device gets half a key. Worthless.

Works with any wallet that supports the protocol. Works for AI agents that need to spend but shouldn't be trusted with full keys. Works for anyone who wants real custody guarantees instead of "trust me" security.

## What you get

Two wallets under one operator:

| Wallet | Chain | Curve | What it signs |
|--------|-------|-------|---------------|
| Shielded | Zcash Orchard | Ed25519/EdDSA | Private ZEC transactions |
| Bitcoin | Bitcoin | secp256k1/ECDSA | BTC transactions |

Both wallets share one operator identity. Both enforced by the same spending policy (Sui Move contract). Both attested on-chain via ZAP1.

## How it works

```
Your phone / hardware wallet
  |
  | operator key share
  |
Ika MPC Network (2PC-MPC on Sui)
  |
  | network key share (distributed across nodes)
  |
  +-- Spending Policy (Move contract)
  |     max per tx, daily cap, approved recipients
  |
  +-- Sign Zcash tx (Ed25519/EdDSA) -> shielded spend
  +-- Sign Bitcoin tx (secp256k1/ECDSA) -> BTC spend
  |
ZAP1 Attestation (Zcash mainnet)
  |
  +-- every spend on-chain as AGENT_ACTION
  +-- policy violations recorded
  +-- full audit trail, verifiable by anyone
```

## Install

```
npm install @frontiercompute/zcash-ika
```

## Usage

```typescript
import {
  createDualCustody,
  spendShielded,
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

// Create dual custody - one shielded ZEC wallet + one BTC wallet
const custody = await createDualCustody(config, operatorSeed);
// custody.shielded.address -> Orchard UA
// custody.bitcoin.address -> BTC address
// Same operator, same policy, both split-key

// Set spending policy (enforced by Sui contract, not by the agent)
await setPolicy(config, custody.shielded.id, {
  maxPerTx: 100_000,       // 0.001 ZEC max per tx
  maxDaily: 1_000_000,     // 0.01 ZEC daily cap
  allowedRecipients: [],   // any recipient
  approvalThreshold: 500_000,
});

// Shielded ZEC spend - agent requests, both key shares cooperate
const zecResult = await spendShielded(config, custody.shielded.id, operatorSeed, {
  to: "u1abc...",
  amount: 50_000,
  memo: "payment for API access",
});

// Bitcoin spend - same MPC flow, different curve
const btcResult = await spendBitcoin(config, custody.bitcoin.id, operatorSeed, {
  to: "bc1q...",
  amount: 100_000,
});

// Check compliance history (works now against live ZAP1 API)
const history = await getHistory(config, custody.shielded.id);
const compliance = await checkCompliance(config, custody.shielded.id);
```

## Signing parameters

| Chain | Curve | Algorithm | Hash | Use case |
|-------|-------|-----------|------|----------|
| Zcash Orchard | ED25519 | EdDSA | SHA512 | Shielded ZEC |
| Zcash transparent | SECP256K1 | ECDSASecp256k1 | DoubleSHA256 | t-addr ZEC |
| Bitcoin | SECP256K1 | ECDSASecp256k1 | DoubleSHA256 | BTC |

Bitcoin and Zcash transparent share the same curve and hash. One secp256k1 dWallet can sign for both chains (different address derivation).

## Why this matters

Every wallet today is trust-based. The app has the full key. If it gets hacked, funds are gone. Hardware wallets improve this but still hold a complete key in one place.

This is structurally different. The private key is never whole. Not on your phone, not on the Ika network, not anywhere. Both halves must cooperate to sign. The spending policy lives in a Sui smart contract that neither party can unilaterally modify.

For AI agents, this is the difference between "the agent promises not to steal" and "the agent mathematically cannot steal."

## Stack

- [Ika](https://ika.xyz) - 2PC-MPC threshold signing on Sui (mainnet live)
- [ZAP1](https://pay.frontiercompute.io) - on-chain attestation protocol
- [Zebra](https://github.com/ZcashFoundation/zebra) - Zcash node
- Zcash Orchard pool - shielded transactions
- Bitcoin - you know what Bitcoin is

## Status

Interface published. Ika SDK integrated. DKG + signing flow documented.

What works today:
- `getHistory()` and `checkCompliance()` - live against ZAP1 API
- All Ika SDK primitives re-exported and typed
- Chain parameter configs for all three signing modes

What's next:
- Testnet DKG ceremony (create actual dWallets)
- Ed25519 -> Orchard spending key derivation bridge
- Sign a real Zcash sighash through the MPC
- Bitcoin transaction signing demo

## License

MIT
