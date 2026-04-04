# zcash-ika

Zero-trust Zcash agent custody. Born shielded, stay shielded.

The agent holds half a key. The operator holds the other half. Neither can sign alone. Every operation attested to Zcash via ZAP1.

Built on [Ika's 2PC-MPC network](https://ika.xyz) for EdDSA signing. Policy enforced by Sui smart contracts. Transactions stay in the Orchard shielded pool from creation to spend.

## How it works

```
Operator (phone/hardware wallet)
  |
  | user key share
  |
Ika MPC Network (Sui)
  |
  | network key share (distributed across nodes)
  |
  +-- Spending Policy (Move contract on Sui)
  |     max per tx, daily cap, approved recipients
  |
  +-- Sign Zcash transaction (2PC-MPC, EdDSA)
  |     both shares cooperate, full key never exists
  |
ZAP1 Attestation (Zcash mainnet)
  |
  +-- Every spend attested as AGENT_ACTION
  +-- Policy violations on-chain as POLICY_VIOLATION
  +-- Bond deposits as BOND_DEPOSIT
```

## Install

```
npm install @frontiercompute/zcash-ika
```

## Usage

```typescript
import { createWallet, spend, setPolicy, getHistory } from "@frontiercompute/zcash-ika";

// Create a zero-trust shielded wallet
const wallet = await createWallet({
  network: "testnet",
  zebraRpcUrl: "http://127.0.0.1:8232",
  zap1ApiUrl: "https://pay.frontiercompute.io",
  zap1ApiKey: "your-key",
}, operatorSeed);

// Set spending policy (enforced by Sui contract)
await setPolicy(config, wallet.id, {
  maxPerTx: 100_000,      // 0.001 ZEC max per transaction
  maxDaily: 1_000_000,    // 0.01 ZEC daily cap
  allowedRecipients: [],  // any recipient
  approvalThreshold: 500_000, // require operator approval above 0.005 ZEC
});

// Spend (agent requests, both key shares cooperate)
const result = await spend(config, wallet.id, operatorSeed, {
  to: "u1abc...",
  amountZat: 50_000,
  memo: "payment for API access",
});

// Verify on-chain
console.log(result.verifyUrl);

// Check compliance history
const history = await getHistory(config, wallet.id);
const compliance = await checkCompliance(config, wallet.id);
```

## Why this matters

Every agent wallet today is trust-based. The agent has the full key. If it goes rogue, it drains the wallet. Rate limits and kill switches are software controls that software can bypass.

This is different. The private key is never whole. The Ika MPC network holds one share, the operator holds the other. A compromised agent gets half a key. Worthless. A compromised MPC node gets the other half. Also worthless.

Spending policy lives in a Sui smart contract, not in the agent's code. The agent can't modify its own limits because the contract holds the signing capability.

## Stack

- [Ika](https://ika.xyz) - 2PC-MPC threshold signing on Sui
- [ZAP1](https://github.com/Frontier-Compute/zap1) - on-chain attestation protocol
- [Zebra](https://github.com/ZcashFoundation/zebra) - Zcash node
- [zcash_primitives](https://crates.io/crates/zcash_primitives) - Orchard transaction building

## Status

Interface published. Core signing integration in progress. Testnet DKG + signing demo coming next.

The `getHistory` and `checkCompliance` functions work against the live ZAP1 API today. Wallet creation and spending require Ika testnet access (EdDSA went live December 2025).

## License

MIT
