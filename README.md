# zcash-ika

Split-key custody for Zcash and Bitcoin. The private key never exists whole.

[![npm](https://img.shields.io/npm/v/@frontiercompute/zcash-ika)](https://www.npmjs.com/package/@frontiercompute/zcash-ika)

## What this is

Your agent/DAO/treasury holds ZEC and BTC through [Ika's 2PC-MPC network](https://ika.xyz). One key share on your device, one distributed across Ika's nodes on Sui. Both must cooperate to sign. Spending policy enforced by smart contract. Every action attested on-chain via [ZAP1](https://pay.frontiercompute.io).

**Ed25519 dWallet live on Ika testnet.** First Zcash-capable dWallet ever created on the network.

## Use cases

### AI Agent Custody
Your agent needs to spend money. Give it a split-key wallet instead of full access. The agent requests transactions, but can't override spending limits, daily caps, or approved recipient lists. If the agent gets compromised, the attacker gets half a key. Worthless.

```
npx @frontiercompute/zcash-mcp  # 17 tools, any MCP client
```

### DAO Treasury
Multi-sig is 2003 technology. Split-key custody means the treasury key literally doesn't exist in one place. Policy lives in a Sui Move contract that no single party controls. Every spend attested to Zcash for the full audit trail, but balances stay shielded.

### Privacy Payroll
Pay contributors without publishing amounts on a block explorer. Shielded ZEC from an Orchard address, every payment attested via ZAP1 for compliance. The auditor sees proof of payment. Nobody else sees anything.

### Cross-Border Commerce
Hold shielded ZEC + stablecoins (USDC/USDT via secp256k1 on EVM chains) in one wallet. Same operator, same policy. Swap between them via NEAR Intents. Settlement is private. Compliance is provable.

### Compliance Without Exposure
ZAP1 attestations prove what happened without revealing what you hold. Bond deposits prove skin in the game. Policy verification proves you followed the rules. All on Zcash mainnet, all verifiable, nothing visible beyond what you choose to share.

## Signing parameters

| Chain | Curve | Algorithm | Hash | Status |
|-------|-------|-----------|------|--------|
| Zcash Orchard | ED25519 | EdDSA | SHA512 | dWallet live on testnet |
| Bitcoin | SECP256K1 | ECDSASecp256k1 | DoubleSHA256 | SDK ready |
| Zcash transparent | SECP256K1 | ECDSASecp256k1 | DoubleSHA256 | SDK ready |
| Ethereum/Base | SECP256K1 | ECDSASecp256k1 | KECCAK256 | SDK ready |

One secp256k1 dWallet signs for Bitcoin, Zcash transparent, and every EVM chain.

## Install

```bash
npm install @frontiercompute/zcash-ika
```

## Quick start

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

// Create dual custody - shielded ZEC + BTC/stablecoins
const custody = await createDualCustody(config, operatorSeed);

// Set spending policy (enforced by Sui contract, not by trust)
await setPolicy(config, custody.shielded.id, {
  maxPerTx: 100_000,       // 0.001 ZEC per tx
  maxDaily: 1_000_000,     // 0.01 ZEC daily cap
  allowedRecipients: [],   // any recipient (or lock to specific addresses)
  approvalThreshold: 500_000, // operator approval above 0.005 ZEC
});

// Shielded spend - agent requests, both key shares cooperate
const result = await spendShielded(config, custody.shielded.id, operatorSeed, {
  to: "u1abc...",
  amount: 50_000,
  memo: "payment for API access",
});

// Compliance check (works now against live ZAP1 API)
const compliance = await checkCompliance(config, custody.shielded.id);
// { compliant: true, violations: 0, bondDeposits: 1 }
```

## How it works

```
Operator (phone / hardware wallet / DAO multisig)
  |
  | user key share
  |
Ika MPC Network (2PC-MPC on Sui, mainnet live)
  |
  | network key share (distributed across nodes)
  |
  +-- Spending Policy (Sui Move contract)
  |     max per tx, daily cap, approved recipients
  |     the agent CANNOT modify its own limits
  |
  +-- Sign Zcash tx (Ed25519/EdDSA)  -> shielded spend
  +-- Sign Bitcoin tx (secp256k1/ECDSA) -> BTC spend
  +-- Sign EVM tx (secp256k1/ECDSA)  -> USDC/USDT spend
  |
ZAP1 Attestation (Zcash mainnet)
  +-- every spend recorded as AGENT_ACTION
  +-- policy violations on-chain as POLICY_VIOLATION
  +-- bond deposits prove skin in the game
  +-- full audit trail, verifiable by anyone
```

## What's live

- Ed25519 dWallet on Ika testnet (TX: `FYcuaxBCAfuZqfBW7JEtEJME3KLBSBKLvhjLpZGSyaXb`)
- `getHistory()` and `checkCompliance()` against live ZAP1 API
- All Ika SDK primitives re-exported and typed
- Chain parameter configs for all signing modes
- DKG test script proving the full round-trip

## What's next

- secp256k1 dWallet for BTC/stablecoins (same flow, different curve)
- Sign a real Zcash sighash through the MPC
- Ed25519 -> Orchard spending key derivation bridge
- Move policy template for spending limits
- Mainnet deployment

## The competition

| Project | Custody | Privacy | Attestation |
|---------|---------|---------|-------------|
| Coinbase AgentKit | Full key in agent | None | None |
| GOAT SDK | Full key in agent | None | None |
| Solana Agent Kit | Full key in agent | None | None |
| **zcash-ika** | **Split-key MPC** | **Zcash Orchard** | **ZAP1 on-chain** |

## Stack

- [Ika](https://ika.xyz) - 2PC-MPC threshold signing on Sui
- [ZAP1](https://pay.frontiercompute.io) - on-chain attestation protocol
- [Zebra](https://github.com/ZcashFoundation/zebra) - Zcash node
- [zcash-mcp](https://www.npmjs.com/package/@frontiercompute/zcash-mcp) - 17-tool MCP server

## License

MIT
