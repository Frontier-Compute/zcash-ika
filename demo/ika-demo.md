# Ika RFP Demo - 60 seconds

One dWallet. Three chain families. Split custody. No key ever whole.

## Setup (before the call)

Terminal open with `quick-demo.cjs` ready to run.
Browser tabs pre-loaded:
1. npm package page
2. Zcash block explorer TX
3. Sui testnet explorer (Move package)
4. verify.frontiercompute.cash

## Beat 1: Install (5 sec)

Show the npm package. Already published, already works.

```bash
npm i @frontiercompute/zcash-ika
```

Say: "Published on npm. 65 exports. TX builders for Zcash and Bitcoin, spend policy via Sui Move, attestation pipeline. One install."

## Beat 2: Derive addresses from dWallet pubkey (10 sec)

Run the demo script:

```bash
node demo/quick-demo.cjs
```

Expected output:

```
--- zcash-ika address derivation ---

dWallet pubkey: 03d691c837d008538ffbbb60438dad338b9b6a1a732b1b17096f890c9abdc12cb7
dWallet ID:     0x108c8e98d0384d3eef7e65e6abd4613fdc23ca3fca2fe1badd60d54ab8e84c90

ZEC t-addr (mainnet): t1JgBmDT2Q4Bgj3obsZ5BYsH86Yd2GP8NBf
ZEC t-addr (testnet): tmAWw63wRnihBsJ13YHNvQXwshXhqk42Lqh
BTC addr   (mainnet): 1oakt2tRjQ68Qkhw8G4R4BCqtRwXFy45N
BTC addr   (testnet): mgKY3w7sEkqLuXEKehESEyPXht2eVETwCU

Same secp256k1 key. Two chains. One dWallet controls both.
```

Say: "One dWallet on Ika. Compressed secp256k1 pubkey. Derives to a Zcash t-address and a Bitcoin address. Same key, two chains. No network call - pure local crypto, runs in under a second."

## Beat 3: Mainnet TX (10 sec)

Show browser tab: Zcash block explorer.

TX: `9ced54f695258ca0ead4e7188ad6e1eee489dbf8c7b89571e27ddca793bf239b`

Explorer: https://zcashblockexplorer.com/transactions/9ced54f695258ca0ead4e7188ad6e1eee489dbf8c7b89571e27ddca793bf239b

Say: "This is a real mainnet Zcash transaction. Built and signed with this SDK. ZIP 244 sighash, v5 format, broadcast through Zebra. The signing used a dWallet - the key never existed whole at any point."

Ika sign TX on Sui: `Hcn1cW27nELwPog7xwfedNE1kGAsSzSmFy5whGALw77b`

## Beat 4: Move policy contract (10 sec)

Show browser tab: Sui testnet explorer.

Package: `0xb0468033d854e95ad89de4b6fec8f6d8e8187778c9d8337a6aa30a5c24775a77`

Explorer: https://testnet.suivision.xyz/package/0xb0468033d854e95ad89de4b6fec8f6d8e8187778c9d8337a6aa30a5c24775a77

Say: "Spend policy enforced on-chain. Two modules: policy.move and custody.move. Per-TX limits, daily caps, recipient whitelist, emergency freeze. The agent can only spend within bounds the operator sets. All on Sui, all verifiable."

## Beat 5: npm package + exports (10 sec)

Show browser tab: https://www.npmjs.com/package/@frontiercompute/zcash-ika

Or show terminal output from the demo script listing all exports.

Say: "65 exports. Full Zcash v5 TX builder, Bitcoin TX builder, dWallet creation, signing, spend policy, vault management, agent registration, attestation. This is not a prototype - it is a working SDK."

Version: 0.6.0 (check `npm info @frontiercompute/zcash-ika version` before demo)

## Beat 6: 5-chain verification (10 sec)

Show browser tab: https://verify.frontiercompute.cash

Or: https://pay.frontiercompute.io/verify/{leaf_hash}/check

Say: "Every custody operation gets attested to Zcash mainnet via ZAP1. Proofs are verified on 5 chains - Arbitrum, Base, Hyperliquid, Solana, NEAR. Cross-chain audit trail. Not just signing - full accountability."

## Closing (5 sec)

"One secp256k1 dWallet on Ika signs for Zcash, Bitcoin, and EVM. Policy on Sui. Attestation on Zcash. Verification on 5 chains. The key never exists whole. That is agent custody."

## If they ask "what about shielded?"

"Orchard uses RedPallas on the Pallas curve. Ika supports secp256k1 and Ed25519 today. No path from Ika to Orchard signing right now. For shielded, we use an embedded wallet with direct Orchard key management. This SDK handles transparent - which is where the multi-chain story lives."

## If they ask "what is left to build?"

"The signing flow works E2E. The TX builder is proven on mainnet. The policy contract compiles and deploys. What is left: wiring setPolicy() and checkPolicy() to the deployed Move package, presign automation, and the agent registration UX. Five milestones, ten weeks."

## Quick reference

| Asset | Link |
|-------|------|
| npm | https://www.npmjs.com/package/@frontiercompute/zcash-ika |
| GitHub | https://github.com/Frontier-Compute/zcash-ika |
| ZEC mainnet TX | https://zcashblockexplorer.com/transactions/9ced54f695258ca0ead4e7188ad6e1eee489dbf8c7b89571e27ddca793bf239b |
| Ika sign TX | https://testnet.suivision.xyz/txblock/Hcn1cW27nELwPog7xwfedNE1kGAsSzSmFy5whGALw77b |
| Move package | https://testnet.suivision.xyz/package/0xb0468033d854e95ad89de4b6fec8f6d8e8187778c9d8337a6aa30a5c24775a77 |
| dWallet ID | 0x108c8e98d0384d3eef7e65e6abd4613fdc23ca3fca2fe1badd60d54ab8e84c90 |
| Verify | https://verify.frontiercompute.cash |
| ZAP1 API | https://pay.frontiercompute.io |
