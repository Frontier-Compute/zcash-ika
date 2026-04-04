/**
 * @frontiercompute/zcash-ika
 *
 * Zero-trust Zcash agent custody. Born shielded, stay shielded.
 *
 * The agent holds half a key. The operator holds the other half.
 * Neither can sign alone. Every operation attested to Zcash via ZAP1.
 *
 * Built on Ika's 2PC-MPC network (Sui) for Zcash EdDSA signing.
 */
/**
 * Create a zero-trust shielded wallet.
 *
 * Generates a dWallet on Ika with Ed25519 key split between
 * the operator (user share) and the Ika MPC network (network share).
 * Derives an Orchard payment address from the Ed25519 key.
 */
export async function createWallet(config, operatorSeed) {
    // Phase 1: Use Ika SDK for DKG
    // Phase 2: Derive Orchard address via zcash_primitives
    // For now: document the flow, ship the interface
    throw new Error("createWallet requires Ika testnet access. " +
        "Set up: npm install @ika.xyz/sdk && configure Sui wallet. " +
        "See https://docs.ika.xyz for DKG walkthrough.");
}
/**
 * Set spending policy on the dWallet.
 *
 * Policy is enforced at the Sui smart contract level.
 * The agent cannot bypass it because the contract holds the DWalletCap.
 * Violating policy = the contract refuses to call approve_message().
 */
export async function setPolicy(config, walletId, policy) {
    // Deploy or update Move module on Sui that gates approve_message()
    // with the specified constraints
    throw new Error("setPolicy requires a deployed Move module on Sui. " +
        "See docs/move-policy-template.move for the template.");
}
/**
 * Spend from the shielded wallet.
 *
 * Flow:
 * 1. Build Zcash Orchard transaction (zcash_primitives)
 * 2. Extract sighash
 * 3. Sign via Ika 2PC-MPC (both shares cooperate)
 * 4. Attach signature to transaction
 * 5. Broadcast via Zebra sendrawtransaction
 * 6. Attest via ZAP1 as AGENT_ACTION
 *
 * The agent never has the full signing key.
 * The operator can set policy that the agent cannot override.
 */
export async function spend(config, walletId, operatorSeed, request) {
    // Phase 1: Build Orchard tx via our existing wallet.rs code (FFI or HTTP)
    // Phase 2: Extract sighash, sign via Ika
    // Phase 3: Broadcast + attest
    throw new Error("spend requires active dWallet + Zebra node. " +
        "Integration in progress.");
}
/**
 * Verify the wallet's attestation history.
 *
 * Returns all ZAP1 attestations for this wallet, verifiable on-chain.
 */
export async function getHistory(config, walletId) {
    const resp = await fetch(`${config.zap1ApiUrl}/lifecycle/${walletId}`);
    if (!resp.ok)
        return [];
    const data = (await resp.json());
    return (data.leaves || []).map((l) => ({
        leafHash: l.leaf_hash,
        eventType: l.event_type,
        timestamp: l.created_at,
    }));
}
/**
 * Check wallet's policy compliance status.
 */
export async function checkCompliance(config, walletId) {
    const resp = await fetch(`${config.zap1ApiUrl}/agent/${walletId}/policy/verify`);
    if (!resp.ok)
        return { compliant: false, violations: -1, bondDeposits: 0 };
    const data = (await resp.json());
    return {
        compliant: data.compliant,
        violations: data.violations,
        bondDeposits: data.bond_deposits || 0,
    };
}
