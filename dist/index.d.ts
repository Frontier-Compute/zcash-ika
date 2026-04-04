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
export interface ZcashIkaConfig {
    /** Ika network: mainnet or testnet */
    network: "mainnet" | "testnet";
    /** Zebra node RPC for broadcasting */
    zebraRpcUrl: string;
    /** ZAP1 API for attestation */
    zap1ApiUrl: string;
    /** ZAP1 API key for write operations */
    zap1ApiKey?: string;
}
export interface ShieldedWallet {
    /** dWallet ID on Ika/Sui */
    id: string;
    /** Ed25519 public key (raw bytes) */
    publicKey: Uint8Array;
    /** Derived Zcash Orchard address */
    orchardAddress: string;
    /** Network the wallet was created on */
    network: string;
}
export interface SpendPolicy {
    /** Max zatoshis per single transaction */
    maxPerTx: number;
    /** Max zatoshis per 24h window */
    maxDaily: number;
    /** Allowed recipient addresses (empty = any) */
    allowedRecipients: string[];
    /** Require operator approval above this amount */
    approvalThreshold: number;
}
export interface ShieldedSpend {
    /** Recipient Orchard address */
    to: string;
    /** Amount in zatoshis */
    amountZat: number;
    /** Memo (ZAP1 structured or plain text) */
    memo?: string;
}
export interface SpendResult {
    /** Transaction ID on Zcash */
    txid: string;
    /** ZAP1 attestation leaf hash */
    leafHash: string;
    /** Verify URL */
    verifyUrl: string;
    /** Whether policy was checked */
    policyChecked: boolean;
}
/**
 * Create a zero-trust shielded wallet.
 *
 * Generates a dWallet on Ika with Ed25519 key split between
 * the operator (user share) and the Ika MPC network (network share).
 * Derives an Orchard payment address from the Ed25519 key.
 */
export declare function createWallet(config: ZcashIkaConfig, operatorSeed: Uint8Array): Promise<ShieldedWallet>;
/**
 * Set spending policy on the dWallet.
 *
 * Policy is enforced at the Sui smart contract level.
 * The agent cannot bypass it because the contract holds the DWalletCap.
 * Violating policy = the contract refuses to call approve_message().
 */
export declare function setPolicy(config: ZcashIkaConfig, walletId: string, policy: SpendPolicy): Promise<string>;
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
export declare function spend(config: ZcashIkaConfig, walletId: string, operatorSeed: Uint8Array, request: ShieldedSpend): Promise<SpendResult>;
/**
 * Verify the wallet's attestation history.
 *
 * Returns all ZAP1 attestations for this wallet, verifiable on-chain.
 */
export declare function getHistory(config: ZcashIkaConfig, walletId: string): Promise<{
    leafHash: string;
    eventType: string;
    timestamp: string;
}[]>;
/**
 * Check wallet's policy compliance status.
 */
export declare function checkCompliance(config: ZcashIkaConfig, walletId: string): Promise<{
    compliant: boolean;
    violations: number;
    bondDeposits: number;
}>;
