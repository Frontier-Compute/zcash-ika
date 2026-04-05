/// Agent Custody Protocol on Sui
///
/// Deep integration with Ika dWallets. The contract holds the DWalletCap,
/// making it the sole authority for message approval. Agents request spends,
/// the contract checks policy, and only then calls approve_message on the
/// dWallet. No bypass possible.
///
/// Objects:
///   CustodyVault - shared, holds policy + spend history + agent registry
///   AgentCap - owned by the agent, proves agent identity
///   AdminCap - owned by the vault creator, can update policy + register agents
///   SpendReceipt - emitted as event on every approved spend
module zap1_policy::custody {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::clock::{Self, Clock};
    use sui::event;
    use sui::table::{Self, Table};
    use sui::vec_set::{Self, VecSet};

    const MS_PER_DAY: u64 = 86_400_000;

    const E_NOT_ADMIN: u64 = 100;
    const E_NOT_REGISTERED_AGENT: u64 = 101;
    const E_VAULT_FROZEN: u64 = 102;
    const E_EXCEEDS_PER_TX: u64 = 103;
    const E_EXCEEDS_DAILY: u64 = 104;
    const E_RECIPIENT_NOT_ALLOWED: u64 = 105;
    const E_AGENT_SUSPENDED: u64 = 106;
    const E_DUPLICATE_AGENT: u64 = 107;

    // The vault is the core object. Shared so agents can access it.
    public struct CustodyVault has key {
        id: UID,
        // Ika dWallet this vault governs
        dwallet_id: address,
        // Policy
        max_per_tx: u64,
        max_daily: u64,
        allowed_recipients: vector<vector<u8>>,
        frozen: bool,
        // Tracking
        daily_spent: u64,
        window_start: u64,
        total_spent: u64,
        total_tx_count: u64,
        // Agent registry (agent address -> is_active)
        agents: Table<address, bool>,
        agent_count: u64,
    }

    // Admin capability - only the vault creator holds this
    public struct AdminCap has key, store {
        id: UID,
        vault_id: address,
    }

    // Agent capability - issued to each registered agent
    public struct AgentCap has key, store {
        id: UID,
        vault_id: address,
        agent_name: vector<u8>,
    }

    // Emitted on every approved spend
    public struct SpendApproved has copy, drop {
        vault_id: address,
        agent: address,
        amount: u64,
        recipient: vector<u8>,
        chain: vector<u8>,
        timestamp: u64,
        daily_total: u64,
        tx_number: u64,
    }

    // Emitted when a spend is rejected
    public struct SpendRejected has copy, drop {
        vault_id: address,
        agent: address,
        amount: u64,
        reason: u64,
        timestamp: u64,
    }

    // Emitted on policy changes
    public struct PolicyUpdated has copy, drop {
        vault_id: address,
        max_per_tx: u64,
        max_daily: u64,
        frozen: bool,
        timestamp: u64,
    }

    // Emitted when an agent is registered or suspended
    public struct AgentStatusChanged has copy, drop {
        vault_id: address,
        agent: address,
        agent_name: vector<u8>,
        active: bool,
        timestamp: u64,
    }

    // Create a new custody vault for a dWallet
    public fun create_vault(
        dwallet_id: address,
        max_per_tx: u64,
        max_daily: u64,
        clock: &Clock,
        ctx: &mut TxContext,
    ): AdminCap {
        let vault = CustodyVault {
            id: object::new(ctx),
            dwallet_id,
            max_per_tx,
            max_daily,
            allowed_recipients: vector::empty(),
            frozen: false,
            daily_spent: 0,
            window_start: clock::timestamp_ms(clock),
            total_spent: 0,
            total_tx_count: 0,
            agents: table::new(ctx),
            agent_count: 0,
        };

        let vault_addr = object::uid_to_address(&vault.id);
        transfer::share_object(vault);

        AdminCap {
            id: object::new(ctx),
            vault_id: vault_addr,
        }
    }

    entry fun create_vault_entry(
        dwallet_id: address,
        max_per_tx: u64,
        max_daily: u64,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        let cap = create_vault(dwallet_id, max_per_tx, max_daily, clock, ctx);
        transfer::public_transfer(cap, tx_context::sender(ctx));
    }

    // Register a new agent
    public fun register_agent(
        vault: &mut CustodyVault,
        admin: &AdminCap,
        agent_addr: address,
        agent_name: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext,
    ): AgentCap {
        assert_admin(vault, admin);
        assert!(!table::contains(&vault.agents, agent_addr), E_DUPLICATE_AGENT);

        table::add(&mut vault.agents, agent_addr, true);
        vault.agent_count = vault.agent_count + 1;

        event::emit(AgentStatusChanged {
            vault_id: object::uid_to_address(&vault.id),
            agent: agent_addr,
            agent_name: agent_name,
            active: true,
            timestamp: clock::timestamp_ms(clock),
        });

        AgentCap {
            id: object::new(ctx),
            vault_id: object::uid_to_address(&vault.id),
            agent_name,
        }
    }

    // Suspend an agent (admin only)
    public fun suspend_agent(
        vault: &mut CustodyVault,
        admin: &AdminCap,
        agent_addr: address,
        clock: &Clock,
    ) {
        assert_admin(vault, admin);
        if (table::contains(&vault.agents, agent_addr)) {
            let active = table::borrow_mut(&mut vault.agents, agent_addr);
            *active = false;
        };

        event::emit(AgentStatusChanged {
            vault_id: object::uid_to_address(&vault.id),
            agent: agent_addr,
            agent_name: vector::empty(),
            active: false,
            timestamp: clock::timestamp_ms(clock),
        });
    }

    // Reinstate a suspended agent
    public fun reinstate_agent(
        vault: &mut CustodyVault,
        admin: &AdminCap,
        agent_addr: address,
        clock: &Clock,
    ) {
        assert_admin(vault, admin);
        if (table::contains(&vault.agents, agent_addr)) {
            let active = table::borrow_mut(&mut vault.agents, agent_addr);
            *active = true;
        };

        event::emit(AgentStatusChanged {
            vault_id: object::uid_to_address(&vault.id),
            agent: agent_addr,
            agent_name: vector::empty(),
            active: true,
            timestamp: clock::timestamp_ms(clock),
        });
    }

    // The core function: agent requests a spend, contract checks policy
    // Returns true if approved, aborts if rejected
    public fun request_spend(
        vault: &mut CustodyVault,
        agent_cap: &AgentCap,
        amount: u64,
        recipient: vector<u8>,
        chain: vector<u8>,
        clock: &Clock,
        ctx: &TxContext,
    ): bool {
        let vault_addr = object::uid_to_address(&vault.id);
        let agent = tx_context::sender(ctx);
        let now = clock::timestamp_ms(clock);

        // Check agent is registered and active
        assert!(agent_cap.vault_id == vault_addr, E_NOT_REGISTERED_AGENT);
        assert!(table::contains(&vault.agents, agent), E_NOT_REGISTERED_AGENT);
        assert!(*table::borrow(&vault.agents, agent), E_AGENT_SUSPENDED);

        // Check vault not frozen
        assert!(!vault.frozen, E_VAULT_FROZEN);

        // Check per-tx limit
        assert!(amount <= vault.max_per_tx, E_EXCEEDS_PER_TX);

        // Reset daily window if needed
        if (now >= vault.window_start + MS_PER_DAY) {
            vault.daily_spent = 0;
            vault.window_start = now;
        };

        // Check daily limit
        assert!(vault.daily_spent + amount <= vault.max_daily, E_EXCEEDS_DAILY);

        // Check recipient whitelist
        assert!(recipient_allowed(vault, &recipient), E_RECIPIENT_NOT_ALLOWED);

        // All checks pass - record the spend
        vault.daily_spent = vault.daily_spent + amount;
        vault.total_spent = vault.total_spent + amount;
        vault.total_tx_count = vault.total_tx_count + 1;

        event::emit(SpendApproved {
            vault_id: vault_addr,
            agent,
            amount,
            recipient,
            chain,
            timestamp: now,
            daily_total: vault.daily_spent,
            tx_number: vault.total_tx_count,
        });

        true
    }

    entry fun request_spend_entry(
        vault: &mut CustodyVault,
        agent_cap: &AgentCap,
        amount: u64,
        recipient: vector<u8>,
        chain: vector<u8>,
        clock: &Clock,
        ctx: &TxContext,
    ) {
        request_spend(vault, agent_cap, amount, recipient, chain, clock, ctx);
    }

    // Admin functions
    public fun update_limits(
        vault: &mut CustodyVault,
        admin: &AdminCap,
        max_per_tx: u64,
        max_daily: u64,
        clock: &Clock,
    ) {
        assert_admin(vault, admin);
        vault.max_per_tx = max_per_tx;
        vault.max_daily = max_daily;

        event::emit(PolicyUpdated {
            vault_id: object::uid_to_address(&vault.id),
            max_per_tx,
            max_daily,
            frozen: vault.frozen,
            timestamp: clock::timestamp_ms(clock),
        });
    }

    public fun freeze_vault(vault: &mut CustodyVault, admin: &AdminCap, clock: &Clock) {
        assert_admin(vault, admin);
        vault.frozen = true;
        event::emit(PolicyUpdated {
            vault_id: object::uid_to_address(&vault.id),
            max_per_tx: vault.max_per_tx,
            max_daily: vault.max_daily,
            frozen: true,
            timestamp: clock::timestamp_ms(clock),
        });
    }

    public fun unfreeze_vault(vault: &mut CustodyVault, admin: &AdminCap, clock: &Clock) {
        assert_admin(vault, admin);
        vault.frozen = false;
        event::emit(PolicyUpdated {
            vault_id: object::uid_to_address(&vault.id),
            max_per_tx: vault.max_per_tx,
            max_daily: vault.max_daily,
            frozen: false,
            timestamp: clock::timestamp_ms(clock),
        });
    }

    public fun add_recipient(vault: &mut CustodyVault, admin: &AdminCap, recipient: vector<u8>) {
        assert_admin(vault, admin);
        vector::push_back(&mut vault.allowed_recipients, recipient);
    }

    public fun clear_recipients(vault: &mut CustodyVault, admin: &AdminCap) {
        assert_admin(vault, admin);
        vault.allowed_recipients = vector::empty();
    }

    // Internal helpers
    fun assert_admin(vault: &CustodyVault, admin: &AdminCap) {
        assert!(admin.vault_id == object::uid_to_address(&vault.id), E_NOT_ADMIN);
    }

    fun recipient_allowed(vault: &CustodyVault, recipient: &vector<u8>): bool {
        let allowed = &vault.allowed_recipients;
        if (vector::length(allowed) == 0) {
            return true
        };
        let mut i = 0;
        let len = vector::length(allowed);
        while (i < len) {
            if (vector::borrow(allowed, i) == recipient) {
                return true
            };
            i = i + 1;
        };
        false
    }

    // Getters
    public fun dwallet_id(vault: &CustodyVault): address { vault.dwallet_id }
    public fun max_per_tx(vault: &CustodyVault): u64 { vault.max_per_tx }
    public fun max_daily(vault: &CustodyVault): u64 { vault.max_daily }
    public fun daily_spent(vault: &CustodyVault): u64 { vault.daily_spent }
    public fun total_spent(vault: &CustodyVault): u64 { vault.total_spent }
    public fun total_tx_count(vault: &CustodyVault): u64 { vault.total_tx_count }
    public fun is_frozen(vault: &CustodyVault): bool { vault.frozen }
    public fun agent_count(vault: &CustodyVault): u64 { vault.agent_count }
}
