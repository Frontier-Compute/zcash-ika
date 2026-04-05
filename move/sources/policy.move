module zap1_policy::policy {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::clock::{Self, Clock};

    const MS_PER_DAY: u64 = 86_400_000;

    const E_NOT_AUTHORIZED: u64 = 0;
    const E_FROZEN: u64 = 1;
    const E_EXCEEDS_PER_TX: u64 = 2;
    const E_EXCEEDS_DAILY: u64 = 3;
    const E_RECIPIENT_NOT_ALLOWED: u64 = 4;

    public struct SpendPolicy has key, store {
        id: UID,
        dwallet_id: address,
        owner: address,
        max_per_tx: u64,
        max_daily: u64,
        daily_spent: u64,
        window_start: u64,
        allowed_recipients: vector<vector<u8>>,
        frozen: bool,
    }

    public struct PolicyCap has key, store {
        id: UID,
        policy_id: address,
    }

    // Create policy, transfer SpendPolicy to sender, return PolicyCap
    public fun create_policy(
        dwallet_id: address,
        max_per_tx: u64,
        max_daily: u64,
        clock: &Clock,
        ctx: &mut TxContext,
    ): PolicyCap {
        let sender = tx_context::sender(ctx);
        let now = clock::timestamp_ms(clock);

        let policy = SpendPolicy {
            id: object::new(ctx),
            dwallet_id,
            owner: sender,
            max_per_tx,
            max_daily,
            daily_spent: 0,
            window_start: now,
            allowed_recipients: vector::empty(),
            frozen: false,
        };

        let policy_addr = object::uid_to_address(&policy.id);

        transfer::public_share_object(policy);

        let cap = PolicyCap {
            id: object::new(ctx),
            policy_id: policy_addr,
        };

        cap
    }

    // Entry wrapper for create_policy
    entry fun create_policy_entry(
        dwallet_id: address,
        max_per_tx: u64,
        max_daily: u64,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        let cap = create_policy(dwallet_id, max_per_tx, max_daily, clock, ctx);
        transfer::public_transfer(cap, tx_context::sender(ctx));
    }

    // Reset daily window if 24h has passed
    fun maybe_reset_window(policy: &mut SpendPolicy, now: u64) {
        if (now >= policy.window_start + MS_PER_DAY) {
            policy.daily_spent = 0;
            policy.window_start = now;
        };
    }

    fun assert_cap(policy: &SpendPolicy, cap: &PolicyCap) {
        assert!(cap.policy_id == object::uid_to_address(&policy.id), E_NOT_AUTHORIZED);
    }

    fun recipient_allowed(policy: &SpendPolicy, recipient: &vector<u8>): bool {
        let allowed = &policy.allowed_recipients;
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

    // Check if a spend would be allowed (read-only)
    public fun check_spend(
        policy: &SpendPolicy,
        amount: u64,
        recipient: vector<u8>,
        clock: &Clock,
    ): bool {
        if (policy.frozen) return false;
        if (amount > policy.max_per_tx) return false;

        let now = clock::timestamp_ms(clock);
        let daily = if (now >= policy.window_start + MS_PER_DAY) {
            0
        } else {
            policy.daily_spent
        };

        if (daily + amount > policy.max_daily) return false;
        if (!recipient_allowed(policy, &recipient)) return false;

        true
    }

    // Record a spend after it passes checks
    public fun record_spend(
        policy: &mut SpendPolicy,
        cap: &PolicyCap,
        amount: u64,
        recipient: vector<u8>,
        clock: &Clock,
    ) {
        assert_cap(policy, cap);
        assert!(!policy.frozen, E_FROZEN);
        assert!(amount <= policy.max_per_tx, E_EXCEEDS_PER_TX);

        let now = clock::timestamp_ms(clock);
        maybe_reset_window(policy, now);

        assert!(policy.daily_spent + amount <= policy.max_daily, E_EXCEEDS_DAILY);
        assert!(recipient_allowed(policy, &recipient), E_RECIPIENT_NOT_ALLOWED);

        policy.daily_spent = policy.daily_spent + amount;
    }

    // Entry wrapper for record_spend
    entry fun record_spend_entry(
        policy: &mut SpendPolicy,
        cap: &PolicyCap,
        amount: u64,
        recipient: vector<u8>,
        clock: &Clock,
    ) {
        record_spend(policy, cap, amount, recipient, clock);
    }

    // Update limits
    public fun update_policy(
        policy: &mut SpendPolicy,
        cap: &PolicyCap,
        max_per_tx: u64,
        max_daily: u64,
    ) {
        assert_cap(policy, cap);
        policy.max_per_tx = max_per_tx;
        policy.max_daily = max_daily;
    }

    entry fun update_policy_entry(
        policy: &mut SpendPolicy,
        cap: &PolicyCap,
        max_per_tx: u64,
        max_daily: u64,
    ) {
        update_policy(policy, cap, max_per_tx, max_daily);
    }

    public fun freeze_policy(policy: &mut SpendPolicy, cap: &PolicyCap) {
        assert_cap(policy, cap);
        policy.frozen = true;
    }

    entry fun freeze_entry(policy: &mut SpendPolicy, cap: &PolicyCap) {
        freeze_policy(policy, cap);
    }

    public fun unfreeze_policy(policy: &mut SpendPolicy, cap: &PolicyCap) {
        assert_cap(policy, cap);
        policy.frozen = false;
    }

    entry fun unfreeze_entry(policy: &mut SpendPolicy, cap: &PolicyCap) {
        unfreeze_policy(policy, cap);
    }

    public fun add_recipient(
        policy: &mut SpendPolicy,
        cap: &PolicyCap,
        recipient: vector<u8>,
    ) {
        assert_cap(policy, cap);
        vector::push_back(&mut policy.allowed_recipients, recipient);
    }

    entry fun add_recipient_entry(
        policy: &mut SpendPolicy,
        cap: &PolicyCap,
        recipient: vector<u8>,
    ) {
        add_recipient(policy, cap, recipient);
    }

    public fun clear_recipients(policy: &mut SpendPolicy, cap: &PolicyCap) {
        assert_cap(policy, cap);
        policy.allowed_recipients = vector::empty();
    }

    entry fun clear_recipients_entry(policy: &mut SpendPolicy, cap: &PolicyCap) {
        clear_recipients(policy, cap);
    }

    // Getters
    public fun dwallet_id(policy: &SpendPolicy): address { policy.dwallet_id }
    public fun owner(policy: &SpendPolicy): address { policy.owner }
    public fun max_per_tx(policy: &SpendPolicy): u64 { policy.max_per_tx }
    public fun max_daily(policy: &SpendPolicy): u64 { policy.max_daily }
    public fun daily_spent(policy: &SpendPolicy): u64 { policy.daily_spent }
    public fun is_frozen(policy: &SpendPolicy): bool { policy.frozen }
    public fun window_start(policy: &SpendPolicy): u64 { policy.window_start }
}
