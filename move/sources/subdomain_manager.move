module addr::subdomain_manager {
    use addr::keyless;
    use std::error;
    use std::option::{Self, Option};
    use std::signer;
    use std::string::String;
    use aptos_std::big_ordered_map::{Self, BigOrderedMap};
    use aptos_std::object::{Self, Object, DeleteRef, ExtendRef};
    use aptos_framework::event;
    use aptos_framework::timestamp;
    use aptos_names::domains;
    use aptos_names_v2_1::v2_1_domains;
    use router::router::{
        domain_admin_transfer_subdomain,
        get_owner_addr,
        get_primary_name,
        is_name_owner,
        register_subdomain,
        set_primary_name
    };

    /// This doesn't really matter because we the subdomain expiration policy that
    /// means the expiration is inherited from the domain.
    const REGISTRATION_DURATION_SECONDS: u64 = 60 * 60 * 24;

    // Follow the domain expiration.
    const SUBDOMAIN_POLICY_LOOKUP_DOMAIN_EXPIRATION: u8 = 1;

    /// Hard cap on the length of a subdomain or domain string we accept. ANS itself
    /// also enforces a limit; this is a defensive belt-and-braces check.
    const MAX_NAME_LENGTH: u64 = 64;

    /// This subdomain manager is disabled at the moment.
    const E_NOT_ENABLED: u64 = 1;

    /// No one owns this domain / it doesn't exist.
    const E_NO_DOMAIN_OWNER: u64 = 2;

    /// You cannot make a manager for this domain because you don't own it.
    const E_NOT_DOMAIN_OWNER: u64 = 3;

    /// You cannot claim a subdomain without the admin's approval.
    const E_CAN_ONLY_CLAIM_WITH_ADMIN_APPROVAL: u64 = 4;

    /// Only the admin is authorized to perform this operation.
    const E_NOT_ADMIN: u64 = 5;

    /// You have already claimed a subdomain.
    const E_CALLER_HAS_ALREADY_CLAIMED: u64 = 6;

    /// The subdomain has already been claimed by another address.
    const E_SUBDOMAIN_ALREADY_CLAIMED: u64 = 7;

    /// You cannot claim this subdomain because someone else already owns the top level domain with the same name.
    const E_CANNOT_CLAIM_SUBDOMAIN_IF_DOMAIN_OWNED_BY_OTHER_ADDRESS: u64 = 8;

    /// The supplied name (domain or subdomain) is empty.
    const E_EMPTY_NAME: u64 = 9;

    /// The supplied name (domain or subdomain) exceeds `MAX_NAME_LENGTH`.
    const E_NAME_TOO_LONG: u64 = 10;

    struct SubdomainManager has key {
        /// The domain that we are managing subdomains for.
        domain: String,
        /// If true, only keyless accounts can claim a subdomain.
        keyless_only: bool,
        /// If true, `claim_subdomain_without_admin_approval` will be disabled.
        claim_only_with_admin_approval: bool,
        /// The addresses that have claimed a subdomain, mapped to the subdomain they claimed.
        claimed_addresses: BigOrderedMap<address, String>,
        /// Inverse mapping from subdomain back to the address that originally claimed
        /// it. Used by `reclaim_subdomain` to find the original claimer reliably even
        /// if the holder later transfers or retargets the subdomain.
        subdomain_to_claimer: BigOrderedMap<String, address>,
        /// If false, the manager is disabled and people cannot claim subdomains.
        is_enabled: bool,
        extend_ref: ExtendRef,
        delete_ref: DeleteRef
    }

    #[event]
    struct ManagerCreatedEvent has drop, store {
        manager: address,
        admin: address,
        domain: String,
        keyless_only: bool,
        claim_only_with_admin_approval: bool
    }

    #[event]
    struct ManagerEnabledChangedEvent has drop, store {
        manager: address,
        is_enabled: bool
    }

    #[event]
    struct ManagerDeletedEvent has drop, store {
        manager: address,
        admin: address,
        domain: String
    }

    #[event]
    struct SubdomainClaimedEvent has drop, store {
        manager: address,
        claimer_address: address,
        subdomain: String
    }

    #[event]
    struct SubdomainReclaimedEvent has drop, store {
        manager: address,
        subdomain: String,
        prior_claimer: address
    }

    #[event]
    struct SubdomainForceRegisteredEvent has drop, store {
        manager: address,
        subdomain: String
    }

    /// Used purely to enable better error messages.
    enum SubdomainAvailableResult {
        AVAILABLE,
        SUBDOMAIN_ALREADY_CLAIMED,
        CANNOT_CLAIM_SUBDOMAIN_IF_DOMAIN_OWNED_BY_OTHER_ADDRESS
    }

    /// Create a new manager for a domain. The caller must own the domain. Ownership
    /// of the domain will be transferred to the manager.
    public entry fun create_manager(
        caller: &signer,
        domain: String,
        keyless_only: bool,
        claim_only_with_admin_approval: bool
    ) {
        create_manager_inner(
            caller,
            domain,
            keyless_only,
            claim_only_with_admin_approval
        );
    }

    fun create_manager_inner(
        caller: &signer,
        domain: String,
        keyless_only: bool,
        claim_only_with_admin_approval: bool
    ): Object<SubdomainManager> {
        assert_valid_name(&domain);

        let caller_address = signer::address_of(caller);

        // Confirm the caller owns the domain.
        let owner_addr = get_owner_addr(domain, option::none());
        assert!(
            owner_addr.is_some(),
            error::invalid_state(E_NO_DOMAIN_OWNER)
        );
        assert!(
            *owner_addr.borrow() == caller_address,
            error::permission_denied(E_NOT_DOMAIN_OWNER)
        );

        // Create an object for the manager.
        let manager_constructor_ref = object::create_object(caller_address);

        // Create the manager data.
        let manager_ = SubdomainManager {
            domain,
            keyless_only,
            claim_only_with_admin_approval,
            // `new_with_config(0, 0, true)` autoselects degrees and enables slot
            // reuse; required because `String` is variable-sized so `new()` fails.
            claimed_addresses: big_ordered_map::new_with_config(0, 0, true),
            subdomain_to_claimer: big_ordered_map::new_with_config(0, 0, true),
            is_enabled: true,
            extend_ref: manager_constructor_ref.generate_extend_ref(),
            delete_ref: manager_constructor_ref.generate_delete_ref()
        };
        let manager_signer = manager_constructor_ref.generate_signer();

        // Move the manager data to the manager object.
        move_to(&manager_signer, manager_);

        // Transfer ownership of the domain (the token) to the manager. TODO: Is this
        // sufficient, or do I need to do all that v1 stuff in router::transfer_name.
        let manager_address = manager_constructor_ref.address_from_constructor_ref();
        let domain_token_address = v2_1_domains::get_token_addr(domain, option::none());
        object::transfer(
            caller,
            object::address_to_object<v2_1_domains::NameRecord>(domain_token_address),
            manager_address
        );

        event::emit(
            ManagerCreatedEvent {
                manager: manager_address,
                admin: caller_address,
                domain,
                keyless_only,
                claim_only_with_admin_approval
            }
        );

        manager_constructor_ref.object_from_constructor_ref()
    }

    /// Set whether the manager is enabled or not.
    public entry fun set_enabled(
        caller: &signer, manager: Object<SubdomainManager>, is_enabled: bool
    ) {
        assert_admin(caller, manager);

        let manager_address = manager.object_address();
        let manager_ = &mut SubdomainManager[manager_address];

        manager_.is_enabled = is_enabled;

        event::emit(ManagerEnabledChangedEvent { manager: manager_address, is_enabled });
    }

    /// Claim a subdomain. It will be pointed at and sent to the receiver's address.
    /// The caller must pass in `public_key_bytes` if `keyless_only` is true. Otherwise
    /// they can just pass in an empty vector. The admin (owner of the manager object)
    /// must cosign this function call.
    public entry fun claim_subdomain(
        caller: &signer,
        admin: &signer,
        manager: Object<SubdomainManager>,
        subdomain: String,
        public_key_bytes: vector<u8>
    ) {
        assert_admin(admin, manager);
        assert_valid_name(&subdomain);

        let manager_address = manager.object_address();
        let manager_ = &mut SubdomainManager[manager_address];

        claim_subdomain_inner(
            caller,
            manager_address,
            manager_,
            subdomain,
            public_key_bytes
        );
    }

    /// Claim a subdomain. It will be pointed at and sent to the receiver's address.
    /// The caller must pass in `public_key_bytes` if `keyless_only` is true. Otherwise
    /// they can just pass in an empty vector. This can only be called if the manager
    /// was created with `claim_only_with_admin_approval` set to false.
    public entry fun claim_subdomain_without_admin_approval(
        caller: &signer,
        manager: Object<SubdomainManager>,
        subdomain: String,
        public_key_bytes: vector<u8>
    ) {
        assert_valid_name(&subdomain);

        let manager_address = manager.object_address();
        let manager_ = &mut SubdomainManager[manager_address];

        // Bail if `claim_only_with_admin_approval` is true.
        if (manager_.claim_only_with_admin_approval) {
            abort error::permission_denied(E_CAN_ONLY_CLAIM_WITH_ADMIN_APPROVAL)
        };

        claim_subdomain_inner(
            caller,
            manager_address,
            manager_,
            subdomain,
            public_key_bytes
        );
    }

    fun claim_subdomain_inner(
        caller: &signer,
        manager_address: address,
        manager_: &mut SubdomainManager,
        subdomain: String,
        public_key_bytes: vector<u8>
    ) {
        // Make sure the manager is enabled.
        assert!(manager_.is_enabled, error::unavailable(E_NOT_ENABLED));

        let caller_address = signer::address_of(caller);

        // Ensure the caller has not already claimed a subdomain.
        let caller_has_already_claimed =
            manager_.claimed_addresses.contains(&caller_address);
        assert!(
            !caller_has_already_claimed,
            error::invalid_state(E_CALLER_HAS_ALREADY_CLAIMED)
        );

        // Check if the subdomain is available for the caller to claim.
        let subdomain_available_result =
            is_subdomain_available_for_addr(manager_.domain, subdomain, caller_address);
        match(subdomain_available_result) {
            SubdomainAvailableResult::AVAILABLE => {},
            SubdomainAvailableResult::SUBDOMAIN_ALREADY_CLAIMED => {
                abort error::permission_denied(E_SUBDOMAIN_ALREADY_CLAIMED)
            },
            SubdomainAvailableResult::CANNOT_CLAIM_SUBDOMAIN_IF_DOMAIN_OWNED_BY_OTHER_ADDRESS => {
                abort error::permission_denied(
                    E_CANNOT_CLAIM_SUBDOMAIN_IF_DOMAIN_OWNED_BY_OTHER_ADDRESS
                )
            }
        };

        // If `keyless_only` is true, validate that the caller is a keyless account.
        if (manager_.keyless_only) {
            keyless::assert_is_keyless(caller_address, public_key_bytes);
        };

        // Record that the caller has claimed a subdomain. Maintain both directions
        // of the mapping so `reclaim_subdomain` can find the original claimer.
        manager_.claimed_addresses.add(caller_address, subdomain);
        manager_.subdomain_to_claimer.add(subdomain, caller_address);
        event::emit(
            SubdomainClaimedEvent {
                manager: manager_address,
                claimer_address: caller_address,
                subdomain
            }
        );

        // We need to set a expiration time in the future, even though it will be ignored and follow the domain expiration
        let expiration_time_sec: u64 =
            timestamp::now_seconds() + REGISTRATION_DURATION_SECONDS;

        // Register the subdomain to the manager itself and point it at the
        // caller. We deliberately pass `to_addr = none` to skip the router's
        // internal `transfer_name` step, which uses gated `object::transfer`.
        // After the first claim the router disables ungated transfer on the
        // subdomain, so on a re-registration (post-`reclaim`) that gated
        // transfer aborts. We do the ownership move ourselves below using
        // `transfer_with_ref` semantics, which bypass that check.
        let object_signer = manager_.extend_ref.generate_signer_for_extending();
        register_subdomain(
            &object_signer,
            manager_.domain,
            subdomain,
            expiration_time_sec,
            SUBDOMAIN_POLICY_LOOKUP_DOMAIN_EXPIRATION,
            false,
            option::some(caller_address),
            option::none()
        );

        // Transfer ownership of the subdomain to the caller. Uses the stored
        // `transfer_ref` inside the router → v2_1 domains, which bypasses
        // `allow_ungated_transfer`, so this works on both first and repeat
        // registrations of the same subdomain.
        domain_admin_transfer_subdomain(
            &object_signer,
            manager_.domain,
            subdomain,
            caller_address,
            option::some(caller_address)
        );

        // Set this as the account's primary name if they don't already have one.
        let (_, primary_name) = get_primary_name(caller_address);
        if (primary_name.is_none()) {
            set_primary_name(
                caller,
                manager_.domain,
                option::some(subdomain)
            );
        };
    }

    #[view]
    /// Check if the given address is allowed to claim a subdomain based on whether they
    /// have already claimed a subdomain.
    public fun can_claim(
        manager: Object<SubdomainManager>, address: address
    ): bool {
        let manager_address = manager.object_address();
        let manager_ = &SubdomainManager[manager_address];
        !manager_.claimed_addresses.contains(&address)
    }

    /// If the name is registerable in v1, the name can only be registered if it is also
    /// available in v2. Else the name is registered and active in v1, then the name can
    /// only be registered if we have burned the token (sent it to the aptos_names).
    fun can_register(domain: String, subdomain: Option<String>): bool {
        let registerable_in_v1 = domains::name_is_expired_past_grace(subdomain, domain);
        if (registerable_in_v1) {
            v2_1_domains::is_name_registerable(domain, subdomain)
        } else {
            let (is_burned, _token_id) =
                domains::is_token_owner(@aptos_names, subdomain, domain);
            is_burned
        }
    }

    #[view]
    /// Check if the subdomain is available for the address to claim.
    public fun is_subdomain_available_for_addr(
        domain: String, subdomain: String, address: address
    ): SubdomainAvailableResult {
        // Can't claim a subdomain that is already claimed.
        if (!can_register(domain, option::some(subdomain))) {
            return SubdomainAvailableResult::SUBDOMAIN_ALREADY_CLAIMED
        };

        // If the domain is not registered, then the subdomain is available.
        if (can_register(subdomain, option::none())) {
            return SubdomainAvailableResult::AVAILABLE
        };

        // If the desired subdomain is already registered as a domain, then only
        // the owner of that top-level domain may claim the matching subdomain.
        // `is_name_owner` returns true iff `address` IS the owner, so we block
        // when it returns false.
        if (!is_name_owner(address, subdomain, option::none())) {
            return SubdomainAvailableResult::CANNOT_CLAIM_SUBDOMAIN_IF_DOMAIN_OWNED_BY_OTHER_ADDRESS
        };

        SubdomainAvailableResult::AVAILABLE
    }

    /// Reclaim a subdomain from someone who claimed it. Unlike `force_register_subdomain`,
    /// which essentially just parks the domain so no one else can claim it, this makes
    /// it available for someone to claim again.
    public entry fun reclaim_subdomain(
        caller: &signer, manager: Object<SubdomainManager>, subdomain: String
    ) {
        assert_admin(caller, manager);
        assert_valid_name(&subdomain);

        let manager_address = manager.object_address();
        let manager_ = &mut SubdomainManager[manager_address];

        // Look up the original claimer (not the current router target address: the
        // holder may have transferred or retargeted the subdomain since claiming).
        // Both directions of the mapping are then cleared so the claimer is once
        // again eligible to claim a new subdomain.
        let prior_claimer = manager_.subdomain_to_claimer.remove(&subdomain);
        manager_.claimed_addresses.remove(&prior_claimer);

        // Transfer ownership of the "ANS app signer", remove the target address. This
        // makes it eligible for claiming again.
        let manager_object_signer = manager_.extend_ref.generate_signer_for_extending();
        domain_admin_transfer_subdomain(
            &manager_object_signer,
            manager_.domain,
            subdomain,
            v2_1_domains::get_app_signer_addr(),
            option::none()
        );

        event::emit(
            SubdomainReclaimedEvent { manager: manager_address, subdomain, prior_claimer }
        );
    }

    /// Forcibly register a subdomain. It will be sent to and pointed at the manager
    /// object's address. You can use this to reserve subdomains. This ignores the
    /// is_enabled flag.
    public entry fun force_register_subdomain(
        caller: &signer, manager: Object<SubdomainManager>, subdomain: String
    ) {
        assert_admin(caller, manager);
        assert_valid_name(&subdomain);

        let manager_address = manager.object_address();
        let manager_ = &SubdomainManager[manager_address];

        // We need to set a expiration time in the future, even though it will be
        // ignored and follow the domain expiration.
        let expiration_time_sec: u64 =
            timestamp::now_seconds() + REGISTRATION_DURATION_SECONDS;

        let manager_object_signer = manager_.extend_ref.generate_signer_for_extending();
        register_subdomain(
            &manager_object_signer,
            manager_.domain,
            subdomain,
            expiration_time_sec,
            SUBDOMAIN_POLICY_LOOKUP_DOMAIN_EXPIRATION,
            false,
            option::some(manager_address),
            option::some(manager_address)
        );

        event::emit(SubdomainForceRegisteredEvent { manager: manager_address, subdomain });
    }

    /// Return the domain owned by a manager to the caller (the admin), delete the manager.
    public entry fun delete_manager(
        caller: &signer, manager: Object<SubdomainManager>
    ) {
        assert_admin(caller, manager);

        let caller_address = signer::address_of(caller);
        let manager_address = manager.object_address();
        let manager_ = move_from<SubdomainManager>(manager_address);

        // Transfer the domain back to the caller.
        let domain_token_address =
            v2_1_domains::get_token_addr(manager_.domain, option::none());
        object::transfer(
            caller,
            object::address_to_object<v2_1_domains::NameRecord>(domain_token_address),
            caller_address
        );

        let SubdomainManager {
            domain,
            keyless_only: _keyless_only,
            claim_only_with_admin_approval: _claim_only_with_admin_approval,
            claimed_addresses,
            subdomain_to_claimer,
            is_enabled: _is_enabled,
            extend_ref: _extend_ref,
            delete_ref
        } = manager_;

        // Both maps are destroyed even if non-empty: the on-chain mapping state
        // is dropped along with the manager. The values are primitives so no
        // per-value cleanup is required.
        claimed_addresses.destroy(|_v| {});
        subdomain_to_claimer.destroy(|_v| {});

        event::emit(
            ManagerDeletedEvent { manager: manager_address, admin: caller_address, domain }
        );

        // Delete the manager.
        delete_ref.delete();
    }

    /// Aborts unless `caller` is the current owner of `manager`.
    inline fun assert_admin(
        caller: &signer, manager: Object<SubdomainManager>
    ) {
        assert!(
            manager.is_owner(signer::address_of(caller)),
            error::permission_denied(E_NOT_ADMIN)
        );
    }

    /// Validates that a domain or subdomain string is non-empty and within the
    /// length cap. ANS itself enforces stricter rules; this is defence in depth
    /// so the manager surfaces clear error codes early.
    inline fun assert_valid_name(name: &String) {
        let len = name.length();
        assert!(len > 0, error::invalid_argument(E_EMPTY_NAME));
        assert!(len <= MAX_NAME_LENGTH, error::invalid_argument(E_NAME_TOO_LONG));
    }

    // ============ View accessors ============

    #[view]
    /// Return the domain managed by `manager`.
    public fun get_domain(manager: Object<SubdomainManager>): String {
        SubdomainManager[manager.object_address()].domain
    }

    #[view]
    /// Return whether the manager is currently enabled for new claims.
    public fun is_enabled(manager: Object<SubdomainManager>): bool {
        SubdomainManager[manager.object_address()].is_enabled
    }

    #[view]
    /// Return whether the manager only allows keyless accounts to claim.
    public fun is_keyless_only(manager: Object<SubdomainManager>): bool {
        SubdomainManager[manager.object_address()].keyless_only
    }

    #[view]
    /// Return whether claims always require the admin's cosignature.
    public fun requires_admin_approval(manager: Object<SubdomainManager>): bool {
        SubdomainManager[manager.object_address()].claim_only_with_admin_approval
    }

    #[view]
    /// Return the subdomain `claimer` claimed via this manager, or `none` if
    /// they have not claimed one.
    public fun claimed_subdomain_for(
        manager: Object<SubdomainManager>, claimer: address
    ): Option<String> {
        let manager_ = &SubdomainManager[manager.object_address()];
        if (manager_.claimed_addresses.contains(&claimer)) {
            option::some(*manager_.claimed_addresses.borrow(&claimer))
        } else {
            option::none()
        }
    }

    #[view]
    /// Return the address that originally claimed `subdomain` via this manager,
    /// or `none` if the subdomain was never claimed (or has since been reclaimed).
    public fun claimer_for_subdomain(
        manager: Object<SubdomainManager>, subdomain: String
    ): Option<address> {
        let manager_ = &SubdomainManager[manager.object_address()];
        if (manager_.subdomain_to_claimer.contains(&subdomain)) {
            option::some(*manager_.subdomain_to_claimer.borrow(&subdomain))
        } else {
            option::none()
        }
    }

    ///////////////////////////////
    // TESTS
    ///////////////////////////////

    #[test_only]
    use aptos_framework::account;
    #[test_only]
    use aptos_framework::aptos_coin::AptosCoin;
    #[test_only]
    use aptos_framework::coin::{Self, MintCapability};
    #[test_only]
    use aptos_token::token;
    #[test_only]
    use aptos_std::string;
    #[test_only]
    use aptos_names::config;
    #[test_only]
    use aptos_names_v2_1::v2_1_config;
    #[test_only]
    use router::router;

    #[test_only]
    const TESTING_DOMAIN: vector<u8> = b"mydomain";

    #[test_only]
    public fun set_up_testing_time_env(
        aptos_framework: &signer, timestamp: u64
    ) {
        timestamp::set_time_has_started_for_testing(aptos_framework);
        timestamp::update_global_time_for_test_secs(timestamp);
    }

    #[test_only]
    fun get_mint_cap(aptos_framework: &signer): MintCapability<AptosCoin> {
        let (burn_cap, freeze_cap, mint_cap) =
            coin::initialize<AptosCoin>(
                aptos_framework,
                string::utf8(b"TC"),
                string::utf8(b"TC"),
                8,
                false
            );
        coin::destroy_freeze_cap(freeze_cap);
        coin::destroy_burn_cap(burn_cap);
        mint_cap
    }

    #[test_only]
    fun create_test_account(
        mint_cap: &MintCapability<AptosCoin>, account: &signer
    ) {
        account::create_account_for_test(signer::address_of(account));
        coin::register<AptosCoin>(account);
        let coins = coin::mint<AptosCoin>(800_000_000, mint_cap);
        coin::deposit(signer::address_of(account), coins);
        token::initialize_token_store(account);
    }

    #[test_only]
    fun setup_test(
        router: &signer,
        aptos_names: &signer,
        aptos_names_v2_1: &signer,
        manager: &signer,
        user1: &signer,
        user2: &signer,
        aptos_framework: &signer
    ) {
        set_up_testing_time_env(aptos_framework, 1746520524);

        let mint_cap = get_mint_cap(aptos_framework);

        coin::create_coin_conversion_map(aptos_framework);
        coin::create_pairing<AptosCoin>(aptos_framework);

        create_test_account(&mint_cap, router);
        create_test_account(&mint_cap, aptos_names);
        create_test_account(&mint_cap, aptos_names_v2_1);
        create_test_account(&mint_cap, manager);
        create_test_account(&mint_cap, user1);
        create_test_account(&mint_cap, user2);
        create_test_account(&mint_cap, aptos_framework);

        coin::destroy_mint_cap(mint_cap);

        router::init_module_for_test(router);
        domains::init_module_for_test(aptos_names);
        v2_1_domains::init_module_for_test(aptos_names_v2_1);
        config::set_fund_destination_address_test_only(
            signer::address_of(aptos_framework)
        );
        v2_1_config::set_fund_destination_address_test_only(
            signer::address_of(aptos_framework)
        );
        router::set_mode(router, 1);
    }

    #[test_only]
    /// Convenience helper used by all the new tests below: runs `setup_test`,
    /// registers `TESTING_DOMAIN` to `manager`, and creates a manager object
    /// owned by `manager` with the supplied policy flags.
    fun setup_with_manager(
        router: &signer,
        aptos_names: &signer,
        aptos_names_v2_1: &signer,
        manager: &signer,
        user1: &signer,
        user2: &signer,
        aptos_framework: &signer,
        keyless_only: bool,
        claim_only_with_admin_approval: bool
    ): Object<SubdomainManager> {
        setup_test(
            router,
            aptos_names,
            aptos_names_v2_1,
            manager,
            user1,
            user2,
            aptos_framework
        );

        let manager_address = signer::address_of(manager);
        router::register_domain(
            manager,
            string::utf8(TESTING_DOMAIN),
            60 * 60 * 24 * 365,
            option::some(manager_address),
            option::some(manager_address)
        );

        create_manager_inner(
            manager,
            string::utf8(TESTING_DOMAIN),
            keyless_only,
            claim_only_with_admin_approval
        )
    }

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x101,
            user2 = @0x102,
            aptos_framework = @aptos_framework
        )
    ]
    public entry fun test_basic_flow(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer
    ) {
        setup_test(
            &router,
            &aptos_names,
            &aptos_names_v2_1,
            &manager,
            &user1,
            &user2,
            &aptos_framework
        );

        let manager_address = signer::address_of(&manager);
        router::register_domain(
            &manager,
            string::utf8(TESTING_DOMAIN),
            60 * 60 * 24 * 365,
            option::some(manager_address),
            option::some(manager_address)
        );

        let sub1 = string::utf8(b"mysub1");

        // Create the manager.
        let manager_object =
            create_manager_inner(
                &manager,
                string::utf8(TESTING_DOMAIN),
                false,
                false
            );

        // Claim a subdomain as user 1.
        claim_subdomain_without_admin_approval(&user1, manager_object, sub1, vector[]);

        // Confirm that user 1 has the subdomain.
        let sub1_target_addr =
            router::get_target_addr(string::utf8(TESTING_DOMAIN), option::some(sub1));
        assert!(sub1_target_addr.is_some(), 0);
        assert!(sub1_target_addr.borrow() == &signer::address_of(&user1), 0);

        // Reclaim a subdomain as the admin.
        reclaim_subdomain(&manager, manager_object, sub1);

        // Confirm that user 1 no longer has the subdomain.
        let sub1_target_addr =
            router::get_target_addr(string::utf8(TESTING_DOMAIN), option::some(sub1));
        assert!(sub1_target_addr.is_none(), 0);

        // Confirm that user 2 can claim the subdomain now.
        claim_subdomain_without_admin_approval(&user2, manager_object, sub1, vector[]);

        // Confirm that user 2 has the subdomain.
        let sub1_target_addr =
            router::get_target_addr(string::utf8(TESTING_DOMAIN), option::some(sub1));
        assert!(sub1_target_addr.is_some(), 0);
        assert!(sub1_target_addr.borrow() == &signer::address_of(&user2), 0);
    }

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x123,
            user2 = @0x456,
            aptos_framework = @0x1
        )
    ]
    #[expected_failure(abort_code = 327687, location = Self)]
    fun test_cannot_claim_existing_subdomain(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer
    ) {
        setup_test(
            &router,
            &aptos_names,
            &aptos_names_v2_1,
            &manager,
            &user1,
            &user2,
            &aptos_framework
        );

        let manager_address = signer::address_of(&manager);
        router::register_domain(
            &manager,
            string::utf8(TESTING_DOMAIN),
            60 * 60 * 24 * 365,
            option::some(manager_address),
            option::some(manager_address)
        );

        let sub1 = string::utf8(b"mysub1");

        // Create the manager.
        let manager_object =
            create_manager_inner(
                &manager,
                string::utf8(TESTING_DOMAIN),
                false,
                false
            );

        // Claim a subdomain as user 1.
        claim_subdomain_without_admin_approval(&user1, manager_object, sub1, vector[]);

        // Confirm that user 1 has the subdomain.
        let sub1_target_addr =
            router::get_target_addr(string::utf8(TESTING_DOMAIN), option::some(sub1));
        assert!(sub1_target_addr.is_some(), 0);
        assert!(sub1_target_addr.borrow() == &signer::address_of(&user1), 0);

        // Attempt to claim the same subdomain as user 2, which should fail.
        claim_subdomain_without_admin_approval(&user2, manager_object, sub1, vector[]);
    }

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x123,
            user2 = @0x456,
            aptos_framework = @0x1
        )
    ]
    #[expected_failure(abort_code = 196614, location = Self)]
    fun test_cannot_claim_twice(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer
    ) {
        setup_test(
            &router,
            &aptos_names,
            &aptos_names_v2_1,
            &manager,
            &user1,
            &user2,
            &aptos_framework
        );

        let manager_address = signer::address_of(&manager);
        router::register_domain(
            &manager,
            string::utf8(TESTING_DOMAIN),
            60 * 60 * 24 * 365,
            option::some(manager_address),
            option::some(manager_address)
        );

        let sub1 = string::utf8(b"mysub1");
        let sub2 = string::utf8(b"mysub2");
        // Create the manager.
        let manager_object =
            create_manager_inner(
                &manager,
                string::utf8(TESTING_DOMAIN),
                false,
                false
            );

        // Claim a subdomain as user 1.
        claim_subdomain_without_admin_approval(&user1, manager_object, sub1, vector[]);

        // Confirm that user 1 has the subdomain.
        let sub1_target_addr =
            router::get_target_addr(string::utf8(TESTING_DOMAIN), option::some(sub1));
        assert!(sub1_target_addr.is_some(), 0);
        assert!(sub1_target_addr.borrow() == &signer::address_of(&user1), 0);

        // Attempt to claim another subdomain, which should fail.
        claim_subdomain_without_admin_approval(&user1, manager_object, sub2, vector[]);
    }

    // ============ View accessor tests ============

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x101,
            user2 = @0x102,
            aptos_framework = @aptos_framework
        )
    ]
    fun test_view_accessors(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer
    ) {
        let manager_object =
            setup_with_manager(
                &router,
                &aptos_names,
                &aptos_names_v2_1,
                &manager,
                &user1,
                &user2,
                &aptos_framework,
                false,
                true
            );

        assert!(get_domain(manager_object) == string::utf8(TESTING_DOMAIN), 100);
        assert!(is_enabled(manager_object), 101);
        assert!(!is_keyless_only(manager_object), 102);
        assert!(requires_admin_approval(manager_object), 103);

        let user1_addr = signer::address_of(&user1);
        assert!(can_claim(manager_object, user1_addr), 104);
        assert!(claimed_subdomain_for(manager_object, user1_addr).is_none(), 105);
        assert!(
            claimer_for_subdomain(manager_object, string::utf8(b"unused")).is_none(),
            106
        );
    }

    // ============ set_enabled tests ============

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x101,
            user2 = @0x102,
            aptos_framework = @aptos_framework
        )
    ]
    fun test_set_enabled_round_trip(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer
    ) {
        let manager_object =
            setup_with_manager(
                &router,
                &aptos_names,
                &aptos_names_v2_1,
                &manager,
                &user1,
                &user2,
                &aptos_framework,
                false,
                false
            );

        assert!(is_enabled(manager_object), 0);

        set_enabled(&manager, manager_object, false);
        assert!(!is_enabled(manager_object), 1);

        set_enabled(&manager, manager_object, true);
        assert!(is_enabled(manager_object), 2);
    }

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x101,
            user2 = @0x102,
            aptos_framework = @aptos_framework
        )
    ]
    #[expected_failure(abort_code = 327685, location = Self)]
    fun test_set_enabled_unauthorized(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer
    ) {
        let manager_object =
            setup_with_manager(
                &router,
                &aptos_names,
                &aptos_names_v2_1,
                &manager,
                &user1,
                &user2,
                &aptos_framework,
                false,
                false
            );

        // user1 is not the admin, so this must abort with E_NOT_ADMIN.
        set_enabled(&user1, manager_object, false);
    }

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x101,
            user2 = @0x102,
            aptos_framework = @aptos_framework
        )
    ]
    #[expected_failure(abort_code = 851969, location = Self)]
    fun test_disabled_manager_rejects_claim(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer
    ) {
        let manager_object =
            setup_with_manager(
                &router,
                &aptos_names,
                &aptos_names_v2_1,
                &manager,
                &user1,
                &user2,
                &aptos_framework,
                false,
                false
            );

        set_enabled(&manager, manager_object, false);

        // Should abort with E_NOT_ENABLED (UNAVAILABLE category).
        claim_subdomain_without_admin_approval(
            &user1,
            manager_object,
            string::utf8(b"mysub1"),
            vector[]
        );
    }

    // ============ claim_only_with_admin_approval tests ============

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x101,
            user2 = @0x102,
            aptos_framework = @aptos_framework
        )
    ]
    fun test_claim_with_admin_approval_happy(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer
    ) {
        let manager_object =
            setup_with_manager(
                &router,
                &aptos_names,
                &aptos_names_v2_1,
                &manager,
                &user1,
                &user2,
                &aptos_framework,
                false,
                true
            );

        let sub1 = string::utf8(b"mysub1");
        claim_subdomain(
            &user1,
            &manager,
            manager_object,
            sub1,
            vector[]
        );

        let target =
            router::get_target_addr(string::utf8(TESTING_DOMAIN), option::some(sub1));
        assert!(target.is_some(), 0);
        assert!(target.borrow() == &signer::address_of(&user1), 1);

        // The view accessors should now reflect the claim.
        assert!(!can_claim(manager_object, signer::address_of(&user1)), 2);
        assert!(
            claimed_subdomain_for(manager_object, signer::address_of(&user1))
                == option::some(sub1),
            3
        );
        assert!(
            claimer_for_subdomain(manager_object, sub1)
                == option::some(signer::address_of(&user1)),
            4
        );
    }

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x101,
            user2 = @0x102,
            aptos_framework = @aptos_framework
        )
    ]
    #[expected_failure(abort_code = 327685, location = Self)]
    fun test_claim_with_admin_approval_wrong_admin(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer
    ) {
        let manager_object =
            setup_with_manager(
                &router,
                &aptos_names,
                &aptos_names_v2_1,
                &manager,
                &user1,
                &user2,
                &aptos_framework,
                false,
                true
            );

        // user2 is not the admin, so this must abort with E_NOT_ADMIN.
        claim_subdomain(
            &user1,
            &user2,
            manager_object,
            string::utf8(b"mysub1"),
            vector[]
        );
    }

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x101,
            user2 = @0x102,
            aptos_framework = @aptos_framework
        )
    ]
    #[expected_failure(abort_code = 327684, location = Self)]
    fun test_claim_only_with_admin_approval_blocks_without(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer
    ) {
        let manager_object =
            setup_with_manager(
                &router,
                &aptos_names,
                &aptos_names_v2_1,
                &manager,
                &user1,
                &user2,
                &aptos_framework,
                false,
                true
            );

        // Manager was created with claim_only_with_admin_approval=true, so the
        // unrestricted entry point must abort with E_CAN_ONLY_CLAIM_WITH_ADMIN_APPROVAL.
        claim_subdomain_without_admin_approval(
            &user1,
            manager_object,
            string::utf8(b"mysub1"),
            vector[]
        );
    }

    // ============ Reclaim / inverse-mapping tests ============

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x101,
            user2 = @0x102,
            aptos_framework = @aptos_framework
        )
    ]
    fun test_reclaim_clears_inverse_mapping(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer
    ) {
        let manager_object =
            setup_with_manager(
                &router,
                &aptos_names,
                &aptos_names_v2_1,
                &manager,
                &user1,
                &user2,
                &aptos_framework,
                false,
                false
            );

        let sub1 = string::utf8(b"mysub1");
        let user1_addr = signer::address_of(&user1);

        claim_subdomain_without_admin_approval(&user1, manager_object, sub1, vector[]);

        // Both directions of the mapping should now be populated.
        assert!(
            claimed_subdomain_for(manager_object, user1_addr) == option::some(sub1), 0
        );
        assert!(
            claimer_for_subdomain(manager_object, sub1) == option::some(user1_addr), 1
        );

        reclaim_subdomain(&manager, manager_object, sub1);

        // Both directions should be cleared, so the original claimer can claim
        // a different subdomain afterwards.
        assert!(can_claim(manager_object, user1_addr), 2);
        assert!(claimed_subdomain_for(manager_object, user1_addr).is_none(), 3);
        assert!(claimer_for_subdomain(manager_object, sub1).is_none(), 4);

        // user1 now claims a different subdomain to confirm they were freed up.
        let sub2 = string::utf8(b"mysub2");
        claim_subdomain_without_admin_approval(&user1, manager_object, sub2, vector[]);
        assert!(
            claimer_for_subdomain(manager_object, sub2) == option::some(user1_addr), 5
        );
    }

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x101,
            user2 = @0x102,
            aptos_framework = @aptos_framework
        )
    ]
    #[expected_failure(abort_code = 327685, location = Self)]
    fun test_reclaim_unauthorized(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer
    ) {
        let manager_object =
            setup_with_manager(
                &router,
                &aptos_names,
                &aptos_names_v2_1,
                &manager,
                &user1,
                &user2,
                &aptos_framework,
                false,
                false
            );

        let sub1 = string::utf8(b"mysub1");
        claim_subdomain_without_admin_approval(&user1, manager_object, sub1, vector[]);

        // user2 is not the admin, so this must abort with E_NOT_ADMIN.
        reclaim_subdomain(&user2, manager_object, sub1);
    }

    // ============ force_register_subdomain tests ============

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x101,
            user2 = @0x102,
            aptos_framework = @aptos_framework
        )
    ]
    fun test_force_register_subdomain(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer
    ) {
        let manager_object =
            setup_with_manager(
                &router,
                &aptos_names,
                &aptos_names_v2_1,
                &manager,
                &user1,
                &user2,
                &aptos_framework,
                false,
                false
            );

        let parked = string::utf8(b"reserved");
        force_register_subdomain(&manager, manager_object, parked);

        // The parked subdomain is owned and pointed at the manager object.
        let target =
            router::get_target_addr(string::utf8(TESTING_DOMAIN), option::some(parked));
        assert!(target.is_some(), 0);
        assert!(target.borrow() == &manager_object.object_address(), 1);

        // No one is recorded as the claimer of the parked subdomain (since
        // `force_register_subdomain` doesn't update the claimed mappings) and
        // ordinary users still have a free claim slot for *other* subdomains.
        assert!(claimer_for_subdomain(manager_object, parked).is_none(), 2);
        assert!(can_claim(manager_object, signer::address_of(&user1)), 3);
    }

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x101,
            user2 = @0x102,
            aptos_framework = @aptos_framework
        )
    ]
    #[expected_failure(abort_code = 327685, location = Self)]
    fun test_force_register_unauthorized(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer
    ) {
        let manager_object =
            setup_with_manager(
                &router,
                &aptos_names,
                &aptos_names_v2_1,
                &manager,
                &user1,
                &user2,
                &aptos_framework,
                false,
                false
            );

        force_register_subdomain(&user1, manager_object, string::utf8(b"reserved"));
    }

    // ============ delete_manager tests ============

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x101,
            user2 = @0x102,
            aptos_framework = @aptos_framework
        )
    ]
    fun test_delete_manager_returns_domain(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer
    ) {
        let manager_object =
            setup_with_manager(
                &router,
                &aptos_names,
                &aptos_names_v2_1,
                &manager,
                &user1,
                &user2,
                &aptos_framework,
                false,
                false
            );

        // Claim something so the inner maps are non-empty when we destroy them.
        let sub1 = string::utf8(b"mysub1");
        claim_subdomain_without_admin_approval(&user1, manager_object, sub1, vector[]);

        delete_manager(&manager, manager_object);

        // After deletion the underlying domain token should be owned by the
        // admin again.
        let owner_addr =
            router::get_owner_addr(string::utf8(TESTING_DOMAIN), option::none());
        assert!(owner_addr.is_some(), 0);
        assert!(owner_addr.borrow() == &signer::address_of(&manager), 1);
    }

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x101,
            user2 = @0x102,
            aptos_framework = @aptos_framework
        )
    ]
    #[expected_failure(abort_code = 327685, location = Self)]
    fun test_delete_manager_unauthorized(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer
    ) {
        let manager_object =
            setup_with_manager(
                &router,
                &aptos_names,
                &aptos_names_v2_1,
                &manager,
                &user1,
                &user2,
                &aptos_framework,
                false,
                false
            );

        delete_manager(&user1, manager_object);
    }

    // ============ Input validation tests ============

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x101,
            user2 = @0x102,
            aptos_framework = @aptos_framework
        )
    ]
    #[expected_failure(abort_code = 65545, location = Self)]
    fun test_empty_subdomain_rejected(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer
    ) {
        let manager_object =
            setup_with_manager(
                &router,
                &aptos_names,
                &aptos_names_v2_1,
                &manager,
                &user1,
                &user2,
                &aptos_framework,
                false,
                false
            );

        claim_subdomain_without_admin_approval(
            &user1,
            manager_object,
            string::utf8(b""),
            vector[]
        );
    }

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x101,
            user2 = @0x102,
            aptos_framework = @aptos_framework
        )
    ]
    #[expected_failure(abort_code = 65546, location = Self)]
    fun test_too_long_subdomain_rejected(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer
    ) {
        let manager_object =
            setup_with_manager(
                &router,
                &aptos_names,
                &aptos_names_v2_1,
                &manager,
                &user1,
                &user2,
                &aptos_framework,
                false,
                false
            );

        // 65 characters: one over `MAX_NAME_LENGTH = 64`.
        claim_subdomain_without_admin_approval(
            &user1,
            manager_object,
            string::utf8(
                b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            vector[]
        );
    }

    // ============ create_manager negative tests ============

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x101,
            user2 = @0x102,
            aptos_framework = @aptos_framework
        )
    ]
    #[expected_failure(abort_code = 196610, location = Self)]
    fun test_create_manager_for_unowned_domain(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer
    ) {
        setup_test(
            &router,
            &aptos_names,
            &aptos_names_v2_1,
            &manager,
            &user1,
            &user2,
            &aptos_framework
        );

        // The domain has never been registered, so this must abort with
        // E_NO_DOMAIN_OWNER (INVALID_STATE category).
        create_manager_inner(
            &manager,
            string::utf8(b"unregistered"),
            false,
            false
        );
    }

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x101,
            user2 = @0x102,
            aptos_framework = @aptos_framework
        )
    ]
    #[expected_failure(abort_code = 327683, location = Self)]
    fun test_create_manager_not_domain_owner(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer
    ) {
        setup_test(
            &router,
            &aptos_names,
            &aptos_names_v2_1,
            &manager,
            &user1,
            &user2,
            &aptos_framework
        );

        let manager_address = signer::address_of(&manager);
        router::register_domain(
            &manager,
            string::utf8(TESTING_DOMAIN),
            60 * 60 * 24 * 365,
            option::some(manager_address),
            option::some(manager_address)
        );

        // user1 does not own TESTING_DOMAIN, so this must abort with
        // E_NOT_DOMAIN_OWNER.
        create_manager_inner(
            &user1,
            string::utf8(TESTING_DOMAIN),
            false,
            false
        );
    }

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x101,
            user2 = @0x102,
            aptos_framework = @aptos_framework
        )
    ]
    #[expected_failure(abort_code = 65545, location = Self)]
    fun test_create_manager_empty_domain(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer
    ) {
        setup_test(
            &router,
            &aptos_names,
            &aptos_names_v2_1,
            &manager,
            &user1,
            &user2,
            &aptos_framework
        );

        create_manager_inner(&manager, string::utf8(b""), false, false);
    }
}
