module addr::subdomain_manager {
    use addr::keyless;
    use std::error;
    use std::option::{Self, Option};
    use std::signer;
    use std::string::String;
    use aptos_std::smart_table::{Self, SmartTable};
    use aptos_std::object::{Self, Object, DeleteRef, ExtendRef};
    use aptos_framework::event;
    use aptos_framework::timestamp;
    use aptos_names::domains;
    use aptos_names_v2_1::v2_1_domains;
    use router::router::{
        Self,
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

    /// This subdomain manager is disabled at the moment.
    const ENOT_ENABLED: u64 = 1;

    /// No one owns this domain / it doesn't exist.
    const ENO_DOMAIN_OWNER: u64 = 2;

    /// You cannot make a manager for this domain because you don't own it.
    const ENOT_DOMAIN_OWNER: u64 = 3;

    /// You cannot claim a subdomain without the admin's approval.
    const E_CAN_ONLY_CLAIM_WITH_ADMIN_APPROVAL: u64 = 4;

    /// Only the admin is authorized to perform this operation.
    const ENOT_ADMIN: u64 = 5;

    /// You have already claimed a subdomain.
    const ECALLER_HAS_ALREADY_CLAIMED: u64 = 6;

    /// The subdomain has already been claimed by another address.
    const ESUBDOMAIN_ALREADY_CLAIMED: u64 = 7;

    /// You cannot claim this subdomain because someone else already owns the top level domain with the same name.
    const ECANNOT_CLAIM_SUBDOMAIN_IF_DOMAIN_OWNED_BY_OTHER_ADDRESS: u64 = 8;

    struct SubdomainManager has key {
        /// The domain that we are managing subdomains for.
        domain: String,
        /// If true, only keyless accounts can claim a subdomain.
        keyless_only: bool,
        /// If true, `claim_subdomain_without_admin_approval` will be disabled.
        claim_only_with_admin_approval: bool,
        /// The addresses that have claimed a subdomain, mapped to the subdomain they claimed.
        claimed_addresses: SmartTable<address, String>,
        /// If false, the manager is disabled and people cannot claim subdomains.
        is_enabled: bool,
        extend_ref: ExtendRef,
        delete_ref: DeleteRef
    }

    #[event]
    struct SubdomainClaimedEvent has drop, store {
        claimer_address: address,
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
        let caller_address = signer::address_of(caller);

        // Confirm the caller owns the domain.
        let owner_addr = get_owner_addr(domain, option::none());
        assert!(
            owner_addr.is_some(),
            error::invalid_state(ENO_DOMAIN_OWNER)
        );
        assert!(
            *owner_addr.borrow() == caller_address,
            error::invalid_state(ENOT_DOMAIN_OWNER)
        );

        // Create an object for the manager.
        let manager_constructor_ref = object::create_object(caller_address);

        // Create the manager data.
        let manager_ = SubdomainManager {
            domain,
            keyless_only,
            claim_only_with_admin_approval,
            claimed_addresses: smart_table::new(),
            is_enabled: true,
            extend_ref: object::generate_extend_ref(&manager_constructor_ref),
            delete_ref: object::generate_delete_ref(&manager_constructor_ref)
        };
        let manager_signer = object::generate_signer(&manager_constructor_ref);

        // Move the manager data to the manager object.
        move_to(&manager_signer, manager_);

        // Transfer ownership of the domain (the token) to the manager. TODO: Is this
        // sufficient, or do I need to do all that v1 stuff in router::transfer_name.
        let manager_address =
            object::address_from_constructor_ref(&manager_constructor_ref);
        let domain_token_address = v2_1_domains::get_token_addr(domain, option::none());
        object::transfer(
            caller,
            object::address_to_object<v2_1_domains::NameRecord>(domain_token_address),
            manager_address
        );

        object::object_from_constructor_ref(&manager_constructor_ref)
    }

    /// Set whether the manager is enabled or not.
    public entry fun set_enabled(
        caller: &signer, manager: Object<SubdomainManager>, is_enabled: bool
    ) acquires SubdomainManager {
        let caller_address = signer::address_of(caller);
        assert!(
            object::is_owner(manager, caller_address),
            error::invalid_state(ENOT_ADMIN)
        );

        let manager_address = object::object_address(&manager);
        let manager_ = borrow_global_mut<SubdomainManager>(manager_address);

        manager_.is_enabled = is_enabled;
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
    ) acquires SubdomainManager {
        let manager_address = object::object_address(&manager);
        let manager_ = borrow_global_mut<SubdomainManager>(manager_address);

        // Bail if the admin is not really the admin (owner of the manager object).
        let admin_address = signer::address_of(admin);
        assert!(
            object::is_owner(manager, admin_address),
            error::invalid_state(ENOT_ADMIN)
        );

        claim_subdomain_inner(caller, manager_, subdomain, public_key_bytes);
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
    ) acquires SubdomainManager {
        let manager_address = object::object_address(&manager);
        let manager_ = borrow_global_mut<SubdomainManager>(manager_address);

        // Bail if `claim_only_with_admin_approval` is true.
        if (manager_.claim_only_with_admin_approval) {
            assert!(
                false, error::permission_denied(E_CAN_ONLY_CLAIM_WITH_ADMIN_APPROVAL)
            );
        };

        claim_subdomain_inner(caller, manager_, subdomain, public_key_bytes);
    }

    fun claim_subdomain_inner(
        caller: &signer,
        manager_: &mut SubdomainManager,
        subdomain: String,
        public_key_bytes: vector<u8>
    ) {
        // Make sure the manager is enabled.
        assert!(manager_.is_enabled, error::unavailable(ENOT_ENABLED));

        let caller_address = signer::address_of(caller);

        // Ensure the caller has not already claimed a subdomain.
        let caller_has_already_claimed =
            manager_.claimed_addresses.contains(caller_address);
        assert!(
            !caller_has_already_claimed,
            error::invalid_state(ECALLER_HAS_ALREADY_CLAIMED)
        );

        // Check if the subdomain is available for the caller to claim.
        let subdomain_available_result =
            is_subdomain_available_for_addr(manager_.domain, subdomain, caller_address);
        match(subdomain_available_result) {
            SubdomainAvailableResult::AVAILABLE => {},
            SubdomainAvailableResult::SUBDOMAIN_ALREADY_CLAIMED => {
                assert!(false, error::permission_denied(ESUBDOMAIN_ALREADY_CLAIMED));
            },
            SubdomainAvailableResult::CANNOT_CLAIM_SUBDOMAIN_IF_DOMAIN_OWNED_BY_OTHER_ADDRESS => {
                assert!(
                    false,
                    error::permission_denied(
                        ECANNOT_CLAIM_SUBDOMAIN_IF_DOMAIN_OWNED_BY_OTHER_ADDRESS
                    )
                );
            }
        };

        // If `keyless_only` is true, validate that the caller is a keyless account.
        if (manager_.keyless_only) {
            keyless::assert_is_keyless(caller_address, public_key_bytes);
        };

        // Record that the caller has claimed a subdomain.
        manager_.claimed_addresses.add(caller_address, subdomain);
        event::emit(SubdomainClaimedEvent { claimer_address: caller_address, subdomain });

        // We need to set a expiration time in the future, even though it will be ignored and follow the domain expiration
        let expiration_time_sec: u64 =
            timestamp::now_seconds() + REGISTRATION_DURATION_SECONDS;

        // Register the subdomain, point it and transfer it to the caller.
        let object_signer = object::generate_signer_for_extending(&manager_.extend_ref);
        register_subdomain(
            &object_signer,
            manager_.domain,
            subdomain,
            expiration_time_sec,
            SUBDOMAIN_POLICY_LOOKUP_DOMAIN_EXPIRATION,
            false,
            option::some(caller_address),
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
    ): bool acquires SubdomainManager {
        let manager_address = object::object_address(&manager);
        let manager_ = borrow_global<SubdomainManager>(manager_address);
        !manager_.claimed_addresses.contains(address)
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

        // If the desired subdomain is already registered as a domain, then only the
        // owner of the domain can claim the subdomain.
        if (is_name_owner(address, subdomain, option::none())) {
            return SubdomainAvailableResult::CANNOT_CLAIM_SUBDOMAIN_IF_DOMAIN_OWNED_BY_OTHER_ADDRESS
        };

        SubdomainAvailableResult::AVAILABLE
    }

    /// Reclaim a subdomain from someone who claimed it. Unlike `force_register_subdomain`,
    /// which essentially just parks the domain so no one else can claim it, this makes
    /// it available for someone to claim again.
    public entry fun reclaim_subdomain(
        caller: &signer, manager: Object<SubdomainManager>, subdomain: String
    ) acquires SubdomainManager {
        let caller_address = signer::address_of(caller);
        assert!(
            object::is_owner(manager, caller_address),
            error::invalid_state(ENOT_ADMIN)
        );

        let manager_address = object::object_address(&manager);
        let manager_ = borrow_global_mut<SubdomainManager>(manager_address);

        // Let the current owner of the subdomain claim another subdomain.
        let subdomain_target_addr = router::get_target_addr(manager_.domain, option::some(subdomain));
        manager_.claimed_addresses.remove(subdomain_target_addr.extract());

        // Transfer ownership of the "ANS app signer", remove the target address. This
        // makes it eligible for claiming again.
        let manager_object_signer = object::generate_signer_for_extending(&manager_.extend_ref);
        domain_admin_transfer_subdomain(
            &manager_object_signer,
            manager_.domain,
            subdomain,
            v2_1_domains::get_app_signer_addr(),
            option::none()
        );
    }

    /// Forcibly register a subdomain. It will be sent to and pointed at the manager
    /// object's address. You can use this to reserve subdomains. This ignores the
    /// is_enabled flag.
    public entry fun force_register_subdomain(
        caller: &signer, manager: Object<SubdomainManager>, subdomain: String
    ) acquires SubdomainManager {
        let caller_address = signer::address_of(caller);
        assert!(
            object::is_owner(manager, caller_address),
            error::invalid_state(ENOT_ADMIN)
        );

        let manager_address = object::object_address(&manager);
        let manager_ = borrow_global<SubdomainManager>(manager_address);

        // We need to set a expiration time in the future, even though it will be
        // ignored and follow the domain expiration.
        let expiration_time_sec: u64 =
            timestamp::now_seconds() + REGISTRATION_DURATION_SECONDS;

        let manager_object_signer = object::generate_signer_for_extending(&manager_.extend_ref);
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
    }

    /// Return the domain owned by a manager to the caller (the admin), delete the manager.
    public entry fun delete_manager(
        caller: &signer, manager: Object<SubdomainManager>
    ) acquires SubdomainManager {
        let caller_address = signer::address_of(caller);
        assert!(
            object::is_owner(manager, caller_address),
            error::invalid_state(ENOT_ADMIN)
        );

        let manager_address = object::object_address(&manager);
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
            domain: _domain,
            keyless_only: _keyless_only,
            claim_only_with_admin_approval: _claim_only_with_admin_approval,
            claimed_addresses,
            is_enabled: _is_enabled,
            extend_ref: _extend_ref,
            delete_ref
        } = manager_;

        claimed_addresses.destroy();

        // Delete the manager.
        object::delete(delete_ref);
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
        aptos_framework: &signer,
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
        config::set_fund_destination_address_test_only(signer::address_of(aptos_framework));
        v2_1_config::set_fund_destination_address_test_only(signer::address_of(aptos_framework));
        router::set_mode(router, 1);
    }

    #[
        test(
            router = @router,
            aptos_names = @aptos_names,
            aptos_names_v2_1 = @aptos_names_v2_1,
            manager = @0x100,
            user1 = @0x101,
            user2 = @0x102,
            aptos_framework = @aptos_framework,
        )
    ]
    public entry fun test_basic_flow(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer,
    ) acquires SubdomainManager {
        setup_test(
            &router,
            &aptos_names,
            &aptos_names_v2_1,
            &manager,
            &user1,
            &user2,
            &aptos_framework,
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
        let manager_object = create_manager_inner(&manager, string::utf8(TESTING_DOMAIN), false, false);

        // Claim a subdomain as user 1.
        claim_subdomain_without_admin_approval(&user1, manager_object, sub1, vector[]);

        // Confirm that user 1 has the subdomain.
        let sub1_target_addr = router::get_target_addr(string::utf8(TESTING_DOMAIN), option::some(sub1));
        assert!(sub1_target_addr.is_some(), 0);
        assert!(sub1_target_addr.borrow() == &signer::address_of(&user1), 0);

        // Reclaim a subdomain as the admin.
        reclaim_subdomain(&manager, manager_object, sub1);

        // Confirm that user 1 no longer has the subdomain.
        let sub1_target_addr = router::get_target_addr(string::utf8(TESTING_DOMAIN), option::some(sub1));
        assert!(sub1_target_addr.is_none(), 0);

        // Confirm that user 2 can claim the subdomain now.
        claim_subdomain_without_admin_approval(&user2, manager_object, sub1, vector[]);

        // Confirm that user 2 has the subdomain.
        let sub1_target_addr = router::get_target_addr(string::utf8(TESTING_DOMAIN), option::some(sub1));
        assert!(sub1_target_addr.is_some(), 0);
        assert!(sub1_target_addr.borrow() == &signer::address_of(&user2), 0);
    }

    #[test(
        router = @router,
        aptos_names = @aptos_names,
        aptos_names_v2_1 = @aptos_names_v2_1,
        manager = @0x100,
        user1 = @0x123,
        user2 = @0x456,
        aptos_framework = @0x1,
    )]
    #[expected_failure(abort_code = 327687, location = Self)]
    fun test_cannot_claim_existing_subdomain(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer,
    ) acquires SubdomainManager {
        setup_test(
            &router,
            &aptos_names,
            &aptos_names_v2_1,
            &manager,
            &user1,
            &user2,
            &aptos_framework,
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
        let manager_object = create_manager_inner(&manager, string::utf8(TESTING_DOMAIN), false, false);

        // Claim a subdomain as user 1.
        claim_subdomain_without_admin_approval(&user1, manager_object, sub1, vector[]);

        // Confirm that user 1 has the subdomain.
        let sub1_target_addr = router::get_target_addr(string::utf8(TESTING_DOMAIN), option::some(sub1));
        assert!(sub1_target_addr.is_some(), 0);
        assert!(sub1_target_addr.borrow() == &signer::address_of(&user1), 0);

        // Attempt to claim the same subdomain as user 2, which should fail.
        claim_subdomain_without_admin_approval(&user2, manager_object, sub1, vector[]);
    }

    #[test(
        router = @router,
        aptos_names = @aptos_names,
        aptos_names_v2_1 = @aptos_names_v2_1,
        manager = @0x100,
        user1 = @0x123,
        user2 = @0x456,
        aptos_framework = @0x1,
    )]
    #[expected_failure(abort_code = 196614, location = Self)]
    fun test_cannot_claim_twice(
        router: signer,
        aptos_names: signer,
        aptos_names_v2_1: signer,
        manager: signer,
        user1: signer,
        user2: signer,
        aptos_framework: signer,
    ) acquires SubdomainManager {
        setup_test(
            &router,
            &aptos_names,
            &aptos_names_v2_1,
            &manager,
            &user1,
            &user2,
            &aptos_framework,
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
        let manager_object = create_manager_inner(&manager, string::utf8(TESTING_DOMAIN), false, false);

        // Claim a subdomain as user 1.
        claim_subdomain_without_admin_approval(&user1, manager_object, sub1, vector[]);

        // Confirm that user 1 has the subdomain.
        let sub1_target_addr = router::get_target_addr(string::utf8(TESTING_DOMAIN), option::some(sub1));
        assert!(sub1_target_addr.is_some(), 0);
        assert!(sub1_target_addr.borrow() == &signer::address_of(&user1), 0);

        // Attempt to claim another subdomain, which should fail.
        claim_subdomain_without_admin_approval(&user1, manager_object, sub2, vector[]);
    }
}
