module addr::subdomain_manager {
    use std::error;
    use std::option::{Self, Option};
    use std::signer;
    use std::string::String;
    use aptos_std::smart_table::{Self, SmartTable};
    use aptos_std::object::{Self, Object, ExtendRef};
    use aptos_framework::event;
    use aptos_framework::timestamp;
    use aptos_names::domains;
    use aptos_names_v2_1::v2_1_domains;
    use router::router::{
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

    /// Only the admin is authorized to perform this operation.
    const ENOT_ADMIN: u64 = 4;

    /// You have already claimed a subdomain.
    const ECALLER_HAS_ALREADY_CLAIMED: u64 = 5;

    /// The subdomain has already been claimed by another address.
    const ESUBDOMAIN_ALREADY_CLAIMED: u64 = 6;

    /// You cannot claim this subdomain because someone else already owns the top level domain with the same name.
    const ECANNOT_CLAIM_SUBDOMAIN_IF_DOMAIN_OWNED_BY_OTHER_ADDRESS: u64 = 7;

    struct SubdomainManager has key {
        /// The domain that we are managing subdomains for.
        domain: String,
        /// The addresses that have claimed a subdomain, mapped to the subdomain they claimed.
        claimed_addresses: SmartTable<address, String>,
        is_enabled: bool,
        extend_ref: ExtendRef
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
    public entry fun create_manager(caller: &signer, domain: String) {
        let caller_address = signer::address_of(caller);

        // Confirm the caller owns the domain.
        let owner_addr = get_owner_addr(domain, option::none());
        assert!(
            owner_addr.is_some(),
            error::invalid_state(ENOT_DOMAIN_OWNER)
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
            claimed_addresses: smart_table::new(),
            is_enabled: true,
            extend_ref: object::generate_extend_ref(&manager_constructor_ref)
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
    public entry fun claim_subdomain(
        caller: &signer,
        admin: &signer,
        manager: Object<SubdomainManager>,
        subdomain: String
    ) acquires SubdomainManager {
        let manager_address = object::object_address(&manager);
        let manager_ = borrow_global_mut<SubdomainManager>(manager_address);

        // Make sure the manager is enabled.
        assert!(manager_.is_enabled, error::unavailable(ENOT_ENABLED));

        let caller_address = signer::address_of(caller);
        let admin_address = signer::address_of(admin);

        // Bail if the admin is not really the admin (owner of the manager object).
        assert!(
            object::is_owner(manager, admin_address),
            error::invalid_state(ENOT_ADMIN)
        );

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
    /// only be registered if we have burned the token (sent it to the router_signer).
    fun can_register(domain: String, subdomain: Option<String>): bool {
        let registerable_in_v1 = domains::name_is_expired_past_grace(subdomain, domain);
        if (registerable_in_v1) {
            v2_1_domains::is_name_registerable(domain, subdomain)
        } else {
            let (is_burned, _token_id) =
                domains::is_token_owner(@router_signer, subdomain, domain);
            is_burned
        }
    }

    #[view]
    /// Check if the subdomain is available for the address to claim.
    public fun is_subdomain_available_for_addr(
        domain: String, subdomain: String, address: address
    ): SubdomainAvailableResult {
        // Can't claim a subdomain that is already claimed.
        if (!can_register(domain, option::some(subdomain)))
            return SubdomainAvailableResult::SUBDOMAIN_ALREADY_CLAIMED;

        // If the domain is not registered, then the subdomain is available.
        if (can_register(subdomain, option::none()))
            return SubdomainAvailableResult::AVAILABLE;

        // If the desired subdomain is already registered as a domain, then only the
        // owner of the domain can claim the subdomain.
        if (is_name_owner(address, subdomain, option::none()))
            return SubdomainAvailableResult::CANNOT_CLAIM_SUBDOMAIN_IF_DOMAIN_OWNED_BY_OTHER_ADDRESS;

        SubdomainAvailableResult::AVAILABLE
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

        let object_signer = object::generate_signer_for_extending(&manager_.extend_ref);
        register_subdomain(
            &object_signer,
            manager_.domain,
            subdomain,
            expiration_time_sec,
            SUBDOMAIN_POLICY_LOOKUP_DOMAIN_EXPIRATION,
            false,
            option::some(manager_address),
            option::some(manager_address)
        );
    }
}
