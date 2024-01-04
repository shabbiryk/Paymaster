use starknet::ContractAddress;
//This would be the user intent skeleton
#[derive(Drop, Serde)]
struct ICall {
    to: ContractAddress,
    selector: felt252,
    calldata: Array<felt252>,
}
#[starknet::contract]
mod Call {
    use core::ecdsa::check_ecdsa_signature;
    use starknet::get_tx_info;
    use starknet::VALIDATED;

    #[storage]
    struct Storage {
        account_public_key: felt252,
    }
    #[generate_trait]
    impl Private<TContractState> of PrivateTrait<TContractState> {
        // Validate the Tx'n not the account that sent the intent
        // Adapt to the new changes 
        fn validate_transaction(self: @ContractState) -> felt252 {
            let tx_info = get_tx_info().unbox();
            let sig = tx_info.signature;
            assert(sig.len() == 2_u32, 'invalid signature length');
            assert(
                check_ecdsa_signature(
                    message_hash: tx_info.transaction_hash,
                    public_key: self.account_public_key.read(),
                    signature_r: *sig[0_u32],
                    signature_s: *sig[1_u32],
                ),
                'invalid signature'
            );

            VALIDATED
        }
    }
}
