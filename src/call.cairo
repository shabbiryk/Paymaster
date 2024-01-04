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
    use core::array::{ArrayTrait, SpanTrait};
    use core::result::{ResultTrait};
    use starknet::get_tx_info;
    use starknet::VALIDATED;
    use super::{ICall};
    use starknet::{SyscallResult, syscalls::call_contract_syscall};

    #[storage]
    struct Storage {
        account_public_key: felt252,
    }
    #[generate_trait]
    impl Private<TContractState> of PrivateTrait<TContractState> {
        // Validate the Tx'n not the account that sent the intent
        // Adapt to the new changes 
        fn _validate_transaction(caller_address: felt252) -> felt252 {
            let tx_info = get_tx_info().unbox();
            let sig = tx_info.signature;
            assert(sig.len() == 2_u32, 'invalid signature length');
            assert(
                check_ecdsa_signature(
                    message_hash: tx_info.transaction_hash,
                    public_key: caller_address,
                    signature_r: *sig[0_u32],
                    signature_s: *sig[1_u32],
                ),
                'invalid signature'
            );

            VALIDATED
        }

        fn _execute_transaction(calls: Span<ICall>) -> Array<Span<felt252>> {
            let mut result: Array<Span<felt252>> = ArrayTrait::new();
            let mut calls = calls;
            loop {
                match calls.pop_front() {
                    Option::Some(call) => {
                        match call_contract_syscall(
                            *call.to, *call.selector, call.calldata.span()
                        ) {
                            Result::Ok(mut returndata) => { result.append(returndata); },
                            Result::Err(revert_message) => { panic(revert_message) },
                        }
                    },
                    Option::None => { break; },
                };
            };
            result
        }
    }
}
