use starknet::ContractAddress;
#[derive(Drop, Serde)]
struct ICall {
    to: ContractAddress,
    selector: felt252,
    calldata: Array<felt252>,
}

#[starknet::interface]
trait IExternalCalls<T> {
    fn call_execute(ref self: T, calls: Array<ICall>) -> Array<Span<felt252>>;
    fn transfer_erc20(ref self: T, token_address: ContractAddress, amount: u256) -> bool;
}

#[starknet::interface]
trait IERC20<TState> {
    fn name(self: @TState) -> felt252;
    fn symbol(self: @TState) -> felt252;
    fn decimals(self: @TState) -> u8;
    fn total_supply(self: @TState) -> u256;
    fn balance_of(self: @TState, account: ContractAddress) -> u256;
    fn allowance(self: @TState, owner: ContractAddress, spender: ContractAddress) -> u256;
    fn transfer(ref self: TState, recipient: ContractAddress, amount: u256) -> bool;
    fn transfer_from(
        ref self: TState, sender: ContractAddress, recipient: ContractAddress, amount: u256
    ) -> bool;
    fn approve(ref self: TState, spender: ContractAddress, amount: u256) -> bool;
}


#[starknet::contract]
mod Call {
    use core::starknet::event::EventEmitter;
    use core::traits::{Into, TryInto};
    use core::box::BoxTrait;
    use core::num::traits::zero::Zero;
    use core::ecdsa::check_ecdsa_signature;
    use core::array::{ArrayTrait, SpanTrait};
    use core::result::{ResultTrait};
    use starknet::get_tx_info;
    use paymaster::error::ErrorMessage;
    use starknet::VALIDATED;
    use super::{ICall, IExternalCalls, IERC20, IERC20Dispatcher, IERC20DispatcherTrait};
    use starknet::{
        get_contract_address, get_caller_address, ContractAddress, SyscallResult,
        syscalls::call_contract_syscall,
    };

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Transfer: Transfer,
    }
    #[derive(Drop, starknet::Event)]
    struct Transfer {
        from: ContractAddress,
        to: ContractAddress,
        value: u256
    }


    #[storage]
    struct Storage {
        account_public_key: felt252,
    }
    #[external(v0)]
    impl ExternalCallImpl of IExternalCalls<ContractState> {
        fn call_execute(ref self: ContractState, calls: Array<ICall>) -> Array<Span<felt252>> {
            let caller = get_caller_address();
            assert(caller.is_zero(), ErrorMessage::INVALID_CALLER);
            let tx_info = get_tx_info().unbox();
            assert(tx_info.version != 0, ErrorMessage::INVALID_TRANSACTION_VERSION);
            assert(
                _validate_transaction(caller.into()) == VALIDATED,
                ErrorMessage::INVALID_USER_SIGNATURE
            );
            _execute_transaction(calls.span())
        }

        fn transfer_erc20(
            ref self: ContractState, token_address: ContractAddress, amount: u256
        ) -> bool {
            let amount_u256: u256 = amount.into();
            let transfer_success = IERC20Dispatcher { contract_address: token_address }
                .transfer_from(get_caller_address(), get_contract_address(), amount_u256);
            assert(transfer_success, ErrorMessage::TRANSFER_FAILED);
            self
                .emit(
                    Transfer {
                        from: get_caller_address(), to: get_contract_address(), value: amount_u256
                    }
                );
            true
        }
    }

    fn _validate_transaction(caller_address: felt252) -> felt252 {
        let tx_info = get_tx_info().unbox();
        let sig = tx_info.signature;
        assert(sig.len() == 2_u32, ErrorMessage::INVALID_SIGNATURE_LENGTH);
        assert(
            check_ecdsa_signature(
                message_hash: tx_info.transaction_hash,
                public_key: caller_address,
                signature_r: *sig[0_u32],
                signature_s: *sig[1_u32],
            ),
            ErrorMessage::INVALID_USER_SIGNATURE
        );

        VALIDATED
    }

    fn _execute_transaction(calls: Span<ICall>) -> Array<Span<felt252>> {
        let mut result: Array<Span<felt252>> = ArrayTrait::new();
        let mut calls = calls;
        loop {
            match calls.pop_front() {
                Option::Some(call) => {
                    match call_contract_syscall(*call.to, *call.selector, call.calldata.span()) {
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
