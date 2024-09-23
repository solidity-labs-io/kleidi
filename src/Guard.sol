pragma solidity 0.8.25;

import {BaseGuard} from "@safe/base/GuardManager.sol";
import {Enum} from "@safe/common/Enum.sol";
import {Safe} from "@safe/Safe.sol";

import {BytesHelper} from "src/BytesHelper.sol";

/// @notice This guard restricts changing owners and modules. It enforces
/// that the owners and modules remain the same after a safe transaction is
/// executed by not allowing self or delegate calls.

/// Config:
///  - the timelock must be a module of the safe to enact changes to the owners and modules
///  - the safe must be the only executor on the timelock

/// no new modules, upgrades, owners, or fallback handlers can be added or
/// removed by a transaction because all self calls are disallowed.
/// this implies that the only way these values can be set are through
/// the timelock, which can call back into the safe and use delegatecall
/// if needed.

/// Blocks all delegate calls, as the owners and modules could be changed.
/// Does not allow changing of the implementation contract either through
/// a normal safe transaction.
/// The implementation contract can still be upgraded through the timelock
/// using module calls back into the safe with a delegatecall.

/// Refund receiver and gas params are not checked because the Safe itself
/// does not hold funds or tokens.

contract Guard is BaseGuard {
    using BytesHelper for bytes;

    /// -----------------------------------------------------
    /// -----------------------------------------------------
    /// ----------------- Safe Hooks ------------------------
    /// -----------------------------------------------------
    /// -----------------------------------------------------

    /// @notice function that restricts Gnosis Safe interaction
    /// to external calls only, and disallows self and delegate calls.
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operationType,
        uint256,
        uint256,
        uint256,
        address,
        address payable,
        bytes memory,
        address
    ) external view {
        if (to == msg.sender) {
            /// only allow self calls to effectively cancel a transaction by
            /// using a nonce without any payload and value.
            require(data.length == 0 && value == 0, "Guard: no self calls");
        }
        /// if delegate calls are allowed, owners or modules could be added
        /// or removed outside of the expected flow, and the only way to reason
        /// about this is to disallow delegate calls as we cannot prove unknown
        /// slots were not written to in the owner or modules mapping
        require(
            operationType == Enum.Operation.Call,
            "Guard: delegate call disallowed"
        );
    }

    /// @notice no-op function, required by the Guard interface.
    /// No checks needed after the tx has been executed.
    /// The pre-checks are enough to ensure the transaction is valid.
    function checkAfterExecution(bytes32, bool) external pure {}
}
