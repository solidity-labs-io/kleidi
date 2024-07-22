pragma solidity 0.8.25;

import {BaseGuard} from "@safe/base/GuardManager.sol";
import {Enum} from "@safe/common/Enum.sol";
import {Safe} from "@safe/Safe.sol";

import {BytesHelper} from "src/BytesHelper.sol";

/// @notice Only the timelock can add, edit, remove or disable
/// time ranges after initialization.
/// Contract that restricts Safe interactions to a specific time range
/// This guard also restricts changing owners and modules. It enforces
/// that the owners and modules remain the same after a transaction is
/// executed. If there is any changes, transactions are reverted.

/// Config:
///  - the timelock must be a module of the safe to enact changes to the owners and modules
///  - the safe must not be the only executor on the timelock, otherwise the safe could be
///  locked out of making changes, except recvoery spells

/// no new modules, upgrades, owners, or fallback handlers can be added or
/// removed by a transaction because all self calls are disallowed.
/// this implies that the only way these values can be set are through
/// the timelock, which can call back into the safe and use delegatecall
/// if needed.

/// after the transaction in checkAfterExecution, check that the number of modules
/// and the actual module addresses are the same
/// check that the owners are the same

/// Blocks all delegate calls, as the owners and modules could be changed.
/// Does not allow changing of the implementation contract either through
/// a normal safe transaction.
/// The implementation contract can still be upgraded through the timelock
/// using module calls back into the safe with a delegatecall.

/// Refund receiver and gas params are not checked because the Safe itself
/// does not hold funds or tokens.

contract Guard is BaseGuard {
    using BytesHelper for bytes;

    /// @notice storage slot for the fallback handler
    /// keccak256("fallback_manager.handler.address")
    uint256 private constant FALLBACK_HANDLER_STORAGE_SLOT =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;

    /// @notice Emitted when the guard is added to a safe
    /// @param safe address of the safe
    event GuardEnabled(address indexed safe);

    /// -----------------------------------------------------
    /// -----------------------------------------------------
    /// ---------------- Initialize Function ----------------
    /// -----------------------------------------------------
    /// -----------------------------------------------------

    /// @notice initialize configuration for a safe as the gnosis safe

    function checkSafe() external {
        require(msg.sender.code.length != 0, "Guard: invalid safe");

        /// it's really hard to reason about what a fallback handler could do
        /// so do not accept a safe that has an active fallback handler to
        /// initialize itself with this guard.
        bytes memory fallBackHandlerBytes = Safe(payable(msg.sender))
            .getStorageAt(FALLBACK_HANDLER_STORAGE_SLOT, 1);

        address fallbackHandler =
            address(uint160(uint256(fallBackHandlerBytes.getFirstWord())));

        require(
            fallbackHandler == address(0),
            "Guard: cannot initialize with fallback handler"
        );

        emit GuardEnabled(msg.sender);
    }

    /// -----------------------------------------------------
    /// -----------------------------------------------------
    /// ----------------- Safe Hooks ------------------------
    /// -----------------------------------------------------
    /// -----------------------------------------------------

    /// @notice function that restricts Gnosis Safe interaction
    /// to only a specific time range in specified days.
    /// no granularity to specify different hours for different allowed days.
    /// all allowed days have the same allowed hours.
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
