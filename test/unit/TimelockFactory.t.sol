// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "test/utils/TimelockUnitFixture.sol";

/// TODO: Add tests for TimelockFactory
contract TimelockFactoryUnitTest is TimelockUnitFixture {
    function testSetup() public view {}

    /// Tests
    /// - create2
    /// - different sender gives different address with all of the same parameters
    /// - factoryCreated is updated when new timelock addresses are created
    /// - events are correct
    /// - addresses calculated correctly
}
