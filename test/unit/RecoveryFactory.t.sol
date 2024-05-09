// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";

import {RecoverySpell} from "@src/RecoverySpell.sol";
import {RecoveryFactory} from "@src/RecoveryFactory.sol";

contract RecoveryFactoryUnitTest is Test {
    RecoveryFactory recoveryFactory;

    function setUp() public {
        recoveryFactory = new RecoveryFactory();
    }

    function testDeployTwiceSameParamsFails(
        bytes32 salt,
        uint8 ownerLength,
        address safe,
        uint256 threshold,
        uint256 delay
    ) public {
        ownerLength = uint8(_bound(ownerLength, 1, 10));
        threshold = _bound(threshold, 1, ownerLength);
        delay = _bound(delay, 1 days, 20 days);

        address[] memory owners = new address[](ownerLength);
        for (uint8 i = 0; i < ownerLength; i++) {
            owners[i] = address(uint160(i));
        }

        RecoverySpell recovery1 = recoveryFactory.createRecoverySpell(
            salt, owners, safe, threshold, delay
        );

        vm.expectRevert();
        RecoverySpell recovery2 = recoveryFactory.createRecoverySpell(
            salt, owners, safe, threshold, delay
        );

        assertEq(
            address(
                recoveryFactory.calculateAddress(
                    salt, owners, safe, threshold, delay
                )
            ),
            address(recovery1),
            "RecoverySpell addresses should be the same"
        );

        assertEq(
            address(0),
            address(recovery2),
            "RecoverySpell addresses should be the same"
        );
    }

    function testDeploymentInvariants(
        bytes32 salt,
        uint8 ownerLength,
        address safe,
        uint256 threshold,
        uint256 delay
    ) public {
        ownerLength = uint8(_bound(ownerLength, 1, 10));

        address[] memory owners = new address[](ownerLength);
        for (uint8 i = 0; i < ownerLength; i++) {
            owners[i] = address(uint160(i));
        }

        RecoverySpell spell =
            _trySpellCreation(salt, owners, safe, threshold, delay);

        /// owner length must be greater than or equal to threshold
        /// threshold must be greater than or equal to 1
        /// delay must be lte 20 days
        /// the above conditions being true implies the spell should not be zero
        if (ownerLength >= threshold && threshold >= 1 && delay <= 20 days) {
            assertNotEq(address(spell), address(0), "spell should not be zero");
        }

        /// if deployment fails, nothing to check
        if (address(spell) != address(0)) {
            assertTrue(
                spell.getOwners().length >= spell.threshold(),
                "threshold invariant 1 violated"
            );
            assertTrue(spell.threshold() >= 1, "threshold invariant 2 violated");
            assertTrue(spell.delay() <= 20 days, "delay invariant violated");

            address[] memory spellOwners = spell.getOwners();

            for (uint8 i = 0; i < ownerLength; i++) {
                assertEq(
                    spellOwners[i],
                    owners[i],
                    "owner equality invariant violated"
                );
            }

            for (uint8 i = 0; i < ownerLength; i++) {
                for (uint8 j = i + 1; j < ownerLength; j++) {
                    assertNotEq(
                        owners[i],
                        owners[j],
                        "duplicate owner invariant violated"
                    );
                }
            }
        }
    }

    function _trySpellCreation(
        bytes32 salt,
        address[] memory owners,
        address safe,
        uint256 threshold,
        uint256 delay
    ) private returns (RecoverySpell) {
        try recoveryFactory.createRecoverySpell(
            salt, owners, safe, threshold, delay
        ) returns (RecoverySpell spell) {
            return spell;
        } catch Error(string memory) {
            return RecoverySpell(address(0));
        }
    }

    function testViewFunctionFailsThresholdGtOwners() public {
        vm.expectRevert("RecoverySpell: Threshold must be lte number of owners");
        recoveryFactory.calculateAddress(
            bytes32(0), new address[](1), address(0), 2, 1
        );
    }

    function testViewFunctionFailsThresholdEqZero() public {
        vm.expectRevert("RecoverySpell: Threshold must be gt 0");
        recoveryFactory.calculateAddress(
            bytes32(0), new address[](1), address(0), 0, 1
        );
    }

    function testViewFunctionFailsDaysOutOfBand() public {
        vm.expectRevert("RecoverySpell: Delay must be lte 20 days");
        recoveryFactory.calculateAddress(
            bytes32(0), new address[](1), address(0), 1, 20 days + 1
        );
    }

    function testCreateFunctionFailsThresholdGtOwners() public {
        vm.expectRevert("RecoverySpell: Threshold must be lte number of owners");
        recoveryFactory.createRecoverySpell(
            bytes32(0), new address[](1), address(0), 2, 1
        );
    }

    function testCreateFunctionFailsThresholdEqZero() public {
        vm.expectRevert("RecoverySpell: Threshold must be gt 0");
        recoveryFactory.createRecoverySpell(
            bytes32(0), new address[](1), address(0), 0, 1
        );
    }

    function testCreateFunctionFailsDaysOutOfBand() public {
        vm.expectRevert("RecoverySpell: Delay must be lte 20 days");
        recoveryFactory.createRecoverySpell(
            bytes32(0), new address[](1), address(0), 1, 20 days + 1
        );
    }

    function testCreateFunctionFailsDuplicateOwner() public {
        vm.expectRevert("RecoverySpell: Duplicate owner");
        recoveryFactory.createRecoverySpell(
            bytes32(0), new address[](3), address(0), 1, 10 days
        );
    }

    function testParamSubstitutionSaltChangesAddress() public view {
        bytes32 salt = bytes32(uint256(1));

        address[] memory owners = new address[](3);
        owners[0] = address(0x1);
        owners[1] = address(0x2);
        owners[2] = address(0x3);

        address safe = address(0x3);
        uint256 threshold = 2;
        uint256 delay = 2 days;

        address firstAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, safe, threshold, delay
            )
        );
        address secondAddress = address(
            recoveryFactory.calculateAddress(
                bytes32(0), owners, safe, threshold, delay
            )
        );

        assertNotEq(
            firstAddress, secondAddress, "addresses should not be the same"
        );
    }

    function testParamSubstitutionOwnerChangesAddress() public view {
        bytes32 salt = bytes32(uint256(1));

        address[] memory owners = new address[](3);
        owners[0] = address(0x1);
        owners[1] = address(0x2);
        owners[2] = address(0x3);

        address safe = address(0x3);
        uint256 threshold = 2;
        uint256 delay = 2 days;

        address firstAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, safe, threshold, delay
            )
        );

        owners[2] = address(0x4);
        address secondAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, safe, threshold, delay
            )
        );

        assertNotEq(
            firstAddress, secondAddress, "addresses should not be the same"
        );
    }

    function testParamSubstitutionSafeChangesAddress() public view {
        bytes32 salt = bytes32(uint256(1));

        address[] memory owners = new address[](3);
        owners[0] = address(0x1);
        owners[1] = address(0x2);
        owners[2] = address(0x3);

        address safe = address(0x3);
        uint256 threshold = 2;
        uint256 delay = 2 days;

        address firstAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, safe, threshold, delay
            )
        );
        address secondAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, address(0x4), threshold, delay
            )
        );

        assertNotEq(
            firstAddress, secondAddress, "addresses should not be the same"
        );
    }

    function testParamSubstitutionThresholdChangesAddress() public view {
        bytes32 salt = bytes32(uint256(1));

        address[] memory owners = new address[](3);
        owners[0] = address(0x1);
        owners[1] = address(0x2);
        owners[2] = address(0x3);

        address safe = address(0x3);
        uint256 threshold = 2;
        uint256 delay = 2 days;

        address firstAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, safe, threshold, delay
            )
        );
        address secondAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, safe, threshold + 1, delay
            )
        );
        address thirdAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, safe, threshold - 1, delay
            )
        );

        assertNotEq(
            firstAddress, secondAddress, "addresses should not be the same"
        );
        assertNotEq(
            secondAddress, thirdAddress, "addresses should not be the same"
        );
        assertNotEq(
            firstAddress, thirdAddress, "addresses should not be the same"
        );
    }

    function testParamSubstitutionDelayChangesAddress() public view {
        bytes32 salt = bytes32(uint256(1));

        address[] memory owners = new address[](3);
        owners[0] = address(0x1);
        owners[1] = address(0x2);
        owners[2] = address(0x3);

        address safe = address(0x3);
        uint256 threshold = 2;
        uint256 delay = 2 days;

        address firstAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, safe, threshold, delay
            )
        );
        address secondAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, safe, threshold, delay + 1
            )
        );
        address thirdAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, safe, threshold, delay - 1
            )
        );

        assertNotEq(
            firstAddress, secondAddress, "addresses should not be the same"
        );
        assertNotEq(
            secondAddress, thirdAddress, "addresses should not be the same"
        );
        assertNotEq(
            firstAddress, thirdAddress, "addresses should not be the same"
        );
    }
}