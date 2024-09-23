pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";

import {RecoverySpell} from "@src/RecoverySpell.sol";
import {RecoverySpellFactory} from "@src/RecoverySpellFactory.sol";

contract RecoverySpellFactoryUnitTest is Test {
    RecoverySpellFactory recoveryFactory;
    address public constant SAFE = address(0x0afe);
    bytes public constant SAFE_BYTECODE = hex"3afe";

    function setUp() public {
        recoveryFactory = new RecoverySpellFactory();
        vm.etch(SAFE, SAFE_BYTECODE);
    }

    function testDeployRecoverySpellFailsNonExistentSafe() public {
        address[] memory owners = new address[](1);
        owners[0] = address(0x1);

        vm.expectRevert("RecoverySpell: safe non-existent");
        recoveryFactory.createRecoverySpell(
            bytes32(0), owners, address(0), 1, 1, 1
        );
    }

    function testCalculateAddressFailsAddressZeroOwners() public {
        address[] memory owners = new address[](1);

        vm.expectRevert("RecoverySpell: Owner cannot be 0");
        recoveryFactory.calculateAddress(
            bytes32(0), owners, address(0), 1, 1, 1
        );
    }

    function testDeployTwiceSameParamsFails(
        bytes32 salt,
        uint8 ownerLength,
        uint256 threshold,
        uint256 recoveryThreshold,
        uint256 delay
    ) public {
        ownerLength = uint8(_bound(ownerLength, 1, 10));
        threshold = _bound(threshold, 1, ownerLength);
        recoveryThreshold = _bound(recoveryThreshold, 0, threshold);
        delay = _bound(delay, 1 days, 20 days);

        address[] memory owners = new address[](ownerLength);
        for (uint8 i = 0; i < ownerLength; i++) {
            owners[i] = address(uint160(i + 1));
        }

        RecoverySpell recovery1 = recoveryFactory.createRecoverySpell(
            salt, owners, SAFE, threshold, recoveryThreshold, delay
        );

        vm.expectRevert();
        RecoverySpell recovery2 = recoveryFactory.createRecoverySpell(
            salt, owners, SAFE, threshold, recoveryThreshold, delay
        );

        assertEq(
            address(
                recoveryFactory.calculateAddress(
                    salt, owners, SAFE, threshold, recoveryThreshold, delay
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
        uint256 threshold,
        uint256 recoveryThreshold,
        uint256 delay
    ) public {
        ownerLength = uint8(_bound(ownerLength, 1, 10));

        address[] memory owners = new address[](ownerLength);
        for (uint8 i = 0; i < ownerLength; i++) {
            owners[i] = address(uint160(i + 1));
        }

        RecoverySpell spell =
            _trySpellCreation(salt, owners, SAFE, threshold, delay);

        /// owner length must be greater than or equal to threshold
        /// threshold must be greater than or equal to 1
        /// recoveryThreshold must be less than or equal to owner length
        /// delay must be lte 20 days
        /// the above conditions being true implies the spell should not be zero
        if (
            ownerLength >= threshold && threshold >= 1 && delay <= 20 days
                && ownerLength >= recoveryThreshold
        ) {
            assertNotEq(address(spell), address(0), "spell should not be zero");
        }

        /// if deployment fails, nothing to check
        if (address(spell) != address(0)) {
            assertTrue(
                spell.getOwners().length >= spell.threshold(),
                "threshold invariant 1 violated"
            );
            assertTrue(spell.threshold() >= 1, "threshold invariant 2 violated");
            assertTrue(spell.delay() <= 365 days, "delay invariant violated");

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
            salt, owners, safe, threshold, threshold, delay
        ) returns (RecoverySpell spell) {
            return spell;
        } catch Error(string memory) {
            return RecoverySpell(address(0));
        }
    }

    function testViewFunctionFailsThresholdGtOwners() public {
        vm.expectRevert("RecoverySpell: Threshold must be lte number of owners");
        recoveryFactory.calculateAddress(
            bytes32(0), new address[](1), SAFE, 2, 1, 0
        );
    }

    function testViewFunctionFailsRecoveryThresholdGtOwners() public {
        vm.expectRevert(
            "RecoverySpell: Recovery threshold must be lte number of owners"
        );
        recoveryFactory.calculateAddress(
            bytes32(0), new address[](1), SAFE, 1, 2, 0
        );
    }

    function testViewFunctionFailsThresholdEqZero() public {
        vm.expectRevert("RecoverySpell: Threshold must be gt 0");
        recoveryFactory.calculateAddress(
            bytes32(0), new address[](1), SAFE, 0, 0, 0
        );
    }

    function testViewFunctionFailsDaysOutOfBand() public {
        vm.expectRevert("RecoverySpell: Delay must be lte a year");
        recoveryFactory.calculateAddress(
            bytes32(0), new address[](1), SAFE, 1, 0, 365 days + 1
        );
    }

    function testCreateFunctionFailsDaysOutOfBand() public {
        vm.expectRevert("RecoverySpell: Delay must be lte a year");
        recoveryFactory.createRecoverySpell(
            bytes32(0), new address[](1), SAFE, 1, 0, 365 days + 1
        );
    }

    function testCreateFunctionFailsThresholdGtOwners() public {
        vm.expectRevert("RecoverySpell: Threshold must be lte number of owners");
        recoveryFactory.createRecoverySpell(
            bytes32(0), new address[](1), SAFE, 2, 0, 1
        );
    }

    function testCreateFunctionFailsThresholdEqZero() public {
        address[] memory recoveryOwners = new address[](1);
        recoveryOwners[0] = address(0x1);

        vm.expectRevert("RecoverySpell: Threshold must be gt 0");
        recoveryFactory.createRecoverySpell(
            bytes32(0), new address[](1), SAFE, 0, 0, 1
        );
    }

    function testCreateFunctionFailsDuplicateOwner() public {
        address[] memory recoveryOwners = new address[](3);
        recoveryOwners[0] = address(0x1);
        recoveryOwners[1] = address(0x2);
        recoveryOwners[2] = address(0x1);

        vm.expectRevert("RecoverySpell: Duplicate owner");
        recoveryFactory.createRecoverySpell(
            bytes32(0), recoveryOwners, SAFE, 1, 1, 10 days
        );
    }

    function testCalculateAddressFailsDuplicateOwner() public {
        address[] memory recoveryOwners = new address[](3);
        recoveryOwners[0] = address(0x1);
        recoveryOwners[1] = address(0x2);
        recoveryOwners[2] = address(0x2);

        vm.expectRevert("RecoverySpell: Duplicate owner");
        recoveryFactory.calculateAddress(
            bytes32(0), recoveryOwners, SAFE, 1, 1, 10 days
        );
    }

    function testParamSubstitutionSaltChangesAddress() public view {
        bytes32 salt = bytes32(uint256(1));

        address[] memory owners = new address[](3);
        owners[0] = address(0x1);
        owners[1] = address(0x2);
        owners[2] = address(0x3);

        uint256 recoveryThreshold = 1;
        uint256 threshold = 2;
        uint256 delay = 2 days;

        address firstAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, SAFE, threshold, recoveryThreshold, delay
            )
        );
        address secondAddress = address(
            recoveryFactory.calculateAddress(
                bytes32(0), owners, SAFE, threshold, recoveryThreshold, delay
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

        uint256 recoveryThreshold = 1;
        uint256 threshold = 2;
        uint256 delay = 2 days;

        address firstAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, SAFE, threshold, recoveryThreshold, delay
            )
        );

        owners[2] = address(0x4);
        address secondAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, SAFE, threshold, recoveryThreshold, delay
            )
        );

        assertNotEq(
            firstAddress, secondAddress, "addresses should not be the same"
        );
    }

    function testParamSubstitutionSafeChangesAddress() public {
        bytes32 salt = bytes32(uint256(1));

        address[] memory owners = new address[](3);
        owners[0] = address(0x1);
        owners[1] = address(0x2);
        owners[2] = address(0x3);

        uint256 recoveryThreshold = 1;
        uint256 threshold = 2;
        uint256 delay = 2 days;

        address safe = address(0x3333);
        vm.etch(safe, SAFE_BYTECODE);

        address firstAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, safe, threshold, recoveryThreshold, delay
            )
        );
        address secondAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, SAFE, threshold, recoveryThreshold, delay
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

        uint256 recoveryThreshold = 1;
        uint256 threshold = 2;
        uint256 delay = 2 days;

        address firstAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, SAFE, threshold, recoveryThreshold, delay
            )
        );
        address secondAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, SAFE, threshold + 1, recoveryThreshold, delay
            )
        );
        address thirdAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, SAFE, threshold - 1, recoveryThreshold, delay
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

    function testParamSubstitutionRecoveryThresholdChangesAddress()
        public
        view
    {
        bytes32 salt = bytes32(uint256(1));

        address[] memory owners = new address[](3);
        owners[0] = address(0x1);
        owners[1] = address(0x2);
        owners[2] = address(0x3);

        uint256 recoveryThreshold = 1;
        uint256 threshold = 2;
        uint256 delay = 2 days;

        address firstAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, SAFE, threshold, recoveryThreshold, delay
            )
        );
        address secondAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, SAFE, threshold, recoveryThreshold + 1, delay
            )
        );
        address thirdAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, SAFE, threshold, recoveryThreshold - 1, delay
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

        uint256 recoveryThreshold = 1;
        uint256 threshold = 2;
        uint256 delay = 2 days;

        address firstAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, SAFE, threshold, recoveryThreshold, delay
            )
        );
        address secondAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, SAFE, threshold, recoveryThreshold, delay + 1
            )
        );
        address thirdAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, SAFE, threshold, recoveryThreshold, delay - 1
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
