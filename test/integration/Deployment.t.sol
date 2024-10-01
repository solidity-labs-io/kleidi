pragma solidity 0.8.25;

import {IERC20} from "@openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {
    IMorpho,
    Position,
    IMorphoBase,
    MarketParams
} from "src/interface/IMorpho.sol";

import {stdError} from "forge-std/Test.sol";

import {Guard} from "src/Guard.sol";
import {SystemDeploy} from "src/deploy/SystemDeploy.s.sol";
import {RecoverySpell} from "src/RecoverySpell.sol";
import {AddressCalculation} from "src/views/AddressCalculation.sol";
import {RecoverySpellFactory} from "src/RecoverySpellFactory.sol";
import {TimelockFactory, DeploymentParams} from "src/TimelockFactory.sol";
import {generateCalldatas} from "test/utils/NestedArrayHelper.sol";
import {
    InstanceDeployer,
    NewInstance,
    SystemInstance
} from "src/InstanceDeployer.sol";

contract DeploymentMultichainTest is SystemDeploy {
    /// @notice reference to the Guard contract
    Guard public guard;

    /// @notice the multicall contract
    address public multicall;

    /// @notice address of the morpho blue contract
    address public morphoBlue;

    /// @notice ethena USD contract
    address public ethenaUsd;

    /// @notice DAI contract
    address public dai;

    /// @notice morpho blue irm contract
    address public irm;

    /// @notice morpho blue oracle contract
    address public oracle;

    /// @notice reference to the instance deployer
    InstanceDeployer public deployer;

    /// @notice reference to the AddressCalculation contract
    AddressCalculation public addressCalculation;

    /// @notice reference to the RecoverySpellFactory contract
    RecoverySpellFactory public recoveryFactory;

    /// @notice reference to the TimelockFactory contract
    TimelockFactory public timelockFactory;

    /// @notice the length of the market params in bytes
    uint256 constant MARKET_PARAMS_BYTES_LENGTH = 5 * 32;

    /// @notice liquidation loan to value ratio
    uint256 public constant lltv = 915000000000000000;

    /// @notice the base fork id
    uint256 public baseForkId;

    /// @notice the ethereum fork id
    uint256 public ethereumForkId;

    function setUp() public {
        vm.makePersistent(address(addresses));
        vm.makePersistent(address(this));

        baseForkId = vm.createSelectFork("base");
        ethereumForkId = vm.createFork(vm.envString("ETH_RPC_URL"));

        /// Deploy the system on Base
        deploy();

        vm.selectFork(ethereumForkId);

        /// Deploy the system on Mainnet
        deploy();

        ethenaUsd = addresses.getAddress("ETHENA_USD");
        dai = addresses.getAddress("DAI");
        irm = addresses.getAddress("MORPHO_BLUE_IRM");
        oracle = addresses.getAddress("MORPHO_BLUE_EUSD_DAI_ORACLE");
        multicall = addresses.getAddress("MULTICALL3");
        morphoBlue = addresses.getAddress("MORPHO_BLUE");

        guard = Guard(addresses.getAddress("GUARD"));
        recoveryFactory =
            RecoverySpellFactory(addresses.getAddress("RECOVERY_SPELL_FACTORY"));
        deployer = InstanceDeployer(addresses.getAddress("INSTANCE_DEPLOYER"));
        timelockFactory =
            TimelockFactory(addresses.getAddress("TIMELOCK_FACTORY"));
        addressCalculation =
            AddressCalculation(addresses.getAddress("ADDRESS_CALCULATION"));
    }

    function testMultichainDeployment() public view {
        assertEq(
            addresses.getAddress("TIMELOCK_FACTORY", 1),
            addresses.getAddress("TIMELOCK_FACTORY", 8453),
            "TIMELOCK_FACTORY address should be the same"
        );
        assertEq(
            addresses.getAddress("RECOVERY_SPELL_FACTORY", 1),
            addresses.getAddress("RECOVERY_SPELL_FACTORY", 8453),
            "RECOVERY_SPELL_FACTORY address should be the same"
        );
        assertEq(
            addresses.getAddress("GUARD", 1),
            addresses.getAddress("GUARD", 8453),
            "GUARD address should be the same"
        );
        assertEq(
            addresses.getAddress("INSTANCE_DEPLOYER", 1),
            addresses.getAddress("INSTANCE_DEPLOYER", 8453),
            "INSTANCE_DEPLOYER address should be the same"
        );
    }

    function testDifferentCalldataSameAddresses()
        public
        returns (NewInstance memory instance)
    {
        address[] memory owners = new address[](3);
        owners[0] = vm.addr(10);
        owners[1] = vm.addr(11);
        owners[2] = vm.addr(12);

        address[] memory recoverySpells = new address[](0);
        address[] memory hotSigners = new address[](2);
        hotSigners[0] = vm.addr(1111111);
        hotSigners[1] = vm.addr(2222222);

        instance = NewInstance(
            owners,
            2,
            recoverySpells,
            DeploymentParams(
                2 days,
                /// min delay
                7 days,
                /// expiration period
                vm.addr(13),
                28 days,
                /// pause duration
                hotSigners,
                new address[](0),
                new bytes4[](0),
                new uint16[](0),
                new uint16[](0),
                new bytes[][](0),
                bytes32(0)
            )
        );

        SystemInstance memory calculatedInstance =
            addressCalculation.calculateAddress(instance);

        {
            /// each morpho blue function call needs two checks:
            /// 1). check the pool id where funds are being deposited is whitelisted.
            /// 2). check the recipient of the funds is whitelisted whether withdrawing
            /// or depositing.

            uint16[] memory startIndexes = new uint16[](8);
            /// morpho blue supply
            startIndexes[0] = 4;

            /// only grab last twenty bytes of the 7th argument
            startIndexes[1] = 4 + 32 * 7 + 12;

            /// ethena usd approve morpho
            startIndexes[2] = 16;

            /// only check last twenty bytes of the 1st argument
            startIndexes[3] = 4 + 32 * 8 + 12;

            /// only grab last twenty bytes of the 8th argument
            startIndexes[4] = 4 + 32 * 8 + 12;

            /// only grab last twenty bytes of the 8th argument
            startIndexes[5] = 4 + 32 * 8 + 12;

            /// check last twenty bytes of the 7th argument
            startIndexes[6] = 4 + 32 * 6 + 12;

            /// check last twenty bytes of the 8th argument
            startIndexes[7] = 4 + 32 * 7 + 12;

            uint16[] memory endIndexes = new uint16[](8);
            /// morpho blue supply
            endIndexes[0] = startIndexes[0] + 32 * 5;

            /// last twenty bytes represents who supplying on behalf of
            endIndexes[1] = startIndexes[1] + 20;

            /// ethena usd approve morpho
            endIndexes[2] = startIndexes[2] + 20;

            /// last twenty bytes represents who is approved to spend the tokens
            /// morpho borrow
            endIndexes[3] = startIndexes[3] + 20;

            /// morpho repay
            endIndexes[4] = startIndexes[4] + 20;

            /// morpho withdraw
            endIndexes[5] = startIndexes[5] + 20;

            /// last twenty bytes represents asset receiver
            endIndexes[6] = startIndexes[6] + 20;

            /// last twenty bytes represents asset receiver
            endIndexes[7] = startIndexes[7] + 20;

            /// last twenty bytes represents asset receiver

            bytes4[] memory selectors = new bytes4[](8);
            selectors[0] = IMorphoBase.supply.selector;
            selectors[1] = IMorphoBase.supply.selector;
            selectors[2] = IERC20.approve.selector;
            selectors[3] = IMorphoBase.borrow.selector;
            selectors[4] = IMorphoBase.repay.selector;
            selectors[5] = IMorphoBase.withdraw.selector;
            /// if borrowable assets are supplied to a market where there is bad debt, there is a possibility of loss
            /// so the timelock should be the only one allowed to supply borrowable assets to the whitelisted market
            /// supplying collateral to markets with bad debt should not pose a risk to capital because the
            /// collateral is not borrowed
            selectors[6] = IMorphoBase.supplyCollateral.selector;
            selectors[7] = IMorphoBase.withdrawCollateral.selector;

            bytes[][] memory calldatas = new bytes[][](8);
            bytes memory singleCalldata;

            /// can only deposit to dai/eusd pool
            singleCalldata = abi.encode(dai, ethenaUsd, oracle, irm, lltv);
            calldatas = generateCalldatas(calldatas, singleCalldata, 0);

            /// can only deposit to timelock
            singleCalldata = abi.encodePacked(calculatedInstance.timelock);
            calldatas = generateCalldatas(calldatas, singleCalldata, 1);

            /// morpho blue address can be approved to spend eUSD
            singleCalldata = abi.encodePacked(morphoBlue);
            calldatas = generateCalldatas(calldatas, singleCalldata, 2);

            /// can only borrow on behalf of timelock
            singleCalldata = abi.encodePacked(calculatedInstance.timelock);
            calldatas = generateCalldatas(calldatas, singleCalldata, 3);

            /// can only deposit to timelock
            calldatas = generateCalldatas(calldatas, singleCalldata, 4);

            /// can only repay on behalf of timelock
            calldatas = generateCalldatas(calldatas, singleCalldata, 5);

            /// can only supply collateral on behalf of timelock
            calldatas = generateCalldatas(calldatas, singleCalldata, 6);

            /// can only withdraw collateral back to timelock
            calldatas = generateCalldatas(calldatas, singleCalldata, 7);

            address[] memory targets = new address[](8);
            targets[0] = morphoBlue;
            targets[1] = morphoBlue;
            targets[2] = ethenaUsd;
            targets[3] = morphoBlue;
            targets[4] = morphoBlue;
            targets[5] = morphoBlue;
            targets[6] = morphoBlue;
            targets[7] = morphoBlue;
        }

        instance.recoverySpells = new address[](1);
        instance.recoverySpells[0] = address(111111111111);

        SystemInstance memory calculatedInstance2 =
            addressCalculation.calculateAddress(instance);

        vm.prank(hotSigners[0]);
        SystemInstance memory actualInstanceMainnet =
            deployer.createSystemInstance(instance);

        assertEq(
            address(calculatedInstance.safe),
            address(actualInstanceMainnet.safe),
            "Deployed vs Actual Safe addresses should be the same"
        );
        assertEq(
            address(calculatedInstance.safe),
            address(calculatedInstance2.safe),
            "Safe addresses should be the same"
        );
        assertEq(
            address(calculatedInstance.timelock),
            address(calculatedInstance2.timelock),
            "Timelock addresses should be the same"
        );
        assertEq(
            address(calculatedInstance.timelock),
            address(actualInstanceMainnet.timelock),
            "Deployed vs Actual Timelock addresses should be the same"
        );

        vm.selectFork(baseForkId);

        addressCalculation =
            AddressCalculation(addresses.getAddress("ADDRESS_CALCULATION"));

        SystemInstance memory calculatedInstanceBase =
            addressCalculation.calculateAddress(instance);

        /// change the whitelisted calldata before deployment on base
        instance.timelockParams.contractAddresses = new address[](1);
        instance.timelockParams.contractAddresses[0] = address(1);
        instance.timelockParams.selectors = new bytes4[](1);
        instance.timelockParams.selectors[0] = bytes4("1");

        instance.timelockParams.startIndexes = new uint16[](1);
        instance.timelockParams.startIndexes[0] = 4;

        instance.timelockParams.endIndexes = new uint16[](1);
        instance.timelockParams.endIndexes[0] = 10;

        instance.timelockParams.datas = new bytes[][](1);
        bytes[] memory data = new bytes[](1);
        data[0] = new bytes(6);
        instance.timelockParams.datas[0] = data;

        vm.prank(hotSigners[0]);
        SystemInstance memory actualInstanceBase =
            deployer.createSystemInstance(instance);

        assertEq(
            address(calculatedInstanceBase.safe),
            address(calculatedInstance.safe),
            "Safe addresses should be the same across chains"
        );
        assertEq(
            address(calculatedInstanceBase.safe),
            address(actualInstanceBase.safe),
            "Deployed vs Actual Safe addresses should be the same across chains"
        );
        assertEq(
            address(calculatedInstanceBase.timelock),
            address(calculatedInstance.timelock),
            "Timelock addresses should be the same across chains"
        );
        assertEq(
            address(calculatedInstanceBase.timelock),
            address(actualInstanceBase.timelock),
            "Deployed vs Actual Timelock addresses should be the same"
        );

        {
            vm.expectRevert("InstanceDeployer: safe already created");
            addressCalculation.calculateAddress(instance);

            /// panic at owner assertion
            vm.prank(hotSigners[0]);
            vm.expectRevert(stdError.assertionError);
            deployer.createSystemInstance(instance);

            vm.selectFork(ethereumForkId);

            vm.expectRevert("InstanceDeployer: safe already created");
            addressCalculation.calculateAddress(instance);

            vm.prank(hotSigners[0]);
            vm.expectRevert(stdError.assertionError);
            deployer.createSystemInstance(instance);
        }
    }

    function testDifferentRecoverySpellSameAddresses()
        public
        returns (NewInstance memory instance)
    {
        address[] memory owners = new address[](3);
        owners[0] = vm.addr(10);
        owners[1] = vm.addr(11);
        owners[2] = vm.addr(12);

        address[] memory recoverySpells = new address[](0);
        address[] memory hotSigners = new address[](2);
        hotSigners[0] = vm.addr(1111111);
        hotSigners[1] = vm.addr(2222222);

        instance = NewInstance(
            owners,
            2,
            recoverySpells,
            DeploymentParams(
                2 days,
                /// min delay
                7 days,
                /// expiration period
                vm.addr(13),
                28 days,
                /// pause duration
                hotSigners,
                new address[](0),
                new bytes4[](0),
                new uint16[](0),
                new uint16[](0),
                new bytes[][](0),
                bytes32(0)
            )
        );

        SystemInstance memory calculatedInstance =
            addressCalculation.calculateAddress(instance);

        {
            /// each morpho blue function call needs two checks:
            /// 1). check the pool id where funds are being deposited is whitelisted.
            /// 2). check the recipient of the funds is whitelisted whether withdrawing
            /// or depositing.

            uint16[] memory startIndexes = new uint16[](8);
            /// morpho blue supply
            startIndexes[0] = 4;

            /// only grab last twenty bytes of the 7th argument
            startIndexes[1] = 4 + 32 * 7 + 12;

            /// ethena usd approve morpho
            startIndexes[2] = 16;

            /// only check last twenty bytes of the 1st argument
            startIndexes[3] = 4 + 32 * 8 + 12;

            /// only grab last twenty bytes of the 8th argument
            startIndexes[4] = 4 + 32 * 8 + 12;

            /// only grab last twenty bytes of the 8th argument
            startIndexes[5] = 4 + 32 * 8 + 12;

            /// check last twenty bytes of the 7th argument
            startIndexes[6] = 4 + 32 * 6 + 12;

            /// check last twenty bytes of the 8th argument
            startIndexes[7] = 4 + 32 * 7 + 12;

            uint16[] memory endIndexes = new uint16[](8);
            /// morpho blue supply
            endIndexes[0] = startIndexes[0] + 32 * 5;

            /// last twenty bytes represents who supplying on behalf of
            endIndexes[1] = startIndexes[1] + 20;

            /// ethena usd approve morpho
            endIndexes[2] = startIndexes[2] + 20;

            /// last twenty bytes represents who is approved to spend the tokens
            /// morpho borrow
            endIndexes[3] = startIndexes[3] + 20;

            /// morpho repay
            endIndexes[4] = startIndexes[4] + 20;

            /// morpho withdraw
            endIndexes[5] = startIndexes[5] + 20;

            /// last twenty bytes represents asset receiver
            endIndexes[6] = startIndexes[6] + 20;

            /// last twenty bytes represents asset receiver
            endIndexes[7] = startIndexes[7] + 20;

            /// last twenty bytes represents asset receiver

            bytes4[] memory selectors = new bytes4[](8);
            selectors[0] = IMorphoBase.supply.selector;
            selectors[1] = IMorphoBase.supply.selector;
            selectors[2] = IERC20.approve.selector;
            selectors[3] = IMorphoBase.borrow.selector;
            selectors[4] = IMorphoBase.repay.selector;
            selectors[5] = IMorphoBase.withdraw.selector;
            /// if borrowable assets are supplied to a market where there is bad debt, there is a possibility of loss
            /// so the timelock should be the only one allowed to supply borrowable assets to the whitelisted market
            /// supplying collateral to markets with bad debt should not pose a risk to capital because the
            /// collateral is not borrowed
            selectors[6] = IMorphoBase.supplyCollateral.selector;
            selectors[7] = IMorphoBase.withdrawCollateral.selector;

            bytes[][] memory calldatas = new bytes[][](8);
            bytes memory singleCalldata;

            /// can only deposit to dai/eusd pool
            singleCalldata = abi.encode(dai, ethenaUsd, oracle, irm, lltv);
            calldatas = generateCalldatas(calldatas, singleCalldata, 0);

            /// can only deposit to timelock
            singleCalldata = abi.encodePacked(calculatedInstance.timelock);
            calldatas = generateCalldatas(calldatas, singleCalldata, 1);

            /// morpho blue address can be approved to spend eUSD
            singleCalldata = abi.encodePacked(morphoBlue);
            calldatas = generateCalldatas(calldatas, singleCalldata, 2);

            // /// can only borrow on behalf of timelock
            singleCalldata = abi.encodePacked(calculatedInstance.timelock);
            calldatas = generateCalldatas(calldatas, singleCalldata, 3);

            // /// can only deposit to timelock
            calldatas = generateCalldatas(calldatas, singleCalldata, 4);

            // /// can only repay on behalf of timelock
            calldatas = generateCalldatas(calldatas, singleCalldata, 5);

            // /// can only supply collateral on behalf of timelock
            calldatas = generateCalldatas(calldatas, singleCalldata, 6);

            // /// can only withdraw collateral back to timelock
            calldatas = generateCalldatas(calldatas, singleCalldata, 7);

            address[] memory targets = new address[](8);
            targets[0] = morphoBlue;
            targets[1] = morphoBlue;
            targets[2] = ethenaUsd;
            targets[3] = morphoBlue;
            targets[4] = morphoBlue;
            targets[5] = morphoBlue;
            targets[6] = morphoBlue;
            targets[7] = morphoBlue;
        }

        instance.recoverySpells = new address[](1);
        instance.recoverySpells[0] = address(111111111111);

        SystemInstance memory calculatedInstance2 =
            addressCalculation.calculateAddress(instance);

        vm.prank(hotSigners[0]);
        SystemInstance memory actualInstanceMainnet =
            deployer.createSystemInstance(instance);

        assertEq(
            address(calculatedInstance.safe),
            address(actualInstanceMainnet.safe),
            "Deployed vs Actual Safe addresses should be the same"
        );
        assertEq(
            address(calculatedInstance.safe),
            address(calculatedInstance2.safe),
            "Safe addresses should be the same"
        );
        assertEq(
            address(calculatedInstance.timelock),
            address(calculatedInstance2.timelock),
            "Timelock addresses should be the same"
        );
        assertEq(
            address(calculatedInstance.timelock),
            address(actualInstanceMainnet.timelock),
            "Deployed vs Actual Timelock addresses should be the same"
        );

        vm.selectFork(baseForkId);

        addressCalculation =
            AddressCalculation(addresses.getAddress("ADDRESS_CALCULATION"));

        instance.recoverySpells[0] = address(222222222222);

        SystemInstance memory calculatedInstanceBase =
            addressCalculation.calculateAddress(instance);

        vm.prank(hotSigners[0]);
        SystemInstance memory actualInstanceBase =
            deployer.createSystemInstance(instance);

        assertEq(
            address(calculatedInstanceBase.safe),
            address(calculatedInstance.safe),
            "Safe addresses should be the same across chains"
        );
        assertEq(
            address(calculatedInstanceBase.safe),
            address(actualInstanceBase.safe),
            "Deployed vs Actual Safe addresses should be the same across chains"
        );
        assertEq(
            address(calculatedInstanceBase.timelock),
            address(calculatedInstance.timelock),
            "Timelock addresses should be the same across chains"
        );
        assertEq(
            address(calculatedInstanceBase.timelock),
            address(actualInstanceBase.timelock),
            "Deployed vs Actual Timelock addresses should be the same"
        );

        {
            vm.expectRevert("InstanceDeployer: safe already created");
            addressCalculation.calculateAddress(instance);

            /// panic at owner assertion
            vm.prank(hotSigners[0]);
            vm.expectRevert(stdError.assertionError);
            deployer.createSystemInstance(instance);

            vm.selectFork(ethereumForkId);

            vm.expectRevert("InstanceDeployer: safe already created");
            addressCalculation.calculateAddress(instance);

            vm.prank(hotSigners[0]);
            vm.expectRevert(stdError.assertionError);
            deployer.createSystemInstance(instance);
        }
    }
}
