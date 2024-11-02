pragma solidity ^0.8.13;

import {console, Test} from "forge-std/Test.sol";

import {InstanceDeployer, NewInstance} from "src/InstanceDeployer.sol";

contract InstanceDeployerTest is Test {
    bytes public deploymentParams =
        hex"afc814dd00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000014dc79964da2c08b23698b3d3cc7ca32193d9955000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000151800000000000000000000000000000000000000000000000000000000000278d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000015180000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000003a000000000000000000000000000000000000000000000000000000000000004a000000000000000000000000000000000000000000000000000000000000005a000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000001000000000000000000000000990a31f1035ffbc89c2c86487745c0562ff85b390000000000000000000000000000000000000000000000000000000000000007000000000000000000000000bbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb000000000000000000000000bbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb000000000000000000000000bbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb0000000000000000000000004c9edd5852cd905f086c759e8383e09bff1e68b3000000000000000000000000cb327b99ff831bf8223cced12b1338ff3aa322ff000000000000000000000000c1cba3fcea344f92d9239c08c0568f6f2f0ee4520000000000000000000000002416092f143378750bb29b79ed961ab195cceea50000000000000000000000000000000000000000000000000000000000000007a99aad8900000000000000000000000000000000000000000000000000000000a99aad89000000000000000000000000000000000000000000000000000000005c2bea4900000000000000000000000000000000000000000000000000000000095ea7b300000000000000000000000000000000000000000000000000000000095ea7b300000000000000000000000000000000000000000000000000000000095ea7b300000000000000000000000000000000000000000000000000000000095ea7b3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000f000000000000000000000000000000000000000000000000000000000000000f00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000000a4000000000000000000000000000000000000000000000000000000000000010400000000000000000000000000000000000000000000000000000000000001040000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000002400000000000000000000000000000000000000000000000000000000000000240000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000048000000000000000000000000000000000000000000000000000000000000005000000000000000000000000000000000000000000000000000000000000000580000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000006800000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002c000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000006b175474e89094c44da98b954eedeac495271d0f0000000000000000000000004c9edd5852cd905f086c759e8383e09bff1e68b3000000000000000000000000ae4750d0813b5e37a51f7629beedd72af1f9ca35000000000000000000000000870ac11d48b15db9a138cf899d20f13f79ba00bc0000000000000000000000000000000000000000000000000aaf96eb9d0d000000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000cfa3ef56d303ae4faaba0592388f19d7c3399fb4000000000000000000000000cb327b99ff831bf8223cced12b1338ff3aa322ff000000000000000000000000c866447b4c254e2029f1bfb700f5aa43ce27b1be00000000000000000000000046415998764c29ab2a25cbea6254146d50d226870000000000000000000000000000000000000000000000000bef55718ad6000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000060a3e35cc302bfa44cb288bc5a4f316fdb1adb42000000000000000000000000c1cba3fcea344f92d9239c08c0568f6f2f0ee452000000000000000000000000a54122f0e0766258377ffe732e454a3248f454f400000000000000000000000046415998764c29ab2a25cbea6254146d50d226870000000000000000000000000000000000000000000000000bef55718ad6000000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda029130000000000000000000000002416092f143378750bb29b79ed961ab195cceea50000000000000000000000001baab21821c6468f8aee73ee60fd8fdc39c0c97300000000000000000000000046415998764c29ab2a25cbea6254146d50d226870000000000000000000000000000000000000000000000000aaf96eb9d0d0000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000028a2c6e32f3b70be1b9e8254f2cbcbda1ee6a93def000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000028a2c6e32f3b70be1b9e8254f2cbcbda1ee6a93def000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000028a2c6e32f3b70be1b9e8254f2cbcbda1ee6a93def000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000028a2c6e32f3b70be1b9e8254f2cbcbda1ee6a93def000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000028a2c6e32f3b70be1b9e8254f2cbcbda1ee6a93def000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000028a2c6e32f3b70be1b9e8254f2cbcbda1ee6a93def000000000000000000000000";

    function testCheckCalldata() public {
        address instanceDeployer = 0xa6567A0bc6F0c465e69947E5d45a0b55d197b4a3;

        (bool success,) = instanceDeployer.call(deploymentParams);

        console.log("success: ", success);
    }
}
