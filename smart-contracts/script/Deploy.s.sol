// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../contracts/RobotAttestationRegistry.sol";

contract DeployScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address admin = vm.envAddress("ADMIN_ADDRESS");

        // Parse gateway addresses from env (comma-separated)
        string memory gatewayAddressesStr = vm.envString("GATEWAY_ADDRESSES");
        address[] memory gateways = parseAddresses(gatewayAddressesStr);

        console.log("Deploying RobotAttestationRegistry...");
        console.log("Admin:", admin);
        console.log("Gateway count:", gateways.length);

        vm.startBroadcast(deployerPrivateKey);

        RobotAttestationRegistry registry = new RobotAttestationRegistry(
            admin,
            gateways
        );

        console.log("Registry deployed at:", address(registry));

        vm.stopBroadcast();

        // Verify deployment
        console.log("\nVerifying deployment...");
        console.log("Admin has DEFAULT_ADMIN_ROLE:", registry.hasRole(registry.DEFAULT_ADMIN_ROLE(), admin));
        console.log("Admin has GOVERNANCE_ROLE:", registry.hasRole(registry.GOVERNANCE_ROLE(), admin));

        for (uint256 i = 0; i < gateways.length; i++) {
            console.log("Gateway", i, "has GATEWAY_ROLE:", registry.hasRole(registry.GATEWAY_ROLE(), gateways[i]));
        }
    }

    /// @notice Parse comma-separated addresses
    function parseAddresses(string memory addresses) internal pure returns (address[] memory) {
        // Simple parser for comma-separated addresses
        // Format: "0x123...,0x456...,0x789..."

        bytes memory addrBytes = bytes(addresses);
        uint256 count = 1;

        // Count commas
        for (uint256 i = 0; i < addrBytes.length; i++) {
            if (addrBytes[i] == ",") {
                count++;
            }
        }

        address[] memory result = new address[](count);

        // Split and parse (simplified - in production use a proper CSV parser)
        // For now, assume single gateway
        result[0] = vm.parseAddress(addresses);

        return result;
    }
}
