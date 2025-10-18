// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/RobotAttestationRegistry.sol";

contract RobotAttestationRegistryTest is Test {
    RobotAttestationRegistry public registry;

    address public admin = address(0x1);
    address public gateway = address(0x2);
    address public user = address(0x3);

    event ModelRegistered(
        bytes32 indexed modelHash,
        string name,
        address indexed registeredBy,
        uint256 timestamp
    );

    event CheckpointAnchored(
        bytes32 indexed checkpointId,
        bytes32 indexed merkleRoot,
        bytes32 indexed enclaveMeasurement,
        address gateway,
        string vendor,
        uint256 timestamp
    );

    event EnclaveRevoked(
        bytes32 indexed enclaveMeasurement,
        address indexed revokedBy,
        string reason,
        uint256 timestamp
    );

    function setUp() public {
        vm.startPrank(admin);

        address[] memory initialGateways = new address[](1);
        initialGateways[0] = gateway;

        registry = new RobotAttestationRegistry(admin, initialGateways);

        vm.stopPrank();
    }

    // ============ Model Registry Tests ============

    function testRegisterModel() public {
        bytes32 modelHash = keccak256("model-v1");
        string memory name = "TestModel v1";
        bytes32 datasetHash = keccak256("dataset-v1");
        string memory containerDigest = "sha256:abc123";
        bytes memory signatureBundle = hex"deadbeef";

        vm.startPrank(user);

        vm.expectEmit(true, true, false, true);
        emit ModelRegistered(modelHash, name, user, block.timestamp);

        registry.registerModel(
            name,
            modelHash,
            datasetHash,
            containerDigest,
            signatureBundle
        );

        RobotAttestationRegistry.ModelInfo memory info = registry.getModel(modelHash);
        assertEq(info.name, name);
        assertEq(info.modelHash, modelHash);
        assertEq(info.datasetHash, datasetHash);
        assertEq(info.containerDigest, containerDigest);
        assertEq(info.registeredBy, user);
        assertTrue(info.active);

        vm.stopPrank();
    }

    function testCannotRegisterModelTwice() public {
        bytes32 modelHash = keccak256("model-v1");

        vm.startPrank(user);

        registry.registerModel(
            "Model v1",
            modelHash,
            bytes32(0),
            "",
            ""
        );

        vm.expectRevert(RobotAttestationRegistry.ModelAlreadyRegistered.selector);
        registry.registerModel(
            "Model v1 duplicate",
            modelHash,
            bytes32(0),
            "",
            ""
        );

        vm.stopPrank();
    }

    function testRevokeModel() public {
        bytes32 modelHash = keccak256("model-v1");

        vm.prank(user);
        registry.registerModel("Model v1", modelHash, bytes32(0), "", "");

        vm.prank(admin);
        registry.revokeModel(modelHash);

        assertTrue(registry.isModelRevoked(modelHash));
        assertFalse(registry.getModel(modelHash).active);
    }

    function testCannotRevokeModelUnauthorized() public {
        bytes32 modelHash = keccak256("model-v1");

        vm.prank(user);
        registry.registerModel("Model v1", modelHash, bytes32(0), "", "");

        vm.prank(user);
        vm.expectRevert();
        registry.revokeModel(modelHash);
    }

    // ============ Checkpoint Anchoring Tests ============

    function testAnchorCheckpoint() public {
        bytes32 merkleRoot = keccak256("merkle-root");
        bytes32 enclaveMeasurement = keccak256("enclave-measurement");
        string memory vendor = "intel-sgx";
        bytes memory gatewaySignature = hex"abcdef";

        vm.startPrank(gateway);

        vm.expectEmit(false, true, true, true);
        emit CheckpointAnchored(
            bytes32(0), // checkpointId is computed, so we can't predict it
            merkleRoot,
            enclaveMeasurement,
            gateway,
            vendor,
            block.timestamp
        );

        bytes32 checkpointId = registry.anchorCheckpoint(
            merkleRoot,
            enclaveMeasurement,
            vendor,
            gatewaySignature
        );

        RobotAttestationRegistry.Checkpoint memory cp = registry.getCheckpoint(checkpointId);
        assertEq(cp.merkleRoot, merkleRoot);
        assertEq(cp.enclaveMeasurement, enclaveMeasurement);
        assertEq(cp.gateway, gateway);
        assertEq(cp.vendor, vendor);

        vm.stopPrank();
    }

    function testCannotAnchorCheckpointUnauthorized() public {
        bytes32 merkleRoot = keccak256("merkle-root");
        bytes32 enclaveMeasurement = keccak256("enclave-measurement");

        vm.prank(user);
        vm.expectRevert();
        registry.anchorCheckpoint(
            merkleRoot,
            enclaveMeasurement,
            "intel-sgx",
            ""
        );
    }

    function testCannotAnchorCheckpointWithZeroMerkleRoot() public {
        vm.prank(gateway);
        vm.expectRevert(RobotAttestationRegistry.InvalidMerkleRoot.selector);
        registry.anchorCheckpoint(
            bytes32(0),
            keccak256("enclave"),
            "intel-sgx",
            ""
        );
    }

    function testCannotAnchorCheckpointWithRevokedEnclave() public {
        bytes32 enclaveMeasurement = keccak256("enclave-measurement");

        // Revoke the enclave first
        vm.prank(admin);
        registry.emergencyRevokeEnclave(enclaveMeasurement, "Compromised");

        // Try to anchor checkpoint
        vm.prank(gateway);
        vm.expectRevert(RobotAttestationRegistry.EnclaveRevoked.selector);
        registry.anchorCheckpoint(
            keccak256("merkle-root"),
            enclaveMeasurement,
            "intel-sgx",
            ""
        );
    }

    function testVerifyCheckpoint() public {
        bytes32 merkleRoot = keccak256("merkle-root");
        bytes32 enclaveMeasurement = keccak256("enclave-measurement");

        vm.prank(gateway);
        bytes32 checkpointId = registry.anchorCheckpoint(
            merkleRoot,
            enclaveMeasurement,
            "intel-sgx",
            ""
        );

        assertTrue(registry.verifyCheckpoint(checkpointId));
    }

    function testVerifyCheckpointReturnsFalseForNonexistent() public {
        bytes32 fakeId = keccak256("fake-checkpoint");
        assertFalse(registry.verifyCheckpoint(fakeId));
    }

    function testVerifyCheckpointReturnsFalseForRevokedEnclave() public {
        bytes32 merkleRoot = keccak256("merkle-root");
        bytes32 enclaveMeasurement = keccak256("enclave-measurement");

        vm.prank(gateway);
        bytes32 checkpointId = registry.anchorCheckpoint(
            merkleRoot,
            enclaveMeasurement,
            "intel-sgx",
            ""
        );

        // Revoke the enclave
        vm.prank(admin);
        registry.emergencyRevokeEnclave(enclaveMeasurement, "Compromised");

        assertFalse(registry.verifyCheckpoint(checkpointId));
    }

    // ============ Emergency Revocation Tests ============

    function testEmergencyRevokeEnclave() public {
        bytes32 enclaveMeasurement = keccak256("enclave-measurement");
        string memory reason = "CVE-2025-12345 detected";

        vm.prank(admin);
        vm.expectEmit(true, true, false, true);
        emit EnclaveRevoked(enclaveMeasurement, admin, reason, block.timestamp);

        registry.emergencyRevokeEnclave(enclaveMeasurement, reason);

        assertTrue(registry.isEnclaveRevoked(enclaveMeasurement));
    }

    function testCannotRevokeEnclaveUnauthorized() public {
        vm.prank(user);
        vm.expectRevert();
        registry.emergencyRevokeEnclave(keccak256("enclave"), "test");
    }

    function testReinstateEnclave() public {
        bytes32 enclaveMeasurement = keccak256("enclave-measurement");

        vm.startPrank(admin);

        registry.emergencyRevokeEnclave(enclaveMeasurement, "Compromised");
        assertTrue(registry.isEnclaveRevoked(enclaveMeasurement));

        registry.reinstateEnclave(enclaveMeasurement);
        assertFalse(registry.isEnclaveRevoked(enclaveMeasurement));

        vm.stopPrank();
    }

    // ============ Access Control Tests ============

    function testAddGateway() public {
        address newGateway = address(0x999);

        vm.prank(admin);
        registry.addGateway(newGateway);

        assertTrue(registry.hasRole(registry.GATEWAY_ROLE(), newGateway));
    }

    function testRemoveGateway() public {
        vm.prank(admin);
        registry.removeGateway(gateway);

        assertFalse(registry.hasRole(registry.GATEWAY_ROLE(), gateway));
    }

    function testCannotAddGatewayUnauthorized() public {
        vm.prank(user);
        vm.expectRevert();
        registry.addGateway(address(0x999));
    }

    // ============ Fuzz Tests ============

    function testFuzzRegisterModel(
        string calldata name,
        bytes32 modelHash,
        bytes32 datasetHash
    ) public {
        vm.assume(modelHash != bytes32(0));
        vm.assume(bytes(name).length > 0 && bytes(name).length < 256);

        vm.prank(user);
        registry.registerModel(name, modelHash, datasetHash, "", "");

        RobotAttestationRegistry.ModelInfo memory info = registry.getModel(modelHash);
        assertEq(info.modelHash, modelHash);
        assertEq(info.datasetHash, datasetHash);
    }

    function testFuzzAnchorCheckpoint(
        bytes32 merkleRoot,
        bytes32 enclaveMeasurement
    ) public {
        vm.assume(merkleRoot != bytes32(0));
        vm.assume(enclaveMeasurement != bytes32(0));

        vm.prank(gateway);
        bytes32 checkpointId = registry.anchorCheckpoint(
            merkleRoot,
            enclaveMeasurement,
            "test-vendor",
            ""
        );

        assertTrue(registry.verifyCheckpoint(checkpointId));
    }
}
