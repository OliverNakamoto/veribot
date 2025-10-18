// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title Robot Attestation Registry
/// @notice Manages model registry, checkpoint anchoring, and enclave revocation
/// @dev Implements AccessControl for multi-role management
contract RobotAttestationRegistry is AccessControl, ReentrancyGuard {
    // ============ Roles ============

    bytes32 public constant GATEWAY_ROLE = keccak256("GATEWAY_ROLE");
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    // ============ Structs ============

    /// @notice Model provenance information
    struct ModelInfo {
        string name;
        bytes32 modelHash; // SHA-256 of model binary + weights
        bytes32 datasetHash; // SHA-256 of training dataset (optional)
        string containerDigest; // OCI container digest
        bytes signatureBundle; // Sigstore/in-toto signature
        address registeredBy;
        uint256 registeredAt;
        bool active;
    }

    /// @notice Anchored checkpoint
    struct Checkpoint {
        bytes32 merkleRoot; // Merkle root of log entries
        bytes32 enclaveMeasurement; // TEE measurement (MRENCLAVE for SGX)
        address gateway; // Gateway that submitted this checkpoint
        uint256 timestamp; // Block timestamp of anchoring
        string vendor; // Attestation vendor (e.g., "intel-sgx", "aws-nitro")
        bytes gatewaySignature; // Gateway HSM signature
    }

    // ============ State Variables ============

    /// @notice Model registry: modelHash => ModelInfo
    mapping(bytes32 => ModelInfo) public models;

    /// @notice Checkpoint anchors: checkpointId => Checkpoint
    mapping(bytes32 => Checkpoint) public checkpoints;

    /// @notice Revoked enclave measurements
    mapping(bytes32 => bool) public revokedEnclaves;

    /// @notice Revoked model hashes
    mapping(bytes32 => bool) public revokedModels;

    /// @notice Counter for checkpoint IDs
    uint256 public checkpointCounter;

    // ============ Events ============

    event ModelRegistered(
        bytes32 indexed modelHash,
        string name,
        address indexed registeredBy,
        uint256 timestamp
    );

    event ModelRevoked(
        bytes32 indexed modelHash,
        address indexed revokedBy,
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

    event EnclaveReinstated(
        bytes32 indexed enclaveMeasurement,
        address indexed reinstatedBy,
        uint256 timestamp
    );

    // ============ Errors ============

    error ModelAlreadyRegistered();
    error ModelNotFound();
    error ModelRevoked();
    error EnclaveRevoked();
    error InvalidMerkleRoot();
    error InvalidEnclaveMeasurement();
    error Unauthorized();

    // ============ Constructor ============

    constructor(address admin, address[] memory initialGateways) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GOVERNANCE_ROLE, admin);

        for (uint256 i = 0; i < initialGateways.length; i++) {
            _grantRole(GATEWAY_ROLE, initialGateways[i]);
        }
    }

    // ============ Model Registry ============

    /// @notice Register a new model with provenance metadata
    /// @param name Human-readable model name and version
    /// @param modelHash SHA-256 hash of model binary + weights
    /// @param datasetHash SHA-256 hash of training dataset (0x0 if not available)
    /// @param containerDigest OCI container digest (e.g., "sha256:abc...")
    /// @param signatureBundle Sigstore/in-toto signature bundle
    function registerModel(
        string calldata name,
        bytes32 modelHash,
        bytes32 datasetHash,
        string calldata containerDigest,
        bytes calldata signatureBundle
    ) external nonReentrant {
        if (models[modelHash].registeredAt != 0) {
            revert ModelAlreadyRegistered();
        }

        models[modelHash] = ModelInfo({
            name: name,
            modelHash: modelHash,
            datasetHash: datasetHash,
            containerDigest: containerDigest,
            signatureBundle: signatureBundle,
            registeredBy: msg.sender,
            registeredAt: block.timestamp,
            active: true
        });

        emit ModelRegistered(modelHash, name, msg.sender, block.timestamp);
    }

    /// @notice Revoke a model (emergency use only)
    /// @param modelHash SHA-256 hash of the model to revoke
    function revokeModel(bytes32 modelHash) external onlyRole(GOVERNANCE_ROLE) {
        if (models[modelHash].registeredAt == 0) {
            revert ModelNotFound();
        }

        models[modelHash].active = false;
        revokedModels[modelHash] = true;

        emit ModelRevoked(modelHash, msg.sender, block.timestamp);
    }

    // ============ Checkpoint Anchoring ============

    /// @notice Anchor a checkpoint (batch of Merkle roots)
    /// @param merkleRoot Merkle root of checkpoint entries
    /// @param enclaveMeasurement TEE measurement (MRENCLAVE, PCR, etc.)
    /// @param vendor Attestation vendor ("intel-sgx", "aws-nitro", "arm-trustzone")
    /// @param gatewaySignature Gateway HSM signature over (merkleRoot, enclaveMeasurement, timestamp)
    /// @return checkpointId Unique identifier for this checkpoint
    function anchorCheckpoint(
        bytes32 merkleRoot,
        bytes32 enclaveMeasurement,
        string calldata vendor,
        bytes calldata gatewaySignature
    ) external onlyRole(GATEWAY_ROLE) nonReentrant returns (bytes32 checkpointId) {
        if (merkleRoot == bytes32(0)) {
            revert InvalidMerkleRoot();
        }

        if (enclaveMeasurement == bytes32(0)) {
            revert InvalidEnclaveMeasurement();
        }

        if (revokedEnclaves[enclaveMeasurement]) {
            revert EnclaveRevoked();
        }

        checkpointId = keccak256(
            abi.encodePacked(
                merkleRoot,
                enclaveMeasurement,
                msg.sender,
                block.timestamp,
                checkpointCounter++
            )
        );

        checkpoints[checkpointId] = Checkpoint({
            merkleRoot: merkleRoot,
            enclaveMeasurement: enclaveMeasurement,
            gateway: msg.sender,
            timestamp: block.timestamp,
            vendor: vendor,
            gatewaySignature: gatewaySignature
        });

        emit CheckpointAnchored(
            checkpointId,
            merkleRoot,
            enclaveMeasurement,
            msg.sender,
            vendor,
            block.timestamp
        );
    }

    /// @notice Verify a checkpoint exists and is valid
    /// @param checkpointId Checkpoint ID to verify
    /// @return valid True if checkpoint exists and enclave is not revoked
    function verifyCheckpoint(bytes32 checkpointId) external view returns (bool valid) {
        Checkpoint storage cp = checkpoints[checkpointId];
        if (cp.timestamp == 0) {
            return false;
        }

        if (revokedEnclaves[cp.enclaveMeasurement]) {
            return false;
        }

        return true;
    }

    // ============ Emergency Revocation ============

    /// @notice Emergency revoke an enclave measurement (compromised TEE)
    /// @param enclaveMeasurement The measurement to revoke
    /// @param reason Human-readable reason for revocation
    function emergencyRevokeEnclave(
        bytes32 enclaveMeasurement,
        string calldata reason
    ) external onlyRole(GOVERNANCE_ROLE) {
        revokedEnclaves[enclaveMeasurement] = true;

        emit EnclaveRevoked(
            enclaveMeasurement,
            msg.sender,
            reason,
            block.timestamp
        );
    }

    /// @notice Reinstate a previously revoked enclave (after patching)
    /// @param enclaveMeasurement The measurement to reinstate
    function reinstateEnclave(bytes32 enclaveMeasurement) external onlyRole(GOVERNANCE_ROLE) {
        revokedEnclaves[enclaveMeasurement] = false;

        emit EnclaveReinstated(
            enclaveMeasurement,
            msg.sender,
            block.timestamp
        );
    }

    // ============ View Functions ============

    /// @notice Get model information
    /// @param modelHash SHA-256 hash of the model
    /// @return info Model information struct
    function getModel(bytes32 modelHash) external view returns (ModelInfo memory info) {
        return models[modelHash];
    }

    /// @notice Get checkpoint information
    /// @param checkpointId Checkpoint ID
    /// @return cp Checkpoint struct
    function getCheckpoint(bytes32 checkpointId) external view returns (Checkpoint memory cp) {
        return checkpoints[checkpointId];
    }

    /// @notice Check if an enclave measurement is revoked
    /// @param enclaveMeasurement The measurement to check
    /// @return revoked True if revoked
    function isEnclaveRevoked(bytes32 enclaveMeasurement) external view returns (bool revoked) {
        return revokedEnclaves[enclaveMeasurement];
    }

    /// @notice Check if a model is revoked
    /// @param modelHash The model hash to check
    /// @return revoked True if revoked
    function isModelRevoked(bytes32 modelHash) external view returns (bool revoked) {
        return revokedModels[modelHash];
    }

    // ============ Admin Functions ============

    /// @notice Grant gateway role to an address
    /// @param gateway Gateway address
    function addGateway(address gateway) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(GATEWAY_ROLE, gateway);
    }

    /// @notice Revoke gateway role from an address
    /// @param gateway Gateway address
    function removeGateway(address gateway) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(GATEWAY_ROLE, gateway);
    }
}
