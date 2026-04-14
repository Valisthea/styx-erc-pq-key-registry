// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {IERCWWWW} from "./interfaces/IERCWWWW.sol";
import {PQAlgorithms} from "./libraries/PQAlgorithms.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title  StyxPQKeyRegistry
/// @author Valisthea (@Valisthea)
/// @notice Reference implementation of the ERC Post-Quantum Key Registry.
///         On-chain lifecycle management of CRYSTALS-Kyber (ML-KEM), CRYSTALS-Dilithium
///         (ML-DSA), and SLH-DSA post-quantum public keys. NIST FIPS 203/204/205.
///
/// @dev    Key lifecycle: REGISTERED → ACTIVE → ROTATED → REVOKED
///         Key IDs are computed deterministically on-chain to prevent front-running.
///         Public keys are stored in full to enable on-chain verification via the
///         optional IERCWWWW_OnChainVerify extension.
contract StyxPQKeyRegistry is IERCWWWW, ERC165, AccessControl, ReentrancyGuard {

    // ─── Roles ────────────────────────────────────────────────────────────────

    bytes32 public constant REGISTRY_ADMIN_ROLE = keccak256("REGISTRY_ADMIN_ROLE");

    // ─── Storage ──────────────────────────────────────────────────────────────

    /// @dev keyId → key metadata
    mapping(bytes32 => PQKeyInfo) internal _keys;

    /// @dev keyId → raw PQ public key bytes (stored in full for on-chain verification)
    mapping(bytes32 => bytes) internal _publicKeys;

    /// @dev owner → ordered list of all keyIds (all states)
    mapping(address => bytes32[]) internal _ownerKeys;

    /// @dev owner → algorithm → KeyPurpose (uint8) → currently active keyId
    mapping(address => mapping(bytes4 => mapping(uint8 => bytes32))) internal _activeKeys;

    /// @dev oldKeyId → newKeyId  (forward rotation pointer)
    mapping(bytes32 => bytes32) internal _rotationTarget;

    /// @dev newKeyId → oldKeyId  (backward pointer, enables rotationChain from any key)
    mapping(bytes32 => bytes32) internal _rotationSource;

    uint256 internal _maxKeysPerOwner;
    uint256 internal _minNistLevel;

    // ─── Constructor ──────────────────────────────────────────────────────────

    /// @param maxKeysPerOwner_ Maximum number of keys (all states) per owner address.
    /// @param minNistLevel_    Minimum NIST security level for accepted keys (1, 2, 3, or 5).
    constructor(uint256 maxKeysPerOwner_, uint256 minNistLevel_) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REGISTRY_ADMIN_ROLE, msg.sender);
        _maxKeysPerOwner = maxKeysPerOwner_;
        _minNistLevel = minNistLevel_;
    }

    // ─── Key Registration ─────────────────────────────────────────────────────

    /// @inheritdoc IERCWWWW
    function registerPQKey(
        address owner,
        bytes4 algorithm,
        KeyPurpose purpose,
        bytes calldata publicKey,
        uint256 validityPeriod
    ) external nonReentrant returns (bytes32 keyId) {
        return _registerKey(owner, algorithm, purpose, publicKey, validityPeriod);
    }

    /// @inheritdoc IERCWWWW
    /// @dev Proof of possession validation is structural at this layer:
    ///      the proof must be non-empty. Full cryptographic verification of
    ///      PQ self-signatures (e.g., ML-DSA signing a canonical registration
    ///      message) requires a PQ precompile or external verifier contract,
    ///      neither of which is yet standardised in the EVM. Protocol
    ///      implementations SHOULD verify the proof off-chain via a dedicated
    ///      PQ verifier before trusting a registered key.
    function registerPQKeyWithProof(
        address owner,
        bytes4 algorithm,
        KeyPurpose purpose,
        bytes calldata publicKey,
        uint256 validityPeriod,
        bytes calldata proofOfPossession
    ) external nonReentrant returns (bytes32 keyId) {
        if (proofOfPossession.length == 0) {
            // keyId not yet computed at this validation stage
            revert InvalidProofOfPossession(bytes32(0));
        }
        return _registerKey(owner, algorithm, purpose, publicKey, validityPeriod);
    }

    function _registerKey(
        address owner,
        bytes4 algorithm,
        KeyPurpose purpose,
        bytes calldata publicKey,
        uint256 validityPeriod
    ) internal returns (bytes32 keyId) {
        // 1. Algorithm must be supported
        if (!PQAlgorithms.isSupported(algorithm)) revert UnsupportedAlgorithm(algorithm);

        // 2. Public key size must match algorithm spec
        uint256 expected = PQAlgorithms.expectedKeySize(algorithm);
        if (publicKey.length != expected) {
            revert InvalidPublicKeyFormat(algorithm, expected, publicKey.length);
        }

        // 3. NIST level must meet minimum
        uint256 level = PQAlgorithms.nistLevel(algorithm);
        if (level < _minNistLevel) revert NistLevelTooLow(level, _minNistLevel);

        // 4. Algorithm-purpose compatibility
        //    KEM algos: ENCAPSULATION or DUAL only
        //    Signature algos: SIGNATURE or DUAL only
        if (PQAlgorithms.isKEM(algorithm) && purpose == KeyPurpose.SIGNATURE) {
            revert AlgorithmPurposeMismatch(algorithm, purpose);
        }
        if (PQAlgorithms.isSignature(algorithm) && purpose == KeyPurpose.ENCAPSULATION) {
            revert AlgorithmPurposeMismatch(algorithm, purpose);
        }

        // 5. Caller must be the key owner
        if (msg.sender != owner) revert UnauthorizedKeyOwner(msg.sender, owner);

        // 6. Owner must not exceed key limit
        if (_ownerKeys[owner].length >= _maxKeysPerOwner) {
            revert MaxKeysReached(owner, _maxKeysPerOwner);
        }

        // 7. Compute keyId deterministically on-chain
        //    Includes chainId and contract address to prevent cross-chain/cross-registry collisions.
        keyId = keccak256(abi.encode(
            block.chainid,
            address(this),
            owner,
            algorithm,
            keccak256(publicKey)
        ));

        // 8. Reject duplicate registration
        if (_keys[keyId].registeredAt != 0) revert KeyAlreadyRegistered(keyId);

        // 9. Store metadata
        _keys[keyId] = PQKeyInfo({
            keyId:        keyId,
            owner:        owner,
            algorithm:    algorithm,
            purpose:      purpose,
            state:        KeyState.REGISTERED,
            registeredAt: block.timestamp,
            activatedAt:  0,
            rotatedAt:    0,
            revokedAt:    0,
            rotatedTo:    bytes32(0),
            nistLevel:    level,
            expiresAt:    validityPeriod > 0 ? block.timestamp + validityPeriod : 0
        });

        // 10. Store public key bytes
        _publicKeys[keyId] = publicKey;

        // 11. Append to owner key list
        _ownerKeys[owner].push(keyId);

        emit PQKeyRegistered(keyId, owner, algorithm, purpose, level);
    }

    // ─── Key Lifecycle ────────────────────────────────────────────────────────

    /// @inheritdoc IERCWWWW
    function activateKey(bytes32 keyId) external nonReentrant {
        PQKeyInfo storage key = _keys[keyId];

        if (key.registeredAt == 0) revert KeyNotFound(keyId);
        if (key.owner != msg.sender) revert UnauthorizedKeyOwner(msg.sender, key.owner);
        if (key.state != KeyState.REGISTERED) revert KeyNotActive(keyId, key.state);

        // Auto-rotate any currently active key for the same (algorithm, purpose, owner)
        bytes32 prevActiveId = _activeKeys[key.owner][key.algorithm][uint8(key.purpose)];
        if (prevActiveId != bytes32(0)) {
            PQKeyInfo storage prevKey = _keys[prevActiveId];
            prevKey.state     = KeyState.ROTATED;
            prevKey.rotatedAt = block.timestamp;
            prevKey.rotatedTo = keyId;
            _rotationTarget[prevActiveId] = keyId;
            _rotationSource[keyId]        = prevActiveId;
            emit PQKeyRotated(prevActiveId, keyId, key.owner);
        }

        key.state       = KeyState.ACTIVE;
        key.activatedAt = block.timestamp;
        _activeKeys[key.owner][key.algorithm][uint8(key.purpose)] = keyId;

        emit PQKeyActivated(keyId, key.owner);
    }

    /// @inheritdoc IERCWWWW
    function rotateKey(bytes32 oldKeyId, bytes32 newKeyId) external nonReentrant {
        PQKeyInfo storage oldKey = _keys[oldKeyId];
        PQKeyInfo storage newKey = _keys[newKeyId];

        if (oldKey.registeredAt == 0) revert KeyNotFound(oldKeyId);
        if (newKey.registeredAt == 0) revert KeyNotFound(newKeyId);
        if (oldKey.owner != msg.sender) revert UnauthorizedKeyOwner(msg.sender, oldKey.owner);
        if (newKey.owner != msg.sender) revert UnauthorizedKeyOwner(msg.sender, newKey.owner);

        if (oldKey.state != KeyState.ACTIVE) revert KeyNotActive(oldKeyId, oldKey.state);
        if (newKey.state != KeyState.REGISTERED) revert RotationTargetNotActive(newKeyId);

        // Algorithm and purpose must match between old and new key
        if (oldKey.algorithm != newKey.algorithm || oldKey.purpose != newKey.purpose) {
            revert AlgorithmPurposeMismatch(newKey.algorithm, newKey.purpose);
        }

        // Retire old key
        oldKey.state     = KeyState.ROTATED;
        oldKey.rotatedAt = block.timestamp;
        oldKey.rotatedTo = newKeyId;
        _rotationTarget[oldKeyId] = newKeyId;
        _rotationSource[newKeyId] = oldKeyId;

        // Activate new key
        newKey.state       = KeyState.ACTIVE;
        newKey.activatedAt = block.timestamp;
        _activeKeys[oldKey.owner][oldKey.algorithm][uint8(oldKey.purpose)] = newKeyId;

        emit PQKeyRotated(oldKeyId, newKeyId, oldKey.owner);
        emit PQKeyActivated(newKeyId, newKey.owner);
    }

    /// @inheritdoc IERCWWWW
    function revokeKey(bytes32 keyId, RevocationReason reason) external nonReentrant {
        PQKeyInfo storage key = _keys[keyId];

        if (key.registeredAt == 0) revert KeyNotFound(keyId);
        if (key.owner != msg.sender) revert UnauthorizedKeyOwner(msg.sender, key.owner);
        if (key.state == KeyState.REVOKED) revert KeyAlreadyRevoked(keyId);

        // Remove from active mapping if it was the current active key
        if (key.state == KeyState.ACTIVE) {
            _activeKeys[key.owner][key.algorithm][uint8(key.purpose)] = bytes32(0);
        }

        key.state     = KeyState.REVOKED;
        key.revokedAt = block.timestamp;

        emit PQKeyRevoked(keyId, key.owner, reason);
    }

    // ─── Key Queries ──────────────────────────────────────────────────────────

    /// @inheritdoc IERCWWWW
    function keyInfo(bytes32 keyId) external view returns (PQKeyInfo memory) {
        if (_keys[keyId].registeredAt == 0) revert KeyNotFound(keyId);
        return _keys[keyId];
    }

    /// @inheritdoc IERCWWWW
    function publicKeyOf(bytes32 keyId) external view returns (bytes memory) {
        if (_keys[keyId].registeredAt == 0) revert KeyNotFound(keyId);
        return _publicKeys[keyId];
    }

    /// @inheritdoc IERCWWWW
    function activeKeyFor(
        address owner,
        bytes4 algorithm,
        KeyPurpose purpose
    ) external view returns (bytes32) {
        return _activeKeys[owner][algorithm][uint8(purpose)];
    }

    /// @inheritdoc IERCWWWW
    function keysOfPaginated(
        address owner,
        uint256 offset,
        uint256 limit
    ) external view returns (bytes32[] memory keys, uint256 total) {
        bytes32[] storage all = _ownerKeys[owner];
        total = all.length;

        if (offset >= total || limit == 0) {
            return (new bytes32[](0), total);
        }

        uint256 end = offset + limit > total ? total : offset + limit;
        uint256 length = end - offset;
        keys = new bytes32[](length);
        for (uint256 i = 0; i < length; i++) {
            keys[i] = all[offset + i];
        }
    }

    /// @inheritdoc IERCWWWW
    function keyCountOf(address owner) external view returns (uint256) {
        return _ownerKeys[owner].length;
    }

    /// @inheritdoc IERCWWWW
    /// @dev Walks backward via _rotationSource to find the chain root, then
    ///      forward via _rotationTarget to build the ordered chain.
    ///      Returns [root, ..., latest] regardless of which key in the chain
    ///      was passed as input.
    function rotationChain(bytes32 keyId) external view returns (bytes32[] memory) {
        if (_keys[keyId].registeredAt == 0) revert KeyNotFound(keyId);

        // Find root by walking backward
        bytes32 root = keyId;
        while (_rotationSource[root] != bytes32(0)) {
            root = _rotationSource[root];
        }

        // Count chain length by walking forward from root
        uint256 length = 0;
        bytes32 cur = root;
        while (cur != bytes32(0)) {
            length++;
            cur = _rotationTarget[cur];
        }

        // Build ordered array
        bytes32[] memory chain = new bytes32[](length);
        cur = root;
        for (uint256 i = 0; i < length; i++) {
            chain[i] = cur;
            cur = _rotationTarget[cur];
        }
        return chain;
    }

    /// @inheritdoc IERCWWWW
    function isKeyUsable(bytes32 keyId) external view returns (bool) {
        PQKeyInfo storage key = _keys[keyId];
        if (key.registeredAt == 0) return false;
        if (key.state != KeyState.ACTIVE) return false;
        if (key.expiresAt != 0 && block.timestamp >= key.expiresAt) return false;
        return true;
    }

    // ─── Configuration ────────────────────────────────────────────────────────

    /// @inheritdoc IERCWWWW
    function minNistLevel() external view returns (uint256) { return _minNistLevel; }

    /// @inheritdoc IERCWWWW
    function maxKeysPerOwner() external view returns (uint256) { return _maxKeysPerOwner; }

    /// @inheritdoc IERCWWWW
    function supportedAlgorithms() external pure returns (bytes4[] memory) {
        return PQAlgorithms.allAlgorithms();
    }

    /// @inheritdoc IERCWWWW
    function isAlgorithmSupported(bytes4 algorithm) external pure returns (bool) {
        return PQAlgorithms.isSupported(algorithm);
    }

    /// @inheritdoc IERCWWWW
    function expectedKeySize(bytes4 algorithm) external pure returns (uint256) {
        return PQAlgorithms.expectedKeySize(algorithm);
    }

    // ─── Admin ────────────────────────────────────────────────────────────────

    /// @notice Update the maximum number of keys per owner address.
    function setMaxKeysPerOwner(uint256 max) external onlyRole(REGISTRY_ADMIN_ROLE) {
        _maxKeysPerOwner = max;
    }

    /// @notice Update the minimum NIST security level for key registration.
    function setMinNistLevel(uint256 level) external onlyRole(REGISTRY_ADMIN_ROLE) {
        _minNistLevel = level;
    }

    // ─── ERC-165 ──────────────────────────────────────────────────────────────

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC165, AccessControl)
        returns (bool)
    {
        return interfaceId == type(IERCWWWW).interfaceId
            || super.supportsInterface(interfaceId);
    }
}
