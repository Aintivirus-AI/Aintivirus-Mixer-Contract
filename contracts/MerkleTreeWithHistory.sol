// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0;

interface IPoseidon {
    function poseidon(
        uint256[2] calldata inputs
    ) external pure returns (uint256);
}

/// @title MerkleTreeWithHistory using dynamic Poseidon-based zero values
contract MerkleTreeWithHistory {
    // BN254 field size for input validation
    uint256 public constant FIELD_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Zero value for empty leaves (keccak256("aintivirus") % FIELD_SIZE)
    uint256 public constant ZERO_VALUE =
        9843416945950214527845121167110536396734923501368431511777016063417998984121;
    // Maximum tree depth
    uint32 public constant TREE_DEPTH = 31;
    // Size of root history for each tree
    uint32 public constant ROOT_HISTORY_SIZE = 30;

    // Poseidon hasher contract
    IPoseidon public immutable hasher;
    // Number of tree levels (max 31)
    uint32 public immutable levels;

    // ETH Merkle tree storage
    mapping(uint32 => bytes32) public filledSubtreesETH;
    mapping(uint32 => bytes32) public rootsETH;
    uint32 public currentRootIndexETH;
    uint32 public nextIndexETH;

    // SOL Merkle tree storage
    mapping(uint32 => bytes32) public filledSubtreesSOL;
    mapping(uint32 => bytes32) public rootsSOL;
    uint32 public currentRootIndexSOL;
    uint32 public nextIndexSOL;

    // Events for off-chain monitoring
    event LeafInsertedETH(bytes32 indexed leaf, uint32 indexed index, bytes32 root);
    event LeafInsertedSOL(bytes32 indexed leaf, uint32 indexed index, bytes32 root);

    // Initialize both ETH and SOL trees with levels and hasher
    constructor(uint32 _levels, address _hasher) {
        require(_levels > 0 && _levels <= TREE_DEPTH, "Invalid tree depth");
        levels = _levels;
        hasher = IPoseidon(_hasher);

        // Initialize both trees in a single loop
        for (uint32 i = 0; i < levels; i++) {
            bytes32 zeroHash = bytes32(_zeroHashAt(i));
            filledSubtreesETH[i] = zeroHash;
            filledSubtreesSOL[i] = zeroHash;
        }
        bytes32 initialRoot = bytes32(_zeroHashAt(levels - 1));
        rootsETH[0] = initialRoot;
        rootsSOL[0] = initialRoot;
    }

    // Hash two inputs using Poseidon
    function hashLeftRight(bytes32 _left, bytes32 _right) internal view returns (bytes32) {
        uint256 left = uint256(_left);
        uint256 right = uint256(_right);
        require(left < FIELD_SIZE && right < FIELD_SIZE, "Input out of field");

        return bytes32(hasher.poseidon([left, right]));
    }

    // Insert a new leaf into the ETH Merkle tree and return its index
    function insertETH(bytes32 _leaf) internal returns (uint32) {
        (uint32 index, bytes32 root) = _insertLeaf(
            _leaf,
            nextIndexETH,
            filledSubtreesETH
        );
        currentRootIndexETH = (currentRootIndexETH + 1) % ROOT_HISTORY_SIZE;
        rootsETH[currentRootIndexETH] = root;
        nextIndexETH++;
        emit LeafInsertedETH(_leaf, index, root);
        return index;
    }

    // Insert a new leaf into the SOL Merkle tree and return its index
    function insertSOL(bytes32 _leaf) internal returns (uint32) {
        (uint32 index, bytes32 root) = _insertLeaf(
            _leaf,
            nextIndexSOL,
            filledSubtreesSOL
        );
        currentRootIndexSOL = (currentRootIndexSOL + 1) % ROOT_HISTORY_SIZE;
        rootsSOL[currentRootIndexSOL] = root;
        nextIndexSOL++;
        emit LeafInsertedSOL(_leaf, index, root);
        return index;
    }

    // Insert a leaf into a Merkle tree and compute the new root
    function _insertLeaf(
        bytes32 _leaf,
        uint32 _nextIndex,
        mapping(uint32 => bytes32) storage subtrees
    ) private returns (uint32, bytes32) {
        require(_nextIndex < (1 << levels), "Merkle tree is full");

        uint32 currentIndex = _nextIndex;
        bytes32 currentHash = _leaf;

        for (uint32 i = 0; i < levels; i++) {
            if (currentIndex % 2 == 0) {
                // Insert as left child, pair with zero hash
                subtrees[i] = currentHash;
                currentHash = hashLeftRight(currentHash, bytes32(_zeroHashAt(i)));
            } else {
                // Insert as right child, pair with stored left child
                currentHash = hashLeftRight(subtrees[i], currentHash);
            }
            currentIndex /= 2;
        }
        return (_nextIndex, currentHash);
    }

    // Check if a root is in the ETH root history
    function isKnownETHRoot(bytes32 _root) public view returns (bool) {
        return _isKnownRoot(_root, rootsETH, currentRootIndexETH);
    }

    // Check if a root is in the SOL root history
    function isKnownSOLRoot(bytes32 _root) public view returns (bool) {
        return _isKnownRoot(_root, rootsSOL, currentRootIndexSOL);
    }

    // Check if a root exists in a root history
    function _isKnownRoot(
        bytes32 _root,
        mapping(uint32 => bytes32) storage roots,
        uint32 currentIndex
    ) private view returns (bool) {
        if (_root == bytes32(0)) return false;

        uint32 idx = currentIndex;
        for (uint256 i = 0; i < ROOT_HISTORY_SIZE; i++) {
            if (roots[idx] == _root) return true;
            idx = idx == 0 ? ROOT_HISTORY_SIZE - 1 : idx - 1;
        }
        return false;
    }

    // Get the most recent ETH root
    function getLastETHRoot() external view returns (bytes32) {
        return rootsETH[currentRootIndexETH];
    }

    // Get the most recent SOL root
    function getLastSOLRoot() external view returns (bytes32) {
        return rootsSOL[currentRootIndexSOL];
    }

    // Compute zero hash for a given level dynamically
    function _zeroHashAt(uint256 index) internal view returns (uint256) {
        require(index < TREE_DEPTH, "Index out of range");
        uint256 current = ZERO_VALUE;
        for (uint256 i = 0; i < index; i++) {
            current = hasher.poseidon([current, current]);
        }
        return current;
    }
}