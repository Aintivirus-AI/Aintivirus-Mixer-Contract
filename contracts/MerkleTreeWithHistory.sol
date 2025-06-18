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
    event LeafInsertedETH(
        bytes32 indexed leaf,
        uint32 indexed index,
        bytes32 root
    );
    event LeafInsertedSOL(
        bytes32 indexed leaf,
        uint32 indexed index,
        bytes32 root
    );

    // Initialize both ETH and SOL trees with levels and hasher
    constructor(uint32 _levels, address _hasher) {
        require(_levels > 0 && _levels <= TREE_DEPTH, "Invalid tree depth");
        levels = _levels;
        hasher = IPoseidon(_hasher);

        // Initialize both trees in a single loop
        for (uint32 i = 0; i < levels; i++) {
            bytes32 zeroHash = _zeroHashAt(i);
            filledSubtreesETH[i] = zeroHash;
            filledSubtreesSOL[i] = zeroHash;
        }
        bytes32 initialRoot = _zeroHashAt(levels - 1);
        rootsETH[0] = initialRoot;
        rootsSOL[0] = initialRoot;
    }

    // Hash two inputs using Poseidon
    function hashLeftRight(
        bytes32 _left,
        bytes32 _right
    ) internal view returns (bytes32) {
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
                currentHash = hashLeftRight(
                    currentHash,
                    _zeroHashAt(i)
                );
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
    function _zeroHashAt(uint256 i) internal pure returns (bytes32) {
        if (i == 0)
            return
                bytes32(
                    0x15c32d32cc07c100000000000000000000000000000000000000000000000000
                );
        else if (i == 1)
            return
                bytes32(
                    0x02cdefab88bc3ce0d721b19a5a180e41258881bb879ddd3d3bacc2faef065303
                );
        else if (i == 2)
            return
                bytes32(
                    0x09ecc8e899d18e48573aa975887e2cc1a74d70f3a83f0cbc3bed62ff2db5ab68
                );
        else if (i == 3)
            return
                bytes32(
                    0x088dcd787c5b778ab2203a33fbaedf9bd48f592818d373d9decf44aa94f650fa
                );
        else if (i == 4)
            return
                bytes32(
                    0x2c2d676e2b3be777eb25fc007cd4a135a87dccdd57fdbd4b5c2b7683e14e6efb
                );
        else if (i == 5)
            return
                bytes32(
                    0x2a6c39429285be7df0ff71aa0a29e3e4e99791bab9ef8ed4171c72aceabb162f
                );
        else if (i == 6)
            return
                bytes32(
                    0x09cfbaf896a716178dd70ea00f71dc8d1740b630dfb7f3ded8807bc6e062a1a0
                );
        else if (i == 7)
            return
                bytes32(
                    0x03ce1a8a943b22ceeb5a5a7a69f2aa380acf930485d138499e8f75437d253614
                );
        else if (i == 8)
            return
                bytes32(
                    0x00c4784d9a47d62ad509dde48e0ad73e1aac4de97fc2441ab2e5a622be31a266
                );
        else if (i == 9)
            return
                bytes32(
                    0x2df4ffbdbef4f03630a1725253926db701d2db13d872eb11c0e7a73016511433
                );
        else if (i == 10)
            return
                bytes32(
                    0x295a6b85677ea7c2637c476d2a08ce249b71c5f30e7aae6137716aa6e65a28ce
                );
        else if (i == 11)
            return
                bytes32(
                    0x1ce1c633b37a8417c23c66ab478b7d77adc604e72116a39197454d75ae8a680b
                );
        else if (i == 12)
            return
                bytes32(
                    0x2498cf994b275a102de033b41cc0216e7b82065e0eb9226b09c42c2ab3782160
                );
        else if (i == 13)
            return
                bytes32(
                    0x29131f645acbea83221800f8a9743cfbf24aef5bd46d535b78aa64674696031d
                );
        else if (i == 14)
            return
                bytes32(
                    0x046d6107a34cede497a70650e058da11a5865834a91ab80f0976d05bc9c9c0a5
                );
        else if (i == 15)
            return
                bytes32(
                    0x0a9f3dbb688dd0fbf658d07b07041919d7f7a94fa9451ff647bff9b267393a17
                );
        else if (i == 16)
            return
                bytes32(
                    0x0b2ab9c46d8331a6d3951d315befedcf94a31d72c441f666fcd5f54d26187643
                );
        else if (i == 17)
            return
                bytes32(
                    0x2044ed9a60c280be6f6b3d32bd61d40ec260f2342bab54ef90a17897ea477766
                );
        else if (i == 18)
            return
                bytes32(
                    0x0862916b590f7fc09196bf4a809d2a53b602a8035c125dc399f9d6f6bef89ce1
                );
        else if (i == 19)
            return
                bytes32(
                    0x25f2aa364463854ac4358656a2d1d4cf9ed1809ac4f8c959fcdc35e87636e9be
                );
        else if (i == 20)
            return
                bytes32(
                    0x1a16e5d35f14c230aa4c58f39102d81a391cf6f54f8064e5f64de9ae7f20b63b
                );
        else if (i == 21)
            return
                bytes32(
                    0x0621dc61d4dda40a127469e89a76007e1e2b49ba9ee3b80813ebefd7beb49af5
                );
        else if (i == 22)
            return
                bytes32(
                    0x13d7ccc630ab8867061543531d02265e5d7d394995fab8dcbec3c7c74cf334fe
                );
        else if (i == 23)
            return
                bytes32(
                    0x248a0cc4659bddb1bfb787fce1c4b4ce7f06b95b03a035a4dd6bca43984d9949
                );
        else if (i == 24)
            return
                bytes32(
                    0x2aaeac5fb7e72a4af29968d38de5be17c12f3a7b26f388afafdfc2f18b361495
                );
        else if (i == 25)
            return
                bytes32(
                    0x1b1cae24c5bfb372805e4356e5429f6b20c3064c5e5a720ad6a18a60a2fcaec5
                );
        else if (i == 26)
            return
                bytes32(
                    0x14586158bacb59b15f7855938d1ff5ea3dd1b41970523d4f6065717983d507a6
                );
        else if (i == 27)
            return
                bytes32(
                    0x21dd7e996cd6ddbf1cced7d24532f25c0e44719ba1b1b8f17e1b74a173963341
                );
        else if (i == 28)
            return
                bytes32(
                    0x0cacf78931f9423135f060fbc4d500352feef4d2f0129bc958eb900459f8a575
                );
        else if (i == 29)
            return
                bytes32(
                    0x2b17b6d33c3044cdeec2416656f8092b07d8898c3c88fb18d701d8cc0d5c8544
                );
        else if (i == 30)
            return
                bytes32(
                    0x2c04d2f293064e607707483b04895d0ad3a2eb31a95737fe9973c0b23072e626
                );
        else if (i == 31)
            return
                bytes32(
                    0x172899c330b1f5544d30f7ff85676fb299ff6dbc40c31d8c8fbfaa0285ef7914
                );
        else revert("Index out of bounds");
    }
}
