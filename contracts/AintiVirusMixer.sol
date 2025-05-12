// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }
}

interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[ERC section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

abstract contract ERC165 is IERC165 {
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}

interface IAccessControl {
    /**
     * @dev The `account` is missing a role.
     */
    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);

    /**
     * @dev The caller of a function is not the expected one.
     *
     * NOTE: Don't confuse with {AccessControlUnauthorizedAccount}.
     */
    error AccessControlBadConfirmation();

    /**
     * @dev Emitted when `newAdminRole` is set as ``role``'s admin role, replacing `previousAdminRole`
     *
     * `DEFAULT_ADMIN_ROLE` is the starting admin for all roles, despite
     * {RoleAdminChanged} not being emitted to signal this.
     */
    event RoleAdminChanged(
        bytes32 indexed role,
        bytes32 indexed previousAdminRole,
        bytes32 indexed newAdminRole
    );

    /**
     * @dev Emitted when `account` is granted `role`.
     *
     * `sender` is the account that originated the contract call. This account bears the admin role (for the granted role).
     * Expected in cases where the role was granted using the internal {AccessControl-_grantRole}.
     */
    event RoleGranted(
        bytes32 indexed role,
        address indexed account,
        address indexed sender
    );

    /**
     * @dev Emitted when `account` is revoked `role`.
     *
     * `sender` is the account that originated the contract call:
     *   - if using `revokeRole`, it is the admin role bearer
     *   - if using `renounceRole`, it is the role bearer (i.e. `account`)
     */
    event RoleRevoked(
        bytes32 indexed role,
        address indexed account,
        address indexed sender
    );

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(
        bytes32 role,
        address account
    ) external view returns (bool);

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {AccessControl-_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) external view returns (bytes32);

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function grantRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function revokeRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been granted `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `callerConfirmation`.
     */
    function renounceRole(bytes32 role, address callerConfirmation) external;
}

abstract contract AccessControl is Context, IAccessControl, ERC165 {
    struct RoleData {
        mapping(address account => bool) hasRole;
        bytes32 adminRole;
    }

    mapping(bytes32 role => RoleData) private _roles;

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    /**
     * @dev Modifier that checks that an account has a specific role. Reverts
     * with an {AccessControlUnauthorizedAccount} error including the required role.
     */
    modifier onlyRole(bytes32 role) {
        _checkRole(role);
        _;
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override returns (bool) {
        return
            interfaceId == type(IAccessControl).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(
        bytes32 role,
        address account
    ) public view virtual returns (bool) {
        return _roles[role].hasRole[account];
    }

    /**
     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `_msgSender()`
     * is missing `role`. Overriding this function changes the behavior of the {onlyRole} modifier.
     */
    function _checkRole(bytes32 role) internal view virtual {
        _checkRole(role, _msgSender());
    }

    /**
     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `account`
     * is missing `role`.
     */
    function _checkRole(bytes32 role, address account) internal view virtual {
        if (!hasRole(role, account)) {
            revert AccessControlUnauthorizedAccount(account, role);
        }
    }

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) public view virtual returns (bytes32) {
        return _roles[role].adminRole;
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleGranted} event.
     */
    function grantRole(
        bytes32 role,
        address account
    ) public virtual onlyRole(getRoleAdmin(role)) {
        _grantRole(role, account);
    }

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleRevoked} event.
     */
    function revokeRole(
        bytes32 role,
        address account
    ) public virtual onlyRole(getRoleAdmin(role)) {
        _revokeRole(role, account);
    }

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been revoked `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `callerConfirmation`.
     *
     * May emit a {RoleRevoked} event.
     */
    function renounceRole(
        bytes32 role,
        address callerConfirmation
    ) public virtual {
        if (callerConfirmation != _msgSender()) {
            revert AccessControlBadConfirmation();
        }

        _revokeRole(role, callerConfirmation);
    }

    /**
     * @dev Sets `adminRole` as ``role``'s admin role.
     *
     * Emits a {RoleAdminChanged} event.
     */
    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual {
        bytes32 previousAdminRole = getRoleAdmin(role);
        _roles[role].adminRole = adminRole;
        emit RoleAdminChanged(role, previousAdminRole, adminRole);
    }

    /**
     * @dev Attempts to grant `role` to `account` and returns a boolean indicating if `role` was granted.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleGranted} event.
     */
    function _grantRole(
        bytes32 role,
        address account
    ) internal virtual returns (bool) {
        if (!hasRole(role, account)) {
            _roles[role].hasRole[account] = true;
            emit RoleGranted(role, account, _msgSender());
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Attempts to revoke `role` from `account` and returns a boolean indicating if `role` was revoked.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleRevoked} event.
     */
    function _revokeRole(
        bytes32 role,
        address account
    ) internal virtual returns (bool) {
        if (hasRole(role, account)) {
            _roles[role].hasRole[account] = false;
            emit RoleRevoked(role, account, _msgSender());
            return true;
        } else {
            return false;
        }
    }
}

interface IDepositVerifier {
    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[5] calldata _pubSignals
    ) external view returns (bool);
}

interface IWithdrawalVrifier {
    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[10] calldata _pubSignals
    ) external view returns (bool);
}

interface IERC20 {
    function transfer(
        address recipient,
        uint256 amount
    ) external returns (bool);
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IERC20Metadata is IERC20 {
    /**
     * @dev Returns the name of the token.
     */
    function name() external view returns (string memory);

    /**
     * @dev Returns the symbol of the token.
     */
    function symbol() external view returns (string memory);

    /**
     * @dev Returns the decimals places of the token.
     */
    function decimals() external view returns (uint8);
}

abstract contract ReentrancyGuard {
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
}

interface IPoseidon {
    function poseidon(uint[2] memory) external pure returns (uint256);
}

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
            bytes32 zeroHash = bytes32(_zeroHashAt(i));
            filledSubtreesETH[i] = zeroHash;
            filledSubtreesSOL[i] = zeroHash;
        }
        bytes32 initialRoot = bytes32(_zeroHashAt(levels - 1));
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
                    bytes32(_zeroHashAt(i))
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
    function _zeroHashAt(uint256 index) internal view returns (uint256) {
        require(index < TREE_DEPTH, "Index out of range");
        uint256 current = ZERO_VALUE;
        for (uint256 i = 0; i < index; i++) {
            current = hasher.poseidon([current, current]);
        }
        return current;
    }
}

contract AintiVirusMixer is
    ReentrancyGuard,
    AccessControl,
    MerkleTreeWithHistory
{
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    IWithdrawalVrifier public verifier;
    IDepositVerifier public depositVerifier;

    address public relayer;

    uint256 public fee; // ERC20 token fee amount for relayer
    uint256 public refund; // ETH fee amount for relayer

    // Ethereum Commitment
    mapping(bytes32 => bool) public ethKnownCommitments;

    // Solana Commitment
    mapping(bytes32 => bool) public solKnownCommitments;

    enum EthNullifierStatus {
        UNINITIATED,
        CONFIRMED
    }

    enum SolNullifierStatus {
        UNINITIATED,
        VERIFYING,
        COMFIRMED
    }
    // Nullifier mappings
    mapping(bytes32 => EthNullifierStatus) public ethUsedNullifiers;
    mapping(bytes32 => SolNullifierStatus) public solUsedNullifiers;

    struct DepositProof {
        uint[2] pA;
        uint[2][2] pB;
        uint[2] pC;
        uint[5] pubSignals;
    }

    struct WithdrawalProof {
        uint[2] pA;
        uint[2][2] pB;
        uint[2] pC;
        uint[10] pubSignals;
    }

    event DepositForSolWithdrawal(
        bytes32 indexed commitment,
        uint32 leafIndex,
        uint256 timestamp
    );
    event CommitmentAddedForEthWithdrawal(
        bytes32 indexed commitment,
        uint32 leafIndex,
        uint256 timestamp
    );

    constructor(
        address _depositVerifier,
        address _verifier,
        address _hasher,
        address _relayer
    ) MerkleTreeWithHistory(20, _hasher) {
        verifier = IWithdrawalVrifier(_verifier);
        depositVerifier = IDepositVerifier(_depositVerifier);

        relayer = _relayer;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);

        fee = 100; // 100 tokens for fee
        refund = 0.001 ether; // 0.001 ether for fee
    }

    function deposit(
        address _currency,
        uint256 _amount,
        bytes32 _commitment,
        DepositProof calldata _proof
    ) public payable nonReentrant {
        require(
            !solKnownCommitments[_commitment],
            "The commitment has been submitted"
        );

        require(
            depositVerifier.verifyProof(
                _proof.pA,
                _proof.pB,
                _proof.pC,
                _proof.pubSignals
            ),
            "Invalid deposit proof"
        );

        require(
            address(uint160(_proof.pubSignals[3])) == _currency,
            "Invalid deposit currency"
        );

        require(_proof.pubSignals[4] == _amount, "Invalid deposit amount");

        uint256 gasStart = gasleft();

        uint32 insertedIndex = insertSOL(_commitment);
        solKnownCommitments[_commitment] = true;

        if (msg.value > 0) {
            require(
                _currency == address(0),
                "ERC20 deposit cannot include ETH"
            );
            require(msg.value >= _amount, "Insufficient ETH deposit");
        } else {
            require(
                IERC20(_currency).balanceOf(msg.sender) >= _amount,
                "Insufficient ERC20 balance"
            );
            require(
                IERC20(_currency).transferFrom(
                    msg.sender,
                    address(this),
                    _amount
                ),
                "ERC20 transfer failed"
            );
        }

        uint256 gasUsed = gasStart - gasleft();
        refund = gasUsed * tx.gasprice;

        emit DepositForSolWithdrawal(
            _commitment,
            insertedIndex,
            block.timestamp
        );
    }

    function addCommitmentForEthWithdrawal(
        bytes32 _commitment
    ) public onlyRole(OPERATOR_ROLE) {
        require(
            !ethKnownCommitments[_commitment],
            "The commitment has been submitted"
        );

        uint32 insertedIndex = insertETH(_commitment);
        ethKnownCommitments[_commitment] = true;

        emit CommitmentAddedForEthWithdrawal(
            _commitment,
            insertedIndex,
            block.timestamp
        );
    }

    function withdraw(
        bytes32 _root,
        WithdrawalProof calldata _proof,
        address _recipient
    ) public onlyRole(OPERATOR_ROLE) nonReentrant {
        require(isKnownETHRoot(_root), "Unknown merkle root for Ethereum");
        require(
            _root == bytes32(_proof.pubSignals[1]),
            "Merkle root is not matched"
        );

        bytes32 nullifierHash = bytes32(_proof.pubSignals[0]);
        require(
            ethUsedNullifiers[nullifierHash] == EthNullifierStatus.UNINITIATED,
            "Nullifier already used for Ethereum"
        );

        require(
            verifier.verifyProof(
                _proof.pA,
                _proof.pB,
                _proof.pC,
                _proof.pubSignals
            ),
            "Invalid withdraw proof"
        );

        require(
            _recipient == address(uint160(_proof.pubSignals[4])),
            "Invalid recipient address"
        );

        ethUsedNullifiers[nullifierHash] = EthNullifierStatus.CONFIRMED;

        address currency = address(uint160(_proof.pubSignals[2]));
        uint256 amount = _proof.pubSignals[3];

        // Withdrawal process
        if (currency == address(0)) {
            (bool success, ) = _recipient.call{value: amount - refund}("");
            require(success, "ETH transfer failed");
        } else {
            uint256 feeAmount = fee * (10 ** IERC20Metadata(currency).decimals());
            require(
                IERC20(currency).transfer(_recipient, amount - feeAmount),
                "ERC20 transfer failed"
            );
        }

        // Fee transfer process (ETH)
        if (refund > 0 && currency == address(0)) {
            (bool success, ) = relayer.call{value: refund}("");
            require(success, "ETH transfer failed");
        }

        // Fee transfer process (ERC20)
        if (fee > 0 && currency != address(0)) {
            uint256 feeAmount = fee * (10 ** IERC20Metadata(currency).decimals());
            require(
                IERC20(currency).transfer(relayer, feeAmount),
                "ERC20 transfer failed"
            );
        }
    }

    function verifySolWithdrawal(
        bytes32 _root,
        WithdrawalProof calldata _proof
    ) public onlyRole(OPERATOR_ROLE) returns (bool verified_) {
        require(isKnownSOLRoot(_root), "Unknown root for Solana");
        require(
            _root == bytes32(_proof.pubSignals[1]),
            "Merkle root is not matched"
        );

        bytes32 nullifierHash = bytes32(_proof.pubSignals[0]);

        require(
            verifier.verifyProof(
                _proof.pA,
                _proof.pB,
                _proof.pC,
                _proof.pubSignals
            ),
            "Invalid withdraw proof"
        );
        require(
            solUsedNullifiers[nullifierHash] != SolNullifierStatus.COMFIRMED,
            "Nullifier is already spent"
        );
        require(
            solUsedNullifiers[nullifierHash] != SolNullifierStatus.VERIFYING,
            "Nullifier is under verification"
        );

        solUsedNullifiers[nullifierHash] = SolNullifierStatus.VERIFYING;

        verified_ = true;
    }

    function setNullifierForSolWithdrawal(
        bytes32 _nullifierHash
    ) public onlyRole(OPERATOR_ROLE) {
        solUsedNullifiers[_nullifierHash] = SolNullifierStatus.COMFIRMED;
    }

    function revertNullifierForSolWithdrawal(
        bytes32 _nullifierHash
    ) public onlyRole(OPERATOR_ROLE) {
        require(
            solUsedNullifiers[_nullifierHash] == SolNullifierStatus.VERIFYING,
            "Nullifier is uninitiated or confirmed"
        );
        solUsedNullifiers[_nullifierHash] = SolNullifierStatus.UNINITIATED;
    }

    function setRelayer(address _relayer) external onlyRole(OPERATOR_ROLE) {
        require(relayer != _relayer, "New relayer must not be same with current relayer");
        relayer = _relayer;
    }

    function setRefund(uint256 _refund) external onlyRole(OPERATOR_ROLE) {
        require(refund != _refund, "New value must not be same with current value");
        refund = _refund;
    }

    function setFee(uint256 _fee) external onlyRole(OPERATOR_ROLE) {
        require(fee != _fee, "New value must not be same with current value");
        fee = _fee;
    }

    receive() external payable {}
}
