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

interface IGroth16Verifier {
    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[5] calldata _pubSignals
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

contract AintiVirusMixer is ReentrancyGuard, AccessControl {
    // Role data of the contract operator
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // Groth16Verifier
    IGroth16Verifier public verifier;

    // Mapping from nullifier to boolean to prevent double spends and double withdrawals
    mapping(bytes32 => bool) private nullifierHashes4EthWithdrawal;
    mapping(uint256 => bool) private commitments4EthWithdrawal;

    mapping(bytes32 => bool) private nullifierHashes4SolWithdrawal;
    mapping(uint256 => bool) private commitments4SolWithdrawal;

    constructor(address _verifier) payable {
        verifier = IGroth16Verifier(_verifier);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
    }

    function deposit(
        address _currency,
        uint256 _amount,
        uint256 _commitment
    ) public payable nonReentrant {
        if (msg.value > 0) {
            require(
                _currency == address(0),
                "ERC20 token deposit can not bring ETH"
            );
            _processETHDeposit(_amount);
        } else {
            require(
                IERC20(_currency).balanceOf(msg.sender) >= _amount,
                "Insufficient ERC20 balance for deposit"
            );
            _processERC20Deposit(_currency, _amount);
        }

        commitments4SolWithdrawal[_commitment] = true;
    }

    function withdraw(
        bytes32 _nullifierHash,
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[5] calldata _pubSignals,
        address payable _recipient
    ) public nonReentrant {
        require(_nullifierHash == keccak256(abi.encodePacked(_pubSignals[0])), "Invalid nullifier");
        require(
            !nullifierHashes4EthWithdrawal[_nullifierHash],
            "The note has been already spent"
        );
        require(
            verifier.verifyProof(_pA, _pB, _pC, _pubSignals),
            "Invalid withdraw proof"
        );
        require(commitments4EthWithdrawal[_pubSignals[0]], "Unknown commitment");

        nullifierHashes4EthWithdrawal[_nullifierHash] = true;

        // Withdraw funds to recipient
        if (address(uint160(_pubSignals[3])) == address(0)) {
            _processETHWithdraw(_recipient, _pubSignals[4]);
        } else {
            _processERC20Withdraw(
                _recipient,
                address(uint160(_pubSignals[3])),
                _pubSignals[4]
            );
        }
    }

    function verifySolWithdrawal(
        bytes32 _nullifierHash,
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[5] calldata _pubSignals
    ) public view returns (bool verified_) {
        require(_nullifierHash == keccak256(abi.encodePacked(_pubSignals[0])), "Invalid nullifier");
        require(
            !nullifierHashes4SolWithdrawal[_nullifierHash],
            "The note has been already spent"
        );
        require(commitments4SolWithdrawal[_pubSignals[0]], "Unknown commitment");
        require(
            verifier.verifyProof(_pA, _pB, _pC, _pubSignals),
            "Invalid withdraw proof"
        );
    
        verified_ = true;
    }

    function addCommitment4ETH(uint256 _commitment) public onlyRole(OPERATOR_ROLE) {
        commitments4EthWithdrawal[_commitment] = true;
    }

    function setNullifierHash4ETH(bytes32 _nullifierHash) public onlyRole(OPERATOR_ROLE) {
        nullifierHashes4EthWithdrawal[_nullifierHash] = true;
    }

    function addCommitment4SOL(uint256 _commitment) public onlyRole(OPERATOR_ROLE) {
        commitments4SolWithdrawal[_commitment] = true;
    }

    function setNullifierHash4SOL(bytes32 _nullifierHash) public onlyRole(OPERATOR_ROLE) {
        nullifierHashes4SolWithdrawal[_nullifierHash] = true;
    }

    function _processETHDeposit(uint256 _amount) internal {
        require(
            msg.value >= _amount,
            "ETH deposit must be greater than or equal to the amount specified or can not be deposit ERC20 token with ETH"
        );
    }

    function _processERC20Deposit(address _token, uint256 _amount) internal {
        // Transfer ERC20 tokens from the user to the mixer contract
        require(
            IERC20(_token).transferFrom(msg.sender, address(this), _amount),
            "ERC20 deposit failed"
        );
    }

    function _processETHWithdraw(
        address payable _recipient,
        uint256 _amount
    ) internal {
        uint256 balance = address(this).balance;
        require(balance >= _amount, "Insufficient ETH balance in contract");
        require(
            msg.value == 0,
            "Message value is supposed to be zero for ETH instance"
        );

        (bool success, ) = _recipient.call{value: _amount}(""); // Transfer ETH to recipient
        require(success, "payment to _recipient did not go thru");
    }

    function _processERC20Withdraw(
        address payable _recipient,
        address _token,
        uint256 _amount
    ) internal {
        uint256 balance = IERC20(_token).balanceOf(address(this));
        require(balance >= _amount, "Insufficient ERC20 balance in contract");
        require(
            IERC20(_token).transfer(_recipient, _amount),
            "ERC20 withdraw failed"
        );
    }

    // To accept ETH directly to the contract
    receive() external payable {}
}
