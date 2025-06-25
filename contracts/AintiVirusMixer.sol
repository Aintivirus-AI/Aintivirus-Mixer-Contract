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

interface IVerifier {
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

contract AintiVirusMixer is ReentrancyGuard, AccessControl {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    IVerifier public immutable verifier;
    IERC20Metadata public immutable mixToken;

    address public feeCollector; // Fee collector address for operator gas fee

    uint256 public fee; // ERC20 token fee amount for operator
    uint256 public refund; // ETH fee amount for operator
    uint256 public minETHDepositAmount; // Minimum deposit amount for ETH
    uint256 public minTokenDepositAmount; // Minimum deposit amount for token

    // Commitments
    mapping(bytes32 => bool) public depositCommitments;
    mapping(bytes32 => bool) public withdrawalCommitments;

    // Nullifier mappings
    mapping(bytes32 => bool) public nullifierHashes;

    struct WithdrawalProof {
        uint[2] pA;
        uint[2][2] pB;
        uint[2] pC;
        uint[5] pubSignals;
    }

    constructor(address _token, address _verifier, address _feeCollector) {
        mixToken = IERC20Metadata(_token);

        verifier = IVerifier(_verifier);

        feeCollector = _feeCollector;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);

        fee = 100; // 100 tokens for fee
        refund = 0.001 ether; // 0.001 ether for fee

        minETHDepositAmount = 0.01 ether;
        minTokenDepositAmount = 500 * (10 ** mixToken.decimals());
    }

    /**
     * @dev Deposits funds (ETH or ERC20 tokens) into the contract for mixing,
     *      supporting multiple modes for simple and bridged mixing operations.
     *      Records the commitment to prevent reuse and handles gas refund calculation.
     * @param _mode The mixing mode (1: ETH to ETH, 2: AINTI ERC20 to AINTI ERC20,
     *              3: ETH to SOL, 4: AINTI SPL to AINTI SPL).
     * @param _amount The amount of ETH or tokens to deposit.
     * @param _commitment A unique commitment hash to track the deposit.
     * @notice Requires sufficient balance and valid mode. Updates deposit and
     *         withdrawal commitments, and calculates gas refund for the transaction.
     * @custom:security Prevents reentrancy attacks during execution.
     */
    function deposit(
        uint256 _mode,
        uint256 _amount,
        bytes32 _commitment
    ) public payable nonReentrant {
        require(
            !depositCommitments[_commitment],
            "The commitment has been submitted"
        );

        // Set deposit commitment TRUE
        depositCommitments[_commitment] = true;

        if (_mode == 1 || _mode == 3) {
            /**
                mode 1 is ETH to ETH (simple mix)
                mode 3 is ETH to SOL (bridged mix)
             */
            require(msg.value >= _amount, "Insufficient ETH deposit");
        } else if (_mode == 2 || _mode == 4) {
            /**
                mode 2 is AINTI(ERC20) to AINTI(ERC20) (simple mix)
                mode 4 is AINTI(SPL) to AINTI(SPL) (bridged mix)
             */
            require(
                mixToken.balanceOf(msg.sender) >= _amount,
                "Insufficient ERC20 balance"
            );
            require(
                mixToken.transferFrom(msg.sender, address(this), _amount),
                "ERC20 transfer failed: Token may not approved"
            );
        } else {
            revert("Invalid mixing mode");
        }

        // Register Ethereum => Ethereum mixing commitment
        if (_mode == 1 || _mode == 2) {
            /**
                mode 1 is ETH to ETH (simple mix)
                mode 2 is AINTI(ERC20) to AINTI(ERC20) (simple mix)
             */
            withdrawalCommitments[_commitment] = true;
        }
    }

    /**
     * @dev Registers a commitment for Solana-to-Ethereum bridged mixing, ensuring
     *      the commitment is unique and not previously submitted.
     * @param _commitment A unique commitment hash to track the withdrawal.
     * @notice Only callable by accounts with OPERATOR_ROLE.
     */
    function registerSolToEthCommitment(
        bytes32 _commitment
    ) public onlyRole(OPERATOR_ROLE) {
        require(
            !withdrawalCommitments[_commitment],
            "The commitment has been submitted"
        );

        withdrawalCommitments[_commitment] = true;
    }

    /**
     * @dev Processes a withdrawal of funds (ETH or ERC20 tokens) based on a
     *      zero-knowledge proof, supporting multiple mixing modes. Verifies the proof,
     *      checks nullifier usage, and transfers funds to the recipient while handling fees.
     * @param _proof The withdrawal proof containing public signals and proof components.
     * @param _recipient The address to receive the withdrawn funds.
     * @notice Only callable by accounts with OPERATOR_ROLE. Prevents reentrancy attacks.
     * @custom:non-reentrant Ensures the function cannot be reentered during execution.
     */
    function withdraw(
        WithdrawalProof calldata _proof,
        address _recipient
    ) public onlyRole(OPERATOR_ROLE) nonReentrant {
        // Record gas left before deposit XD
        uint256 gasStart = gasleft();

        bytes32 nullifierHash = bytes32(_proof.pubSignals[0]);
        require(
            nullifierHashes[nullifierHash] == false,
            "Nullifier already used"
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

        nullifierHashes[nullifierHash] = true;

        uint256 amount = _proof.pubSignals[1];
        uint256 mode = _proof.pubSignals[2];

        // Withdrawal process
        if (mode == 1 || mode == 3) {
            /**
                mode 1 is ETH to ETH (simple mix)
                mode 3 is ETH to SOL (bridged mix)
             */
            (bool success, ) = _recipient.call{value: amount - refund}("");
            require(success, "ETH transfer failed");
        } else if (mode == 2 || mode == 4) {
            /**
                mode 2 is AINTI(ERC20) to AINTI(ERC20) (simple mix)
                mode 4 is AINTI(SPL) to AINTI(SPL) (bridged mix)
             */
            uint256 feeAmount = fee * (10 ** mixToken.decimals());
            require(
                mixToken.transfer(_recipient, amount - feeAmount),
                "ERC20 transfer failed: Contract(escrow) balance may insufficient"
            );
        }

        // Fee transfer process (ETH)
        if (refund > 0 && (mode == 1 || mode == 3)) {
            /**
                mode 1 is ETH to ETH (simple mix)
                mode 3 is ETH to SOL (bridged mix)
             */
            (bool success, ) = feeCollector.call{value: refund}("");
            require(success, "ETH transfer failed");
        }

        // Fee transfer process (ERC20)
        if (fee > 0 && (mode == 2 || mode == 4)) {
            /**
                mode 2 is AINTI(ERC20) to AINTI(ERC20) (simple mix)
                mode 4 is AINTI(SPL) to AINTI(SPL) (bridged mix)
             */
            uint256 feeAmount = fee * (10 ** mixToken.decimals());
            require(
                mixToken.transfer(feeCollector, feeAmount),
                "ERC20 transfer failed"
            );
        }

        uint256 gasUsed = gasStart - gasleft();
        refund = gasUsed * tx.gasprice;
    }

    /**
     * @dev Updates the operator address for the contract, ensuring the new operator
     *      is different from the current one.
     * @param _operator The new operator address.
     * @notice Only callable by accounts with OPERATOR_ROLE.
     */
    function setFeeCollector(address _operator) external onlyRole(OPERATOR_ROLE) {
        require(
            feeCollector != _operator,
            "New operator must not be same with current operator"
        );
        feeCollector = _operator;
    }

    function setMinETHDepositValue(uint256 _value) external onlyRole(OPERATOR_ROLE) {
        require(minETHDepositAmount != _value, "Can not set as current value");
        minETHDepositAmount = _value;
    }

    function setMinTokenDepositValue(uint256 _value) external onlyRole(OPERATOR_ROLE) {
        require(minTokenDepositAmount != _value, "Can not set as current value");
        minTokenDepositAmount = _value;
    }

    /**
     * @dev Updates the refund amount for ETH-based withdrawals, ensuring the new
     *      value is different from the current one.
     * @param _refund The new refund amount.
     * @notice Only callable by accounts with OPERATOR_ROLE.
     */
    function setRefund(uint256 _refund) external onlyRole(OPERATOR_ROLE) {
        require(
            refund != _refund,
            "New value must not be same with current value"
        );
        refund = _refund;
    }

    /**
     * @dev Updates the fee amount for ERC20-based withdrawals, ensuring the new
     *      value is different from the current one.
     * @param _fee The new fee amount.
     * @notice Only callable by accounts with OPERATOR_ROLE.
     */
    function setFee(uint256 _fee) external onlyRole(OPERATOR_ROLE) {
        require(fee != _fee, "New value must not be same with current value");
        fee = _fee;
    }

    receive() external payable {}
}
