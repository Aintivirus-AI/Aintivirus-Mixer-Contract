// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Address.sol";

interface IVerifier {
    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[5] calldata _pubSignals
    ) external view returns (bool);
}

contract AintiVirusMixer is ReentrancyGuard, AccessControl {
    using Address for address;
    using Address for address payable;
    using SafeERC20 for IERC20;

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    IVerifier public immutable verifier;
    IERC20Metadata public immutable mixToken;

    address payable public feeCollector; // Fee collector address for operator gas fee

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

    constructor(address _token, address _verifier, address payable _feeCollector) {
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
            require(msg.value >= minETHDepositAmount, "Deposit amount is under than minimum deposit amount");
            require(msg.value >= _amount, "Insufficient ETH deposit");
        } else if (_mode == 2 || _mode == 4) {
            /**
                mode 2 is AINTI(ERC20) to AINTI(ERC20) (simple mix)
                mode 4 is AINTI(SPL) to AINTI(SPL) (bridged mix)
            */
            require(_amount >= minTokenDepositAmount, "Deposit amount is under than minimum deposit amount");
            require(
                mixToken.balanceOf(msg.sender) >= _amount,
                "Insufficient ERC20 balance"
            );
            SafeERC20.safeTransferFrom(mixToken, msg.sender, address(this), _amount);
                
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
        address payable _recipient
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
            _recipient.sendValue(amount - refund);

            // Fee transfer process (ETH)
            if (refund > 0) {
                feeCollector.sendValue(refund);
            }
        } else if (mode == 2 || mode == 4) {
            /**
                mode 2 is AINTI(ERC20) to AINTI(ERC20) (simple mix)
                mode 4 is AINTI(SPL) to AINTI(SPL) (bridged mix)
             */
            uint256 feeAmount = fee * (10 ** mixToken.decimals());
            SafeERC20.safeTransfer(mixToken, _recipient, amount - feeAmount);

            // Fee transfer process (ERC20)
            if (fee > 0) {
                /**
                    mode 2 is AINTI(ERC20) to AINTI(ERC20) (simple mix)
                    mode 4 is AINTI(SPL) to AINTI(SPL) (bridged mix)
                */
                SafeERC20.safeTransfer(mixToken, feeCollector, feeAmount);
            }
        }

        uint256 gasUsed = gasStart - gasleft();
        refund = gasUsed * tx.gasprice;
    }

    /**
     * @dev Updates the operator address for the contract, ensuring the new operator
     *      is different from the current one.
     * @param _feeCollector The new operator address.
     * @notice Only callable by accounts with OPERATOR_ROLE.
     */
    function setFeeCollector(
        address payable _feeCollector
    ) external onlyRole(OPERATOR_ROLE) {
        require(
            feeCollector != _feeCollector,
            "New operator must not be same with current operator"
        );
        feeCollector = _feeCollector;
    }

    function setMinETHDepositValue(
        uint256 _value
    ) external onlyRole(OPERATOR_ROLE) {
        require(minETHDepositAmount != _value, "Can not set as current value");
        minETHDepositAmount = _value;
    }

    function setMinTokenDepositValue(
        uint256 _value
    ) external onlyRole(OPERATOR_ROLE) {
        require(
            minTokenDepositAmount != _value,
            "Can not set as current value"
        );
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
