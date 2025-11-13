// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title FiatGateway
 * @notice Fiat on/off ramp with KYC integration
 * @dev Integrates with Circle, MoonPay, and institutional banking partners
 */
contract FiatGateway is ReentrancyGuard, AccessControl {

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant KYC_PROVIDER_ROLE = keccak256("KYC_PROVIDER_ROLE");

    struct FiatDeposit {
        address user;
        uint256 amount;
        string currency; // USD, EUR, etc.
        address stablecoin; // USDC, EURC, etc.
        uint256 timestamp;
        string externalId; // Bank transaction ID
        DepositStatus status;
    }

    struct Withdrawal {
        address user;
        uint256 amount;
        address stablecoin;
        string bankAccount; // Encrypted bank details
        string currency;
        uint256 timestamp;
        WithdrawalStatus status;
        string externalId;
    }

    struct KYCRecord {
        address user;
        KYCLevel level;
        uint256 verifiedAt;
        uint256 expiresAt;
        bytes32 documentsHash;
        address verifier;
    }

    enum DepositStatus { PENDING, CONFIRMED, COMPLETED, FAILED }
    enum WithdrawalStatus { PENDING, PROCESSING, COMPLETED, FAILED, CANCELLED }
    enum KYCLevel { NONE, BASIC, INTERMEDIATE, ADVANCED }

    // State
    mapping(bytes32 => FiatDeposit) public deposits;
    mapping(bytes32 => Withdrawal) public withdrawals;
    mapping(address => KYCRecord) public kycRecords;
    mapping(address => bool) public supportedStablecoins;

    // Limits
    mapping(KYCLevel => uint256) public dailyDepositLimits;
    mapping(KYCLevel => uint256) public dailyWithdrawalLimits;
    mapping(address => mapping(uint256 => uint256)) public dailyVolume; // user => day => volume

    // Supported stablecoins
    address public USDC;
    address public EURC;
    address public PYUSD; // PayPal USD

    // Events
    event DepositInitiated(bytes32 indexed depositId, address indexed user, uint256 amount, string currency);
    event DepositCompleted(bytes32 indexed depositId, uint256 stablecoinAmount);
    event WithdrawalRequested(bytes32 indexed withdrawalId, address indexed user, uint256 amount);
    event WithdrawalCompleted(bytes32 indexed withdrawalId, string externalId);
    event KYCVerified(address indexed user, KYCLevel level, uint256 expiresAt);
    event StablecoinAdded(address indexed token, string symbol);

    constructor(
        address _usdc,
        address _eurc,
        address _pyusd
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);

        USDC = _usdc;
        EURC = _eurc;
        PYUSD = _pyusd;

        supportedStablecoins[_usdc] = true;
        supportedStablecoins[_eurc] = true;
        supportedStablecoins[_pyusd] = true;

        // Set default limits (in USD cents)
        dailyDepositLimits[KYCLevel.BASIC] = 1000_00; // $1,000
        dailyDepositLimits[KYCLevel.INTERMEDIATE] = 10000_00; // $10,000
        dailyDepositLimits[KYCLevel.ADVANCED] = 100000_00; // $100,000

        dailyWithdrawalLimits[KYCLevel.BASIC] = 1000_00;
        dailyWithdrawalLimits[KYCLevel.INTERMEDIATE] = 10000_00;
        dailyWithdrawalLimits[KYCLevel.ADVANCED] = 100000_00;
    }

    /**
     * @notice Initiate fiat deposit (called by operator after bank transfer confirmed)
     */
    function initiateDeposit(
        address user,
        uint256 amount,
        string calldata currency,
        string calldata externalId
    ) external onlyRole(OPERATOR_ROLE) returns (bytes32 depositId) {
        require(hasValidKYC(user), "KYC required");
        require(amount > 0, "Invalid amount");

        depositId = keccak256(abi.encodePacked(
            user,
            amount,
            currency,
            externalId,
            block.timestamp
        ));

        address stablecoin = _getStablecoinForCurrency(currency);

        deposits[depositId] = FiatDeposit({
            user: user,
            amount: amount,
            currency: currency,
            stablecoin: stablecoin,
            timestamp: block.timestamp,
            externalId: externalId,
            status: DepositStatus.PENDING
        });

        emit DepositInitiated(depositId, user, amount, currency);

        return depositId;
    }

    /**
     * @notice Complete deposit by minting/transferring stablecoins
     */
    function completeDeposit(
        bytes32 depositId,
        uint256 stablecoinAmount
    ) external onlyRole(OPERATOR_ROLE) nonReentrant {
        FiatDeposit storage deposit = deposits[depositId];
        require(deposit.status == DepositStatus.PENDING, "Invalid status");

        // Check daily limits
        require(
            _checkDailyLimit(deposit.user, stablecoinAmount, true),
            "Daily limit exceeded"
        );

        // Transfer stablecoins to user
        IERC20(deposit.stablecoin).transfer(deposit.user, stablecoinAmount);

        deposit.status = DepositStatus.COMPLETED;

        emit DepositCompleted(depositId, stablecoinAmount);
    }

    /**
     * @notice Request withdrawal to fiat
     */
    function requestWithdrawal(
        uint256 amount,
        address stablecoin,
        string calldata bankAccount,
        string calldata currency
    ) external nonReentrant returns (bytes32 withdrawalId) {
        require(hasValidKYC(msg.sender), "KYC required");
        require(supportedStablecoins[stablecoin], "Unsupported stablecoin");
        require(amount > 0, "Invalid amount");

        // Check daily limits
        require(
            _checkDailyLimit(msg.sender, amount, false),
            "Daily limit exceeded"
        );

        withdrawalId = keccak256(abi.encodePacked(
            msg.sender,
            amount,
            stablecoin,
            bankAccount,
            block.timestamp
        ));

        // Transfer stablecoins to gateway
        IERC20(stablecoin).transferFrom(msg.sender, address(this), amount);

        withdrawals[withdrawalId] = Withdrawal({
            user: msg.sender,
            amount: amount,
            stablecoin: stablecoin,
            bankAccount: bankAccount,
            currency: currency,
            timestamp: block.timestamp,
            status: WithdrawalStatus.PENDING,
            externalId: ""
        });

        emit WithdrawalRequested(withdrawalId, msg.sender, amount);

        return withdrawalId;
    }

    /**
     * @notice Complete withdrawal (called after bank transfer executed)
     */
    function completeWithdrawal(
        bytes32 withdrawalId,
        string calldata externalId
    ) external onlyRole(OPERATOR_ROLE) {
        Withdrawal storage withdrawal = withdrawals[withdrawalId];
        require(
            withdrawal.status == WithdrawalStatus.PENDING ||
            withdrawal.status == WithdrawalStatus.PROCESSING,
            "Invalid status"
        );

        withdrawal.status = WithdrawalStatus.COMPLETED;
        withdrawal.externalId = externalId;

        emit WithdrawalCompleted(withdrawalId, externalId);
    }

    /**
     * @notice Verify user KYC
     */
    function verifyKYC(
        address user,
        KYCLevel level,
        uint256 validityDays,
        bytes32 documentsHash
    ) external onlyRole(KYC_PROVIDER_ROLE) {
        uint256 expiresAt = block.timestamp + (validityDays * 1 days);

        kycRecords[user] = KYCRecord({
            user: user,
            level: level,
            verifiedAt: block.timestamp,
            expiresAt: expiresAt,
            documentsHash: documentsHash,
            verifier: msg.sender
        });

        emit KYCVerified(user, level, expiresAt);
    }

    /**
     * @notice Check if user has valid KYC
     */
    function hasValidKYC(address user) public view returns (bool) {
        KYCRecord memory record = kycRecords[user];
        return record.level != KYCLevel.NONE &&
               record.expiresAt > block.timestamp;
    }

    /**
     * @notice Get user's KYC level
     */
    function getKYCLevel(address user) external view returns (KYCLevel) {
        if (!hasValidKYC(user)) {
            return KYCLevel.NONE;
        }
        return kycRecords[user].level;
    }

    // Internal functions

    function _getStablecoinForCurrency(string memory currency) internal view returns (address) {
        bytes32 currencyHash = keccak256(bytes(currency));

        if (currencyHash == keccak256(bytes("USD"))) {
            return USDC;
        } else if (currencyHash == keccak256(bytes("EUR"))) {
            return EURC;
        }

        revert("Unsupported currency");
    }

    function _checkDailyLimit(
        address user,
        uint256 amount,
        bool isDeposit
    ) internal returns (bool) {
        KYCLevel level = kycRecords[user].level;
        uint256 limit = isDeposit
            ? dailyDepositLimits[level]
            : dailyWithdrawalLimits[level];

        uint256 today = block.timestamp / 1 days;
        uint256 currentVolume = dailyVolume[user][today];

        if (currentVolume + amount > limit) {
            return false;
        }

        dailyVolume[user][today] = currentVolume + amount;
        return true;
    }

    // Admin functions

    function addStablecoin(address token) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedStablecoins[token] = true;
        emit StablecoinAdded(token, "TOKEN");
    }

    function setDailyLimit(
        KYCLevel level,
        uint256 depositLimit,
        uint256 withdrawalLimit
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        dailyDepositLimits[level] = depositLimit;
        dailyWithdrawalLimits[level] = withdrawalLimit;
    }

    function emergencyWithdraw(
        address token,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        IERC20(token).transfer(msg.sender, amount);
    }
}
