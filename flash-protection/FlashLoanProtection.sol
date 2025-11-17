// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * FLASH LOAN PROTECTION SYSTEM
 *
 * HYPOTHESIS: A multi-layered flash loan protection system with transaction
 * origin verification, time-weighted operations, and economic safeguards
 * will prevent 100% of flash loan attacks with <0.1% impact on legitimate users.
 *
 * SUCCESS METRICS:
 * - Flash loan attack prevention: 100%
 * - False positive rate: <0.1%
 * - User experience impact: minimal
 * - Gas overhead: <10%
 * - Detection accuracy: >99.9%
 *
 * SECURITY CONSIDERATIONS:
 * - Transaction origin validation
 * - Block-based timing locks
 * - Balance change monitoring
 * - Price oracle manipulation detection
 * - Governance attack prevention
 */

// Protection level
enum ProtectionLevel {
    STANDARD,       // Basic checks
    ENHANCED,       // Additional time-weighted checks
    MAXIMUM,        // Full protection suite
    PARANOID        // Strictest protection
}

// Action type
enum ActionType {
    SWAP,
    LIQUIDITY_ADD,
    LIQUIDITY_REMOVE,
    GOVERNANCE_VOTE,
    COLLATERAL_ADJUST,
    POSITION_OPEN,
    POSITION_CLOSE,
    ORACLE_UPDATE
}

// User activity
struct UserActivity {
    uint256 lastActionBlock;
    uint256 lastActionTimestamp;
    uint256 blockStartBalance;
    uint256 transactionCount;
    uint256 volumeThisBlock;
    bool inFlashLoan;
    uint256 flashLoanOrigin;
}

// Protection config
struct ProtectionConfig {
    ActionType actionType;
    ProtectionLevel level;
    uint256 minBlockDelay;      // Minimum blocks between actions
    uint256 minTimeDelay;       // Minimum seconds between actions
    uint256 maxVolumePerBlock;  // Max volume in single block
    uint256 maxTransactions;    // Max transactions per block
    bool requireOriginCheck;    // Check tx.origin == msg.sender
    bool requireBalanceCheck;   // Check balance unchanged in block
}

// Flash loan detector
struct FlashLoanDetector {
    mapping(address => uint256) balanceAtBlockStart;
    mapping(address => bool) balanceRecorded;
    mapping(uint256 => bool) suspiciousBlocks;
}

// TWAP guard
struct TWAPGuard {
    uint256 cumulativePrice;
    uint256 lastUpdate;
    uint256 windowSize;
    uint256 maxDeviation;
}

contract FlashLoanProtection is ReentrancyGuard, AccessControl {

    // Roles
    bytes32 public constant PROTECTOR_ROLE = keccak256("PROTECTOR_ROLE");
    bytes32 public constant CONFIG_ROLE = keccak256("CONFIG_ROLE");

    // User activity tracking
    mapping(address => UserActivity) public userActivity;

    // Protection configurations
    mapping(ActionType => ProtectionConfig) public protectionConfigs;

    // Flash loan detection
    FlashLoanDetector private detector;

    // TWAP guards for price manipulation detection
    mapping(address => TWAPGuard) public twapGuards;

    // Blacklisted contracts (known flash loan providers)
    mapping(address => bool) public blacklistedContracts;

    // Whitelisted addresses (trusted contracts)
    mapping(address => bool) public whitelistedAddresses;

    // Global settings
    bool public globalProtectionEnabled = true;
    uint256 public maxPriceDeviationBP = 500; // 5%
    uint256 public blockConfirmations = 1;
    uint256 public globalMaxVolumePerBlock = 1000000 ether;

    // Flash loan indicators
    uint256 public constant MAX_BALANCE_CHANGE = 1000000 ether;
    uint256 public constant SUSPICIOUS_GAS_PRICE = 500 gwei;

    // Events
    event FlashLoanDetected(
        address indexed user,
        address indexed contract_,
        uint256 amount,
        uint256 blockNumber
    );

    event ActionBlocked(
        address indexed user,
        ActionType actionType,
        string reason
    );

    event ProtectionConfigUpdated(
        ActionType actionType,
        ProtectionLevel level
    );

    event SuspiciousActivity(
        address indexed user,
        string activityType,
        uint256 value
    );

    event WhitelistUpdated(address indexed addr, bool status);
    event BlacklistUpdated(address indexed addr, bool status);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PROTECTOR_ROLE, msg.sender);
        _grantRole(CONFIG_ROLE, msg.sender);

        _initializeDefaultConfigs();
    }

    function _initializeDefaultConfigs() internal {
        // Swap protection
        protectionConfigs[ActionType.SWAP] = ProtectionConfig({
            actionType: ActionType.SWAP,
            level: ProtectionLevel.STANDARD,
            minBlockDelay: 0,
            minTimeDelay: 0,
            maxVolumePerBlock: 100000 ether,
            maxTransactions: 10,
            requireOriginCheck: true,
            requireBalanceCheck: false
        });

        // Governance vote protection
        protectionConfigs[ActionType.GOVERNANCE_VOTE] = ProtectionConfig({
            actionType: ActionType.GOVERNANCE_VOTE,
            level: ProtectionLevel.MAXIMUM,
            minBlockDelay: 2,
            minTimeDelay: 60,
            maxVolumePerBlock: type(uint256).max,
            maxTransactions: 1,
            requireOriginCheck: true,
            requireBalanceCheck: true
        });

        // Position open protection
        protectionConfigs[ActionType.POSITION_OPEN] = ProtectionConfig({
            actionType: ActionType.POSITION_OPEN,
            level: ProtectionLevel.ENHANCED,
            minBlockDelay: 1,
            minTimeDelay: 15,
            maxVolumePerBlock: 500000 ether,
            maxTransactions: 5,
            requireOriginCheck: true,
            requireBalanceCheck: true
        });

        // Liquidity removal protection
        protectionConfigs[ActionType.LIQUIDITY_REMOVE] = ProtectionConfig({
            actionType: ActionType.LIQUIDITY_REMOVE,
            level: ProtectionLevel.ENHANCED,
            minBlockDelay: 1,
            minTimeDelay: 30,
            maxVolumePerBlock: 200000 ether,
            maxTransactions: 3,
            requireOriginCheck: true,
            requireBalanceCheck: false
        });

        // Oracle update protection
        protectionConfigs[ActionType.ORACLE_UPDATE] = ProtectionConfig({
            actionType: ActionType.ORACLE_UPDATE,
            level: ProtectionLevel.PARANOID,
            minBlockDelay: 3,
            minTimeDelay: 120,
            maxVolumePerBlock: type(uint256).max,
            maxTransactions: 1,
            requireOriginCheck: true,
            requireBalanceCheck: true
        });
    }

    /**
     * Main protection check
     */
    modifier protectedAction(ActionType actionType, uint256 volume) {
        require(globalProtectionEnabled, "Protection disabled");
        require(_checkFlashLoanProtection(msg.sender, actionType, volume), "Flash loan protection triggered");
        _;
        _recordActivity(msg.sender, actionType, volume);
    }

    /**
     * Check if action is protected against flash loans
     */
    function _checkFlashLoanProtection(
        address user,
        ActionType actionType,
        uint256 volume
    ) internal returns (bool) {
        // Skip checks for whitelisted addresses
        if (whitelistedAddresses[user]) {
            return true;
        }

        ProtectionConfig storage config = protectionConfigs[actionType];

        // Check 1: Origin verification
        if (config.requireOriginCheck) {
            if (!_checkOrigin(user)) {
                emit ActionBlocked(user, actionType, "Origin check failed");
                return false;
            }
        }

        // Check 2: Block delay
        if (config.minBlockDelay > 0) {
            UserActivity storage activity = userActivity[user];
            if (block.number < activity.lastActionBlock + config.minBlockDelay) {
                emit ActionBlocked(user, actionType, "Block delay not met");
                return false;
            }
        }

        // Check 3: Time delay
        if (config.minTimeDelay > 0) {
            UserActivity storage activity = userActivity[user];
            if (block.timestamp < activity.lastActionTimestamp + config.minTimeDelay) {
                emit ActionBlocked(user, actionType, "Time delay not met");
                return false;
            }
        }

        // Check 4: Volume limit per block
        if (volume > config.maxVolumePerBlock) {
            emit ActionBlocked(user, actionType, "Volume exceeds block limit");
            return false;
        }

        // Check 5: Transaction count
        UserActivity storage activity = userActivity[user];
        if (activity.lastActionBlock == block.number) {
            if (activity.transactionCount >= config.maxTransactions) {
                emit ActionBlocked(user, actionType, "Max transactions per block exceeded");
                return false;
            }
            if (activity.volumeThisBlock + volume > config.maxVolumePerBlock) {
                emit ActionBlocked(user, actionType, "Block volume limit exceeded");
                return false;
            }
        }

        // Check 6: Balance change detection
        if (config.requireBalanceCheck) {
            if (!_checkBalanceStability(user)) {
                emit ActionBlocked(user, actionType, "Balance instability detected");
                return false;
            }
        }

        // Check 7: Flash loan detection
        if (_detectFlashLoan(user)) {
            emit FlashLoanDetected(user, msg.sender, volume, block.number);
            return false;
        }

        // Check 8: Gas price anomaly (potential MEV bot)
        if (tx.gasprice > SUSPICIOUS_GAS_PRICE) {
            emit SuspiciousActivity(user, "High gas price", tx.gasprice);
            // Don't block, just log
        }

        // Check 9: Contract interaction check
        if (_isContract(msg.sender) && blacklistedContracts[msg.sender]) {
            emit ActionBlocked(user, actionType, "Blacklisted contract");
            return false;
        }

        return true;
    }

    /**
     * Check transaction origin
     */
    function _checkOrigin(address user) internal view returns (bool) {
        // Verify tx.origin matches sender for EOA transactions
        // or is in call chain for contract interactions
        if (tx.origin == user) {
            return true;
        }

        // Allow contract interactions from whitelisted contracts
        if (whitelistedAddresses[msg.sender]) {
            return true;
        }

        // Reject if called through unknown contract
        return !_isContract(msg.sender);
    }

    /**
     * Check balance stability
     */
    function _checkBalanceStability(address user) internal returns (bool) {
        // Record balance at start of block
        if (!detector.balanceRecorded[user]) {
            detector.balanceAtBlockStart[user] = user.balance;
            detector.balanceRecorded[user] = true;
        }

        uint256 currentBalance = user.balance;
        uint256 startBalance = detector.balanceAtBlockStart[user];

        // Check for large balance changes within same block
        uint256 change = currentBalance > startBalance
            ? currentBalance - startBalance
            : startBalance - currentBalance;

        if (change > MAX_BALANCE_CHANGE) {
            return false;
        }

        return true;
    }

    /**
     * Detect flash loan patterns
     */
    function _detectFlashLoan(address user) internal view returns (bool) {
        UserActivity storage activity = userActivity[user];

        // Pattern 1: Same block activity spike
        if (activity.lastActionBlock == block.number) {
            if (activity.transactionCount > 5) {
                return true;
            }
        }

        // Pattern 2: User marked as in flash loan
        if (activity.inFlashLoan) {
            return true;
        }

        // Pattern 3: Known flash loan contract caller
        if (blacklistedContracts[msg.sender]) {
            return true;
        }

        return false;
    }

    /**
     * Record user activity
     */
    function _recordActivity(
        address user,
        ActionType actionType,
        uint256 volume
    ) internal {
        UserActivity storage activity = userActivity[user];

        if (activity.lastActionBlock != block.number) {
            // New block, reset counters
            activity.transactionCount = 1;
            activity.volumeThisBlock = volume;
            activity.blockStartBalance = user.balance;

            // Reset balance recording
            detector.balanceRecorded[user] = false;
        } else {
            // Same block, increment counters
            activity.transactionCount++;
            activity.volumeThisBlock += volume;
        }

        activity.lastActionBlock = block.number;
        activity.lastActionTimestamp = block.timestamp;
    }

    /**
     * Check if address is contract
     */
    function _isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }
        return size > 0;
    }

    /**
     * Update protection config
     */
    function updateProtectionConfig(
        ActionType actionType,
        ProtectionLevel level,
        uint256 minBlockDelay,
        uint256 minTimeDelay,
        uint256 maxVolumePerBlock,
        uint256 maxTransactions,
        bool requireOriginCheck,
        bool requireBalanceCheck
    ) external onlyRole(CONFIG_ROLE) {
        protectionConfigs[actionType] = ProtectionConfig({
            actionType: actionType,
            level: level,
            minBlockDelay: minBlockDelay,
            minTimeDelay: minTimeDelay,
            maxVolumePerBlock: maxVolumePerBlock,
            maxTransactions: maxTransactions,
            requireOriginCheck: requireOriginCheck,
            requireBalanceCheck: requireBalanceCheck
        });

        emit ProtectionConfigUpdated(actionType, level);
    }

    /**
     * Add to whitelist
     */
    function addToWhitelist(address addr) external onlyRole(PROTECTOR_ROLE) {
        whitelistedAddresses[addr] = true;
        emit WhitelistUpdated(addr, true);
    }

    /**
     * Remove from whitelist
     */
    function removeFromWhitelist(address addr) external onlyRole(PROTECTOR_ROLE) {
        whitelistedAddresses[addr] = false;
        emit WhitelistUpdated(addr, false);
    }

    /**
     * Add to blacklist
     */
    function addToBlacklist(address addr) external onlyRole(PROTECTOR_ROLE) {
        blacklistedContracts[addr] = true;
        emit BlacklistUpdated(addr, true);
    }

    /**
     * Remove from blacklist
     */
    function removeFromBlacklist(address addr) external onlyRole(PROTECTOR_ROLE) {
        blacklistedContracts[addr] = false;
        emit BlacklistUpdated(addr, false);
    }

    /**
     * Mark user as in flash loan (called by integrating contracts)
     */
    function markFlashLoanStart(address user) external onlyRole(PROTECTOR_ROLE) {
        UserActivity storage activity = userActivity[user];
        activity.inFlashLoan = true;
        activity.flashLoanOrigin = block.number;
    }

    /**
     * Mark flash loan ended
     */
    function markFlashLoanEnd(address user) external onlyRole(PROTECTOR_ROLE) {
        UserActivity storage activity = userActivity[user];
        activity.inFlashLoan = false;
    }

    /**
     * Update TWAP guard for price manipulation detection
     */
    function updateTWAPGuard(
        address token,
        uint256 currentPrice,
        uint256 windowSize,
        uint256 maxDeviation
    ) external onlyRole(PROTECTOR_ROLE) {
        TWAPGuard storage guard = twapGuards[token];

        uint256 timeElapsed = block.timestamp - guard.lastUpdate;

        if (guard.lastUpdate == 0) {
            guard.cumulativePrice = currentPrice;
        } else {
            guard.cumulativePrice += currentPrice * timeElapsed;
        }

        guard.lastUpdate = block.timestamp;
        guard.windowSize = windowSize;
        guard.maxDeviation = maxDeviation;
    }

    /**
     * Check if price deviation is suspicious
     */
    function checkPriceManipulation(
        address token,
        uint256 currentPrice
    ) external view returns (bool isSuspicious) {
        TWAPGuard storage guard = twapGuards[token];

        if (guard.lastUpdate == 0) return false;

        // Calculate TWAP
        uint256 timeElapsed = block.timestamp - guard.lastUpdate;
        if (timeElapsed == 0) return false;

        uint256 twap = guard.cumulativePrice / timeElapsed;

        // Check deviation
        uint256 deviation;
        if (currentPrice > twap) {
            deviation = ((currentPrice - twap) * 10000) / twap;
        } else {
            deviation = ((twap - currentPrice) * 10000) / twap;
        }

        return deviation > guard.maxDeviation;
    }

    /**
     * Toggle global protection
     */
    function setGlobalProtection(bool enabled) external onlyRole(CONFIG_ROLE) {
        globalProtectionEnabled = enabled;
    }

    /**
     * Get user protection status
     */
    function getUserProtectionStatus(address user) external view returns (
        uint256 lastActionBlock,
        uint256 lastActionTimestamp,
        uint256 transactionCount,
        uint256 volumeThisBlock,
        bool inFlashLoan
    ) {
        UserActivity storage activity = userActivity[user];
        return (
            activity.lastActionBlock,
            activity.lastActionTimestamp,
            activity.transactionCount,
            activity.volumeThisBlock,
            activity.inFlashLoan
        );
    }

    /**
     * Emergency clear user activity (admin only)
     */
    function clearUserActivity(address user) external onlyRole(PROTECTOR_ROLE) {
        delete userActivity[user];
    }
}
