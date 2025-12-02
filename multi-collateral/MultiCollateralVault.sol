// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * MULTI-COLLATERAL VAULT SYSTEM
 *
 * HYPOTHESIS: A flexible multi-collateral system with risk-adjusted haircuts
 * and correlation-aware portfolio margining will improve capital efficiency
 * by 3x while maintaining 100% system solvency.
 *
 * SUCCESS METRICS:
 * - Capital efficiency: 3x improvement
 * - System solvency: 100%
 * - Collateral utilization: >80%
 * - Liquidation accuracy: >99%
 * - User flexibility: >10 collateral types
 *
 * SECURITY CONSIDERATIONS:
 * - Risk-adjusted haircuts
 * - Correlation risk management
 * - Oracle redundancy per collateral
 * - Concentration limits
 * - Liquidity-based adjustments
 */

// Collateral status
enum CollateralStatus {
    ACTIVE,
    DEPRECATED,
    SUSPENDED,
    DELISTING
}

// Collateral tier
enum CollateralTier {
    PRIME,          // Highest quality (BTC, ETH)
    STANDARD,       // Stable coins, major tokens
    ALTERNATIVE,    // Smaller cap tokens
    EXOTIC          // High risk assets
}

// Collateral info
struct CollateralInfo {
    address token;
    string symbol;
    CollateralTier tier;
    CollateralStatus status;
    uint256 haircut;            // Percentage discount (basis points)
    uint256 maxConcentration;   // Max % of total collateral
    uint256 liquidationBonus;   // Extra percentage for liquidators
    uint256 depositCap;         // Max total deposits
    uint256 currentDeposits;    // Current total deposited
    uint256 minDepositAmount;   // Minimum deposit
    address oracle;             // Price oracle address
    uint256 oracleTimeout;      // Max age of oracle price
    bool canBeUsedForBorrowing; // Can be borrowed against
}

// User collateral position
struct UserCollateral {
    address user;
    address token;
    uint256 amount;
    uint256 depositTime;
    uint256 lastValueUpdate;
    uint256 lockedAmount;       // Amount locked for positions
    uint256 availableAmount;    // Amount available to withdraw
}

// Portfolio summary
struct PortfolioSummary {
    address user;
    uint256 totalValueUSD;
    uint256 adjustedValueUSD;   // After haircuts
    uint256 borrowingPower;
    uint256 usedBorrowingPower;
    uint256 healthFactor;
    uint256 collateralCount;
    uint256 concentrationRisk;
}

// Correlation factor
struct CorrelationFactor {
    address tokenA;
    address tokenB;
    int256 correlation;         // -10000 to 10000 (basis points)
    uint256 lastUpdate;
}

// Price oracle interface
interface IPriceOracle {
    function getPrice(address token) external view returns (uint256 price, uint256 timestamp);
}

contract MultiCollateralVault is ReentrancyGuard, AccessControl {
    using SafeERC20 for IERC20;

    // Roles
    bytes32 public constant COLLATERAL_MANAGER = keccak256("COLLATERAL_MANAGER");
    bytes32 public constant RISK_MANAGER = keccak256("RISK_MANAGER");
    bytes32 public constant LIQUIDATOR_ROLE = keccak256("LIQUIDATOR_ROLE");

    // Collateral registry
    mapping(address => CollateralInfo) public collaterals;
    address[] public collateralList;

    // User positions
    mapping(address => mapping(address => UserCollateral)) public userCollaterals;
    mapping(address => address[]) public userCollateralTokens;

    // Correlation matrix
    mapping(bytes32 => CorrelationFactor) public correlations;

    // Global settings
    uint256 public minHealthFactor = 12000; // 120%
    uint256 public liquidationThreshold = 10000; // 100%
    uint256 public maxCollateralsPerUser = 10;
    uint256 public globalDepositCap = 1000000000 * 1e18; // $1B
    uint256 public currentTotalDeposits;

    // Portfolio margin adjustments
    uint256 public correlationBenefit = 500; // 5% reduction for uncorrelated assets
    bool public portfolioMarginEnabled = true;

    // Events
    event CollateralAdded(
        address indexed token,
        string symbol,
        CollateralTier tier,
        uint256 haircut
    );

    event CollateralDeposited(
        address indexed user,
        address indexed token,
        uint256 amount,
        uint256 valueUSD
    );

    event CollateralWithdrawn(
        address indexed user,
        address indexed token,
        uint256 amount
    );

    event CollateralLocked(
        address indexed user,
        address indexed token,
        uint256 amount
    );

    event CollateralUnlocked(
        address indexed user,
        address indexed token,
        uint256 amount
    );

    event CollateralLiquidated(
        address indexed user,
        address indexed liquidator,
        address indexed token,
        uint256 amount,
        uint256 bonus
    );

    event CorrelationUpdated(
        address tokenA,
        address tokenB,
        int256 correlation
    );

    event CollateralStatusChanged(
        address indexed token,
        CollateralStatus oldStatus,
        CollateralStatus newStatus
    );

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(COLLATERAL_MANAGER, msg.sender);
        _grantRole(RISK_MANAGER, msg.sender);
    }

    /**
     * Add new collateral type
     */
    function addCollateral(
        address token,
        string calldata symbol,
        CollateralTier tier,
        uint256 haircut,
        uint256 maxConcentration,
        uint256 liquidationBonus,
        uint256 depositCap,
        uint256 minDepositAmount,
        address oracle,
        uint256 oracleTimeout
    ) external onlyRole(COLLATERAL_MANAGER) {
        require(collaterals[token].token == address(0), "Collateral exists");
        require(haircut <= 5000, "Haircut too high"); // Max 50% haircut
        require(maxConcentration <= 10000, "Invalid concentration");

        collaterals[token] = CollateralInfo({
            token: token,
            symbol: symbol,
            tier: tier,
            status: CollateralStatus.ACTIVE,
            haircut: haircut,
            maxConcentration: maxConcentration,
            liquidationBonus: liquidationBonus,
            depositCap: depositCap,
            currentDeposits: 0,
            minDepositAmount: minDepositAmount,
            oracle: oracle,
            oracleTimeout: oracleTimeout,
            canBeUsedForBorrowing: tier != CollateralTier.EXOTIC
        });

        collateralList.push(token);

        emit CollateralAdded(token, symbol, tier, haircut);
    }

    /**
     * Deposit collateral
     */
    function deposit(
        address token,
        uint256 amount
    ) external nonReentrant {
        CollateralInfo storage info = collaterals[token];
        require(info.status == CollateralStatus.ACTIVE, "Collateral not active");
        require(amount >= info.minDepositAmount, "Below minimum");
        require(info.currentDeposits + amount <= info.depositCap, "Deposit cap reached");
        require(currentTotalDeposits + amount <= globalDepositCap, "Global cap reached");

        // Check user collateral count
        if (userCollaterals[msg.sender][token].amount == 0) {
            require(
                userCollateralTokens[msg.sender].length < maxCollateralsPerUser,
                "Max collaterals exceeded"
            );
            userCollateralTokens[msg.sender].push(token);
        }

        // Transfer tokens
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        // Update user position
        UserCollateral storage userCol = userCollaterals[msg.sender][token];
        userCol.user = msg.sender;
        userCol.token = token;
        userCol.amount += amount;
        userCol.depositTime = block.timestamp;
        userCol.availableAmount += amount;
        userCol.lastValueUpdate = block.timestamp;

        // Update global deposits
        info.currentDeposits += amount;
        currentTotalDeposits += amount;

        // Check concentration limit
        require(_checkConcentration(msg.sender, token), "Concentration limit exceeded");

        // Get USD value
        (uint256 price,) = IPriceOracle(info.oracle).getPrice(token);
        uint256 valueUSD = (amount * price) / 1e18;

        emit CollateralDeposited(msg.sender, token, amount, valueUSD);
    }

    /**
     * Withdraw collateral
     */
    function withdraw(
        address token,
        uint256 amount
    ) external nonReentrant {
        UserCollateral storage userCol = userCollaterals[msg.sender][token];
        require(userCol.availableAmount >= amount, "Insufficient available");

        // Check health factor after withdrawal
        require(
            _checkHealthFactorAfterWithdrawal(msg.sender, token, amount),
            "Would breach health factor"
        );

        // Update positions
        userCol.amount -= amount;
        userCol.availableAmount -= amount;

        // Update global deposits
        CollateralInfo storage info = collaterals[token];
        info.currentDeposits -= amount;
        currentTotalDeposits -= amount;

        // Remove token from user list if fully withdrawn
        if (userCol.amount == 0) {
            _removeUserCollateralToken(msg.sender, token);
        }

        // Transfer tokens
        IERC20(token).safeTransfer(msg.sender, amount);

        emit CollateralWithdrawn(msg.sender, token, amount);
    }

    /**
     * Lock collateral for position
     */
    function lockCollateral(
        address user,
        address token,
        uint256 amount
    ) external onlyRole(RISK_MANAGER) {
        UserCollateral storage userCol = userCollaterals[user][token];
        require(userCol.availableAmount >= amount, "Insufficient available");

        userCol.lockedAmount += amount;
        userCol.availableAmount -= amount;

        emit CollateralLocked(user, token, amount);
    }

    /**
     * Unlock collateral
     */
    function unlockCollateral(
        address user,
        address token,
        uint256 amount
    ) external onlyRole(RISK_MANAGER) {
        UserCollateral storage userCol = userCollaterals[user][token];
        require(userCol.lockedAmount >= amount, "Insufficient locked");

        userCol.lockedAmount -= amount;
        userCol.availableAmount += amount;

        emit CollateralUnlocked(user, token, amount);
    }

    /**
     * Liquidate undercollateralized position
     */
    function liquidate(
        address user,
        address collateralToken,
        uint256 debtToRepay
    ) external nonReentrant onlyRole(LIQUIDATOR_ROLE) {
        PortfolioSummary memory summary = getPortfolioSummary(user);
        require(summary.healthFactor < liquidationThreshold, "Not liquidatable");

        CollateralInfo storage info = collaterals[collateralToken];
        UserCollateral storage userCol = userCollaterals[user][collateralToken];

        require(userCol.amount > 0, "No collateral");

        // Calculate collateral to seize
        (uint256 price,) = IPriceOracle(info.oracle).getPrice(collateralToken);

        uint256 collateralValue = (debtToRepay * 1e18) / price;
        uint256 bonus = (collateralValue * info.liquidationBonus) / 10000;
        uint256 totalSeize = collateralValue + bonus;

        if (totalSeize > userCol.amount) {
            totalSeize = userCol.amount;
        }

        // Update user position
        userCol.amount -= totalSeize;
        userCol.availableAmount = userCol.availableAmount > totalSeize
            ? userCol.availableAmount - totalSeize
            : 0;

        // Update global deposits
        info.currentDeposits -= totalSeize;
        currentTotalDeposits -= totalSeize;

        // Transfer collateral to liquidator
        IERC20(collateralToken).safeTransfer(msg.sender, totalSeize);

        emit CollateralLiquidated(user, msg.sender, collateralToken, totalSeize, bonus);
    }

    /**
     * Get portfolio summary
     */
    function getPortfolioSummary(address user) public view returns (PortfolioSummary memory) {
        address[] memory tokens = userCollateralTokens[user];

        uint256 totalValueUSD;
        uint256 adjustedValueUSD;

        // Calculate individual collateral values
        for (uint256 i = 0; i < tokens.length; i++) {
            UserCollateral storage userCol = userCollaterals[user][tokens[i]];
            CollateralInfo storage info = collaterals[tokens[i]];

            if (userCol.amount == 0) continue;

            (uint256 price, uint256 timestamp) = IPriceOracle(info.oracle).getPrice(tokens[i]);

            // Check oracle staleness
            require(
                block.timestamp - timestamp <= info.oracleTimeout,
                "Oracle stale"
            );

            uint256 value = (userCol.amount * price) / 1e18;
            totalValueUSD += value;

            // Apply haircut
            uint256 adjusted = (value * (10000 - info.haircut)) / 10000;
            adjustedValueUSD += adjusted;
        }

        // Apply portfolio margin benefit if enabled
        if (portfolioMarginEnabled && tokens.length > 1) {
            uint256 diversificationBenefit = _calculateDiversificationBenefit(user);
            adjustedValueUSD += (adjustedValueUSD * diversificationBenefit) / 10000;
        }

        // Calculate concentration risk
        uint256 concentrationRisk = _calculateConcentrationRisk(user, tokens, totalValueUSD);

        // Health factor (simplified - would need actual debt info)
        uint256 healthFactor = 20000; // 200% default (no debt)

        return PortfolioSummary({
            user: user,
            totalValueUSD: totalValueUSD,
            adjustedValueUSD: adjustedValueUSD,
            borrowingPower: adjustedValueUSD,
            usedBorrowingPower: 0,
            healthFactor: healthFactor,
            collateralCount: tokens.length,
            concentrationRisk: concentrationRisk
        });
    }

    /**
     * Update correlation factor
     */
    function updateCorrelation(
        address tokenA,
        address tokenB,
        int256 correlation
    ) external onlyRole(RISK_MANAGER) {
        require(correlation >= -10000 && correlation <= 10000, "Invalid correlation");

        bytes32 key = _getCorrelationKey(tokenA, tokenB);
        correlations[key] = CorrelationFactor({
            tokenA: tokenA,
            tokenB: tokenB,
            correlation: correlation,
            lastUpdate: block.timestamp
        });

        emit CorrelationUpdated(tokenA, tokenB, correlation);
    }

    /**
     * Update collateral status
     */
    function updateCollateralStatus(
        address token,
        CollateralStatus newStatus
    ) external onlyRole(COLLATERAL_MANAGER) {
        CollateralInfo storage info = collaterals[token];
        require(info.token != address(0), "Collateral not found");

        CollateralStatus oldStatus = info.status;
        info.status = newStatus;

        emit CollateralStatusChanged(token, oldStatus, newStatus);
    }

    /**
     * Update collateral parameters
     */
    function updateCollateralParams(
        address token,
        uint256 haircut,
        uint256 maxConcentration,
        uint256 liquidationBonus,
        uint256 depositCap
    ) external onlyRole(COLLATERAL_MANAGER) {
        CollateralInfo storage info = collaterals[token];
        require(info.token != address(0), "Collateral not found");

        info.haircut = haircut;
        info.maxConcentration = maxConcentration;
        info.liquidationBonus = liquidationBonus;
        info.depositCap = depositCap;
    }

    /**
     * Get user's collateral for specific token
     */
    function getUserCollateral(
        address user,
        address token
    ) external view returns (
        uint256 amount,
        uint256 lockedAmount,
        uint256 availableAmount,
        uint256 valueUSD,
        uint256 adjustedValueUSD
    ) {
        UserCollateral storage userCol = userCollaterals[user][token];
        CollateralInfo storage info = collaterals[token];

        if (userCol.amount == 0) {
            return (0, 0, 0, 0, 0);
        }

        (uint256 price,) = IPriceOracle(info.oracle).getPrice(token);
        valueUSD = (userCol.amount * price) / 1e18;
        adjustedValueUSD = (valueUSD * (10000 - info.haircut)) / 10000;

        return (
            userCol.amount,
            userCol.lockedAmount,
            userCol.availableAmount,
            valueUSD,
            adjustedValueUSD
        );
    }

    /**
     * Get all supported collaterals
     */
    function getAllCollaterals() external view returns (address[] memory) {
        return collateralList;
    }

    /**
     * Get user's collateral tokens
     */
    function getUserCollateralTokens(address user) external view returns (address[] memory) {
        return userCollateralTokens[user];
    }

    /**
     * Check if user can deposit more of a token
     */
    function canDeposit(
        address user,
        address token,
        uint256 amount
    ) external view returns (bool canDep, string memory reason) {
        CollateralInfo storage info = collaterals[token];

        if (info.status != CollateralStatus.ACTIVE) {
            return (false, "Collateral not active");
        }

        if (amount < info.minDepositAmount) {
            return (false, "Below minimum");
        }

        if (info.currentDeposits + amount > info.depositCap) {
            return (false, "Deposit cap reached");
        }

        if (currentTotalDeposits + amount > globalDepositCap) {
            return (false, "Global cap reached");
        }

        if (
            userCollaterals[user][token].amount == 0 &&
            userCollateralTokens[user].length >= maxCollateralsPerUser
        ) {
            return (false, "Max collaterals exceeded");
        }

        return (true, "");
    }

    // Internal functions

    function _checkConcentration(address user, address token) internal view returns (bool) {
        PortfolioSummary memory summary = getPortfolioSummary(user);

        if (summary.totalValueUSD == 0) return true;

        UserCollateral storage userCol = userCollaterals[user][token];
        CollateralInfo storage info = collaterals[token];

        (uint256 price,) = IPriceOracle(info.oracle).getPrice(token);
        uint256 tokenValue = (userCol.amount * price) / 1e18;

        uint256 concentration = (tokenValue * 10000) / summary.totalValueUSD;

        return concentration <= info.maxConcentration;
    }

    function _checkHealthFactorAfterWithdrawal(
        address user,
        address token,
        uint256 amount
    ) internal view returns (bool) {
        // Simplified: just check if user still has sufficient collateral
        UserCollateral storage userCol = userCollaterals[user][token];

        if (userCol.lockedAmount > userCol.amount - amount) {
            return false;
        }

        return true;
    }

    function _calculateDiversificationBenefit(address user) internal view returns (uint256) {
        address[] memory tokens = userCollateralTokens[user];

        if (tokens.length <= 1) return 0;

        // Calculate average correlation
        uint256 totalCorrelations = 0;
        uint256 pairCount = 0;

        for (uint256 i = 0; i < tokens.length; i++) {
            for (uint256 j = i + 1; j < tokens.length; j++) {
                bytes32 key = _getCorrelationKey(tokens[i], tokens[j]);
                CorrelationFactor storage corr = correlations[key];

                if (corr.lastUpdate > 0) {
                    // Add absolute correlation
                    totalCorrelations += corr.correlation > 0
                        ? uint256(corr.correlation)
                        : uint256(-corr.correlation);
                    pairCount++;
                }
            }
        }

        if (pairCount == 0) return correlationBenefit / 2; // Default benefit

        uint256 avgCorrelation = totalCorrelations / pairCount;

        // Lower correlation = higher benefit
        if (avgCorrelation < 5000) {
            return correlationBenefit;
        } else if (avgCorrelation < 7500) {
            return correlationBenefit / 2;
        }

        return 0;
    }

    function _calculateConcentrationRisk(
        address user,
        address[] memory tokens,
        uint256 totalValueUSD
    ) internal view returns (uint256) {
        if (totalValueUSD == 0 || tokens.length == 0) return 0;

        uint256 maxConcentration = 0;

        for (uint256 i = 0; i < tokens.length; i++) {
            UserCollateral storage userCol = userCollaterals[user][tokens[i]];
            CollateralInfo storage info = collaterals[tokens[i]];

            if (userCol.amount == 0) continue;

            (uint256 price,) = IPriceOracle(info.oracle).getPrice(tokens[i]);
            uint256 value = (userCol.amount * price) / 1e18;
            uint256 concentration = (value * 10000) / totalValueUSD;

            if (concentration > maxConcentration) {
                maxConcentration = concentration;
            }
        }

        return maxConcentration;
    }

    function _getCorrelationKey(address tokenA, address tokenB) internal pure returns (bytes32) {
        if (tokenA < tokenB) {
            return keccak256(abi.encodePacked(tokenA, tokenB));
        }
        return keccak256(abi.encodePacked(tokenB, tokenA));
    }

    function _removeUserCollateralToken(address user, address token) internal {
        address[] storage tokens = userCollateralTokens[user];
        for (uint256 i = 0; i < tokens.length; i++) {
            if (tokens[i] == token) {
                tokens[i] = tokens[tokens.length - 1];
                tokens.pop();
                break;
            }
        }
    }
}
