// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * AUTOMATED LIQUIDATION ENGINE
 *
 * HYPOTHESIS: A fair, transparent liquidation mechanism with gradual
 * liquidations and keeper incentives will maintain system solvency
 * while minimizing user losses and preventing cascade liquidations.
 *
 * SUCCESS METRICS:
 * - System solvency: 100% maintained
 * - Liquidation accuracy: >99.9%
 * - User loss minimization: <5% average slippage
 * - Cascade prevention: 0 cascade events
 * - Keeper participation: >10 active keepers
 *
 * SECURITY CONSIDERATIONS:
 * - Oracle manipulation protection
 * - Gradual liquidation mechanism
 * - Keeper incentive alignment
 * - Insurance fund backup
 * - Circuit breakers for extreme events
 */

// Position status
enum PositionStatus {
    HEALTHY,
    WARNING,
    LIQUIDATABLE,
    PARTIALLY_LIQUIDATED,
    FULLY_LIQUIDATED,
    BANKRUPT
}

// Liquidation type
enum LiquidationType {
    PARTIAL,
    FULL,
    BACKSTOP,
    INSURANCE
}

// Margin position
struct MarginPosition {
    uint256 positionId;
    address owner;
    address collateralToken;
    address debtToken;
    uint256 collateralAmount;
    uint256 debtAmount;
    uint256 initialMarginRatio; // basis points
    uint256 maintenanceMarginRatio;
    uint256 liquidationPenalty;
    uint256 openTime;
    uint256 lastUpdateTime;
    PositionStatus status;
}

// Liquidation event
struct LiquidationEvent {
    uint256 liquidationId;
    uint256 positionId;
    address liquidator;
    LiquidationType liquidationType;
    uint256 collateralSeized;
    uint256 debtRepaid;
    uint256 penalty;
    uint256 keeperReward;
    uint256 insuranceFundContribution;
    uint256 timestamp;
}

// Keeper info
struct Keeper {
    address keeperAddress;
    uint256 totalLiquidations;
    uint256 totalRewards;
    uint256 reputation;
    uint256 stake;
    bool isActive;
    uint256 lastLiquidationTime;
}

// Market parameters
struct MarketParams {
    address collateralToken;
    address debtToken;
    uint256 maxLTV; // loan-to-value, basis points
    uint256 liquidationThreshold; // basis points
    uint256 liquidationPenalty; // basis points
    uint256 keeperRewardPercent; // basis points
    uint256 insuranceFundPercent; // basis points
    uint256 minCollateral;
    uint256 maxCollateral;
    bool isActive;
}

// Price feed interface
interface IPriceFeed {
    function getPrice(address token) external view returns (uint256 price, uint256 timestamp);
}

contract LiquidationEngine is ReentrancyGuard, Pausable, AccessControl {
    using SafeERC20 for IERC20;

    // Roles
    bytes32 public constant KEEPER_ROLE = keccak256("KEEPER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // Price feed
    IPriceFeed public priceFeed;

    // Positions
    mapping(uint256 => MarginPosition) public positions;
    mapping(address => uint256[]) public userPositions;
    uint256 public positionCounter;

    // Markets
    mapping(bytes32 => MarketParams) public markets; // keccak256(collateral, debt) => params
    bytes32[] public marketList;

    // Keepers
    mapping(address => Keeper) public keepers;
    address[] public keeperList;

    // Liquidation history
    mapping(uint256 => LiquidationEvent) public liquidations;
    uint256 public liquidationCounter;

    // Insurance fund
    mapping(address => uint256) public insuranceFund;

    // Global parameters
    uint256 public minKeeperStake = 10 ether;
    uint256 public maxLiquidationSize = 50; // percent of position per liquidation
    uint256 public liquidationDelay = 0; // blocks
    uint256 public maxPriceStaleness = 3600; // seconds

    // Circuit breaker
    bool public emergencyMode = false;
    uint256 public maxLiquidationsPerBlock = 100;
    mapping(uint256 => uint256) public liquidationsPerBlock;

    // Events
    event PositionCreated(
        uint256 indexed positionId,
        address indexed owner,
        address collateralToken,
        address debtToken,
        uint256 collateralAmount,
        uint256 debtAmount
    );

    event PositionUpdated(
        uint256 indexed positionId,
        uint256 newCollateral,
        uint256 newDebt,
        PositionStatus newStatus
    );

    event LiquidationExecuted(
        uint256 indexed liquidationId,
        uint256 indexed positionId,
        address indexed liquidator,
        LiquidationType liquidationType,
        uint256 collateralSeized,
        uint256 debtRepaid
    );

    event KeeperRegistered(address indexed keeper, uint256 stake);
    event KeeperRewarded(address indexed keeper, uint256 reward);
    event InsuranceFundContribution(address indexed token, uint256 amount);
    event EmergencyModeActivated(string reason);

    constructor(address _priceFeed) {
        priceFeed = IPriceFeed(_priceFeed);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
    }

    /**
     * Open new margin position
     */
    function openPosition(
        address collateralToken,
        address debtToken,
        uint256 collateralAmount,
        uint256 debtAmount
    ) external nonReentrant whenNotPaused returns (uint256) {
        require(!emergencyMode, "Emergency mode active");

        bytes32 marketKey = keccak256(abi.encodePacked(collateralToken, debtToken));
        MarketParams storage market = markets[marketKey];
        require(market.isActive, "Market not active");

        require(collateralAmount >= market.minCollateral, "Below min collateral");
        require(collateralAmount <= market.maxCollateral, "Above max collateral");

        // Check LTV
        uint256 ltv = calculateLTV(collateralToken, collateralAmount, debtToken, debtAmount);
        require(ltv <= market.maxLTV, "LTV too high");

        // Transfer collateral
        IERC20(collateralToken).safeTransferFrom(msg.sender, address(this), collateralAmount);

        positionCounter++;
        uint256 positionId = positionCounter;

        positions[positionId] = MarginPosition({
            positionId: positionId,
            owner: msg.sender,
            collateralToken: collateralToken,
            debtToken: debtToken,
            collateralAmount: collateralAmount,
            debtAmount: debtAmount,
            initialMarginRatio: ltv,
            maintenanceMarginRatio: market.liquidationThreshold,
            liquidationPenalty: market.liquidationPenalty,
            openTime: block.timestamp,
            lastUpdateTime: block.timestamp,
            status: PositionStatus.HEALTHY
        });

        userPositions[msg.sender].push(positionId);

        emit PositionCreated(
            positionId,
            msg.sender,
            collateralToken,
            debtToken,
            collateralAmount,
            debtAmount
        );

        return positionId;
    }

    /**
     * Add collateral to position
     */
    function addCollateral(uint256 positionId, uint256 amount) external nonReentrant {
        MarginPosition storage position = positions[positionId];
        require(position.owner == msg.sender, "Not position owner");
        require(position.status != PositionStatus.FULLY_LIQUIDATED, "Position closed");

        IERC20(position.collateralToken).safeTransferFrom(msg.sender, address(this), amount);

        position.collateralAmount += amount;
        position.lastUpdateTime = block.timestamp;

        // Update status
        _updatePositionStatus(positionId);

        emit PositionUpdated(
            positionId,
            position.collateralAmount,
            position.debtAmount,
            position.status
        );
    }

    /**
     * Repay debt
     */
    function repayDebt(uint256 positionId, uint256 amount) external nonReentrant {
        MarginPosition storage position = positions[positionId];
        require(position.owner == msg.sender, "Not position owner");
        require(amount <= position.debtAmount, "Amount exceeds debt");

        IERC20(position.debtToken).safeTransferFrom(msg.sender, address(this), amount);

        position.debtAmount -= amount;
        position.lastUpdateTime = block.timestamp;

        // Update status
        _updatePositionStatus(positionId);

        emit PositionUpdated(
            positionId,
            position.collateralAmount,
            position.debtAmount,
            position.status
        );
    }

    /**
     * Liquidate unhealthy position
     */
    function liquidate(
        uint256 positionId,
        uint256 debtToRepay
    ) external nonReentrant whenNotPaused onlyRole(KEEPER_ROLE) returns (uint256) {
        require(!emergencyMode, "Use emergencyLiquidate in emergency mode");
        require(liquidationsPerBlock[block.number] < maxLiquidationsPerBlock, "Too many liquidations");

        MarginPosition storage position = positions[positionId];
        require(position.status == PositionStatus.LIQUIDATABLE, "Position not liquidatable");

        // Enforce partial liquidation limit
        uint256 maxRepay = (position.debtAmount * maxLiquidationSize) / 100;
        if (debtToRepay > maxRepay) {
            debtToRepay = maxRepay;
        }

        return _executeLiquidation(positionId, debtToRepay, msg.sender, LiquidationType.PARTIAL);
    }

    /**
     * Emergency liquidation (bypasses some checks)
     */
    function emergencyLiquidate(
        uint256 positionId
    ) external nonReentrant onlyRole(GUARDIAN_ROLE) returns (uint256) {
        require(emergencyMode, "Not in emergency mode");

        MarginPosition storage position = positions[positionId];
        uint256 debtToRepay = position.debtAmount;

        return _executeLiquidation(positionId, debtToRepay, msg.sender, LiquidationType.BACKSTOP);
    }

    /**
     * Register as keeper
     */
    function registerKeeper() external payable {
        require(msg.value >= minKeeperStake, "Insufficient stake");
        require(!keepers[msg.sender].isActive, "Already registered");

        keepers[msg.sender] = Keeper({
            keeperAddress: msg.sender,
            totalLiquidations: 0,
            totalRewards: 0,
            reputation: 100,
            stake: msg.value,
            isActive: true,
            lastLiquidationTime: 0
        });

        keeperList.push(msg.sender);
        _grantRole(KEEPER_ROLE, msg.sender);

        emit KeeperRegistered(msg.sender, msg.value);
    }

    /**
     * Check if position is liquidatable
     */
    function isLiquidatable(uint256 positionId) external view returns (bool) {
        MarginPosition storage position = positions[positionId];
        if (position.status == PositionStatus.FULLY_LIQUIDATED) return false;

        uint256 currentLTV = calculateLTV(
            position.collateralToken,
            position.collateralAmount,
            position.debtToken,
            position.debtAmount
        );

        return currentLTV > position.maintenanceMarginRatio;
    }

    /**
     * Get position health factor
     */
    function getHealthFactor(uint256 positionId) external view returns (uint256) {
        MarginPosition storage position = positions[positionId];

        uint256 currentLTV = calculateLTV(
            position.collateralToken,
            position.collateralAmount,
            position.debtToken,
            position.debtAmount
        );

        if (currentLTV == 0) return type(uint256).max;
        return (position.maintenanceMarginRatio * 10000) / currentLTV;
    }

    /**
     * Calculate LTV ratio
     */
    function calculateLTV(
        address collateralToken,
        uint256 collateralAmount,
        address debtToken,
        uint256 debtAmount
    ) public view returns (uint256) {
        if (collateralAmount == 0) return type(uint256).max;

        (uint256 collateralPrice, uint256 collateralTimestamp) = priceFeed.getPrice(collateralToken);
        (uint256 debtPrice, uint256 debtTimestamp) = priceFeed.getPrice(debtToken);

        require(
            block.timestamp - collateralTimestamp <= maxPriceStaleness &&
            block.timestamp - debtTimestamp <= maxPriceStaleness,
            "Stale price"
        );

        uint256 collateralValue = collateralAmount * collateralPrice / 1e18;
        uint256 debtValue = debtAmount * debtPrice / 1e18;

        return (debtValue * 10000) / collateralValue; // basis points
    }

    /**
     * Create market
     */
    function createMarket(
        address collateralToken,
        address debtToken,
        uint256 maxLTV,
        uint256 liquidationThreshold,
        uint256 liquidationPenalty,
        uint256 keeperRewardPercent,
        uint256 insuranceFundPercent,
        uint256 minCollateral,
        uint256 maxCollateral
    ) external onlyRole(OPERATOR_ROLE) {
        require(liquidationThreshold > maxLTV, "Invalid thresholds");
        require(keeperRewardPercent + insuranceFundPercent <= liquidationPenalty, "Invalid penalty split");

        bytes32 marketKey = keccak256(abi.encodePacked(collateralToken, debtToken));
        require(!markets[marketKey].isActive, "Market exists");

        markets[marketKey] = MarketParams({
            collateralToken: collateralToken,
            debtToken: debtToken,
            maxLTV: maxLTV,
            liquidationThreshold: liquidationThreshold,
            liquidationPenalty: liquidationPenalty,
            keeperRewardPercent: keeperRewardPercent,
            insuranceFundPercent: insuranceFundPercent,
            minCollateral: minCollateral,
            maxCollateral: maxCollateral,
            isActive: true
        });

        marketList.push(marketKey);
    }

    /**
     * Update position statuses (batch)
     */
    function updatePositionStatuses(uint256[] calldata positionIds) external {
        for (uint256 i = 0; i < positionIds.length; i++) {
            _updatePositionStatus(positionIds[i]);
        }
    }

    /**
     * Activate emergency mode
     */
    function activateEmergencyMode(string calldata reason) external onlyRole(GUARDIAN_ROLE) {
        emergencyMode = true;
        emit EmergencyModeActivated(reason);
    }

    /**
     * Deactivate emergency mode
     */
    function deactivateEmergencyMode() external onlyRole(GUARDIAN_ROLE) {
        emergencyMode = false;
    }

    /**
     * Pause contract
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * Unpause contract
     */
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /**
     * Get user positions
     */
    function getUserPositions(address user) external view returns (uint256[] memory) {
        return userPositions[user];
    }

    /**
     * Get liquidation details
     */
    function getLiquidationDetails(uint256 liquidationId) external view returns (
        uint256 positionId,
        address liquidator,
        LiquidationType liquidationType,
        uint256 collateralSeized,
        uint256 debtRepaid,
        uint256 timestamp
    ) {
        LiquidationEvent storage liq = liquidations[liquidationId];
        return (
            liq.positionId,
            liq.liquidator,
            liq.liquidationType,
            liq.collateralSeized,
            liq.debtRepaid,
            liq.timestamp
        );
    }

    /**
     * Get keeper statistics
     */
    function getKeeperStats(address keeper) external view returns (
        uint256 totalLiquidations,
        uint256 totalRewards,
        uint256 reputation,
        uint256 stake
    ) {
        Keeper storage k = keepers[keeper];
        return (k.totalLiquidations, k.totalRewards, k.reputation, k.stake);
    }

    /**
     * Internal: Execute liquidation
     */
    function _executeLiquidation(
        uint256 positionId,
        uint256 debtToRepay,
        address liquidator,
        LiquidationType liquidationType
    ) internal returns (uint256) {
        MarginPosition storage position = positions[positionId];

        // Calculate collateral to seize
        bytes32 marketKey = keccak256(abi.encodePacked(position.collateralToken, position.debtToken));
        MarketParams storage market = markets[marketKey];

        (uint256 collateralPrice,) = priceFeed.getPrice(position.collateralToken);
        (uint256 debtPrice,) = priceFeed.getPrice(position.debtToken);

        uint256 debtValue = debtToRepay * debtPrice / 1e18;
        uint256 collateralToSeize = (debtValue * 1e18) / collateralPrice;

        // Add penalty
        uint256 penalty = (collateralToSeize * market.liquidationPenalty) / 10000;
        collateralToSeize += penalty;

        // Ensure we don't seize more than available
        if (collateralToSeize > position.collateralAmount) {
            collateralToSeize = position.collateralAmount;
        }

        // Calculate reward and insurance contribution
        uint256 keeperReward = (penalty * market.keeperRewardPercent) / market.liquidationPenalty;
        uint256 insuranceContribution = (penalty * market.insuranceFundPercent) / market.liquidationPenalty;

        // Transfer debt token from liquidator
        IERC20(position.debtToken).safeTransferFrom(liquidator, address(this), debtToRepay);

        // Transfer collateral to liquidator (minus insurance)
        uint256 liquidatorReceives = collateralToSeize - insuranceContribution;
        IERC20(position.collateralToken).safeTransfer(liquidator, liquidatorReceives);

        // Contribute to insurance fund
        insuranceFund[position.collateralToken] += insuranceContribution;

        // Update position
        position.collateralAmount -= collateralToSeize;
        position.debtAmount -= debtToRepay;
        position.lastUpdateTime = block.timestamp;

        // Update status
        if (position.debtAmount == 0 || position.collateralAmount == 0) {
            position.status = PositionStatus.FULLY_LIQUIDATED;
        } else {
            position.status = PositionStatus.PARTIALLY_LIQUIDATED;
            _updatePositionStatus(positionId);
        }

        // Record liquidation
        liquidationCounter++;
        liquidations[liquidationCounter] = LiquidationEvent({
            liquidationId: liquidationCounter,
            positionId: positionId,
            liquidator: liquidator,
            liquidationType: liquidationType,
            collateralSeized: collateralToSeize,
            debtRepaid: debtToRepay,
            penalty: penalty,
            keeperReward: keeperReward,
            insuranceFundContribution: insuranceContribution,
            timestamp: block.timestamp
        });

        // Update keeper stats
        if (hasRole(KEEPER_ROLE, liquidator)) {
            Keeper storage keeper = keepers[liquidator];
            keeper.totalLiquidations++;
            keeper.totalRewards += keeperReward;
            keeper.lastLiquidationTime = block.timestamp;
            keeper.reputation = _calculateKeeperReputation(liquidator);
        }

        liquidationsPerBlock[block.number]++;

        emit LiquidationExecuted(
            liquidationCounter,
            positionId,
            liquidator,
            liquidationType,
            collateralToSeize,
            debtToRepay
        );

        emit KeeperRewarded(liquidator, keeperReward);
        emit InsuranceFundContribution(position.collateralToken, insuranceContribution);

        return liquidationCounter;
    }

    /**
     * Internal: Update position status
     */
    function _updatePositionStatus(uint256 positionId) internal {
        MarginPosition storage position = positions[positionId];
        if (position.status == PositionStatus.FULLY_LIQUIDATED) return;

        uint256 currentLTV = calculateLTV(
            position.collateralToken,
            position.collateralAmount,
            position.debtToken,
            position.debtAmount
        );

        if (currentLTV > position.maintenanceMarginRatio) {
            position.status = PositionStatus.LIQUIDATABLE;
        } else if (currentLTV > position.maintenanceMarginRatio * 90 / 100) {
            position.status = PositionStatus.WARNING;
        } else {
            position.status = PositionStatus.HEALTHY;
        }
    }

    /**
     * Internal: Calculate keeper reputation
     */
    function _calculateKeeperReputation(address keeperAddress) internal view returns (uint256) {
        Keeper storage keeper = keepers[keeperAddress];

        // Base reputation on successful liquidations and stake
        uint256 liquidationScore = keeper.totalLiquidations * 10;
        uint256 stakeScore = keeper.stake / 1 ether;

        uint256 reputation = 100 + liquidationScore + stakeScore;

        // Cap at 1000
        if (reputation > 1000) reputation = 1000;

        return reputation;
    }
}
