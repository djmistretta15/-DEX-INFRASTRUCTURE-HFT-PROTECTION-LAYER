// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * TOKEN ECONOMICS ENGINE
 *
 * HYPOTHESIS: A well-designed token economics model with vesting schedules,
 * buyback & burn mechanisms, and revenue sharing will create sustainable
 * value accrual with >50% reduction in circulating supply over 5 years.
 *
 * SUCCESS METRICS:
 * - Circulating supply reduction: >50% in 5 years
 * - Token velocity: <0.5
 * - Staking participation: >60%
 * - Revenue to token holders: >50% of protocol fees
 * - Price volatility reduction: 30% YoY
 *
 * SECURITY CONSIDERATIONS:
 * - Vesting cliff enforcement
 * - Anti-manipulation mechanisms
 * - Fair distribution
 * - Inflation controls
 * - Emergency unlock prevention
 */

// Vesting schedule
struct VestingSchedule {
    uint256 id;
    address beneficiary;
    uint256 totalAmount;
    uint256 released;
    uint256 startTime;
    uint256 cliffDuration;
    uint256 vestingDuration;
    uint256 slicePeriod;
    bool revocable;
    bool revoked;
}

// Token distribution
struct TokenDistribution {
    uint256 totalSupply;
    uint256 circulatingSupply;
    uint256 stakedSupply;
    uint256 burnedSupply;
    uint256 treasuryBalance;
    uint256 liquidityReserve;
    uint256 ecosystemFund;
}

// Buyback stats
struct BuybackStats {
    uint256 totalBought;
    uint256 totalBurned;
    uint256 totalSpent;
    uint256 averagePrice;
    uint256 lastBuybackTime;
    uint256 buybackCount;
}

// Inflation schedule
struct InflationSchedule {
    uint256 baseRate; // basis points annually
    uint256 decayRate; // basis points per year
    uint256 minRate; // minimum inflation rate
    uint256 lastMintTime;
    uint256 totalMinted;
}

// Revenue allocation
struct RevenueAllocation {
    uint256 stakersPercent; // basis points
    uint256 buybackPercent;
    uint256 treasuryPercent;
    uint256 liquidityPercent;
    uint256 developmentPercent;
}

contract TokenEconomicsEngine is ReentrancyGuard, AccessControl {
    using SafeERC20 for IERC20;

    // Roles
    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");
    bytes32 public constant VESTING_ADMIN = keccak256("VESTING_ADMIN");
    bytes32 public constant BUYBACK_EXECUTOR = keccak256("BUYBACK_EXECUTOR");

    // Protocol token
    IERC20 public immutable protocolToken;

    // Vesting
    mapping(bytes32 => VestingSchedule) public vestingSchedules;
    mapping(address => uint256) public holdersVestingCount;
    bytes32[] public vestingScheduleIds;
    uint256 public vestingSchedulesTotalAmount;

    // Token distribution
    TokenDistribution public distribution;

    // Buyback & burn
    BuybackStats public buybackStats;
    uint256 public minBuybackInterval = 1 days;
    uint256 public maxBuybackAmount;
    address public buybackPairToken; // e.g., USDC

    // Inflation
    InflationSchedule public inflationSchedule;

    // Revenue allocation
    RevenueAllocation public revenueAllocation;

    // Burn tracking
    uint256 public totalBurned;
    mapping(uint256 => uint256) public monthlyBurns;

    // Staking integration
    address public stakingContract;

    // Liquidity pool
    address public liquidityPool;

    // Treasury
    address public treasury;

    // Events
    event VestingScheduleCreated(
        bytes32 indexed scheduleId,
        address indexed beneficiary,
        uint256 amount,
        uint256 startTime,
        uint256 cliffDuration,
        uint256 vestingDuration
    );

    event TokensReleased(
        bytes32 indexed scheduleId,
        address indexed beneficiary,
        uint256 amount
    );

    event VestingRevoked(bytes32 indexed scheduleId, uint256 amountRecovered);

    event TokensBurned(address indexed burner, uint256 amount, string reason);

    event BuybackExecuted(
        uint256 amount,
        uint256 price,
        uint256 burned
    );

    event RevenueDistributed(
        uint256 toStakers,
        uint256 toBuyback,
        uint256 toTreasury,
        uint256 toLiquidity,
        uint256 toDevelopment
    );

    event InflationMinted(uint256 amount, address recipient);

    event AllocationUpdated(
        uint256 stakersPercent,
        uint256 buybackPercent,
        uint256 treasuryPercent,
        uint256 liquidityPercent,
        uint256 developmentPercent
    );

    constructor(
        address _protocolToken,
        address _treasury,
        uint256 _totalSupply
    ) {
        protocolToken = IERC20(_protocolToken);
        treasury = _treasury;

        // Initialize distribution
        distribution = TokenDistribution({
            totalSupply: _totalSupply,
            circulatingSupply: 0,
            stakedSupply: 0,
            burnedSupply: 0,
            treasuryBalance: 0,
            liquidityReserve: 0,
            ecosystemFund: 0
        });

        // Default revenue allocation
        revenueAllocation = RevenueAllocation({
            stakersPercent: 4000, // 40%
            buybackPercent: 3000, // 30%
            treasuryPercent: 1500, // 15%
            liquidityPercent: 1000, // 10%
            developmentPercent: 500 // 5%
        });

        // Initialize inflation (starting at 5%, decaying 1% per year)
        inflationSchedule = InflationSchedule({
            baseRate: 500, // 5% annually
            decayRate: 100, // -1% per year
            minRate: 100, // 1% minimum
            lastMintTime: block.timestamp,
            totalMinted: 0
        });

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(TREASURY_ROLE, msg.sender);
        _grantRole(VESTING_ADMIN, msg.sender);
        _grantRole(BUYBACK_EXECUTOR, msg.sender);
    }

    /**
     * Create vesting schedule
     */
    function createVestingSchedule(
        address beneficiary,
        uint256 amount,
        uint256 startTime,
        uint256 cliffDuration,
        uint256 vestingDuration,
        uint256 slicePeriod,
        bool revocable
    ) external onlyRole(VESTING_ADMIN) returns (bytes32) {
        require(beneficiary != address(0), "Invalid beneficiary");
        require(amount > 0, "Invalid amount");
        require(vestingDuration > 0, "Invalid duration");
        require(slicePeriod >= 1, "Invalid slice period");
        require(vestingDuration >= cliffDuration, "Cliff > vesting");

        // Transfer tokens to this contract
        protocolToken.safeTransferFrom(msg.sender, address(this), amount);

        bytes32 scheduleId = computeVestingScheduleId(
            beneficiary,
            holdersVestingCount[beneficiary]
        );

        vestingSchedules[scheduleId] = VestingSchedule({
            id: uint256(scheduleId),
            beneficiary: beneficiary,
            totalAmount: amount,
            released: 0,
            startTime: startTime == 0 ? block.timestamp : startTime,
            cliffDuration: cliffDuration,
            vestingDuration: vestingDuration,
            slicePeriod: slicePeriod,
            revocable: revocable,
            revoked: false
        });

        vestingSchedulesTotalAmount += amount;
        vestingScheduleIds.push(scheduleId);
        holdersVestingCount[beneficiary]++;

        emit VestingScheduleCreated(
            scheduleId,
            beneficiary,
            amount,
            startTime,
            cliffDuration,
            vestingDuration
        );

        return scheduleId;
    }

    /**
     * Release vested tokens
     */
    function release(bytes32 scheduleId) external nonReentrant {
        VestingSchedule storage schedule = vestingSchedules[scheduleId];
        require(!schedule.revoked, "Vesting revoked");

        uint256 releasable = computeReleasableAmount(schedule);
        require(releasable > 0, "Nothing to release");

        schedule.released += releasable;
        vestingSchedulesTotalAmount -= releasable;

        protocolToken.safeTransfer(schedule.beneficiary, releasable);

        // Update circulating supply
        distribution.circulatingSupply += releasable;

        emit TokensReleased(scheduleId, schedule.beneficiary, releasable);
    }

    /**
     * Revoke vesting schedule
     */
    function revoke(bytes32 scheduleId) external onlyRole(VESTING_ADMIN) {
        VestingSchedule storage schedule = vestingSchedules[scheduleId];
        require(schedule.revocable, "Not revocable");
        require(!schedule.revoked, "Already revoked");

        uint256 releasable = computeReleasableAmount(schedule);
        uint256 refund = schedule.totalAmount - schedule.released - releasable;

        schedule.revoked = true;
        vestingSchedulesTotalAmount -= refund;

        // Release any vested amount to beneficiary
        if (releasable > 0) {
            schedule.released += releasable;
            protocolToken.safeTransfer(schedule.beneficiary, releasable);
        }

        // Return unvested to treasury
        if (refund > 0) {
            protocolToken.safeTransfer(treasury, refund);
        }

        emit VestingRevoked(scheduleId, refund);
    }

    /**
     * Execute buyback and burn
     */
    function executeBuyback(
        uint256 spendAmount,
        uint256 minTokensReceived
    ) external nonReentrant onlyRole(BUYBACK_EXECUTOR) returns (uint256) {
        require(
            block.timestamp >= buybackStats.lastBuybackTime + minBuybackInterval,
            "Too soon"
        );
        require(spendAmount <= maxBuybackAmount, "Exceeds max buyback");

        // In production: integrate with DEX to buy tokens
        // Simplified: assume 1:1 for demonstration
        uint256 tokensReceived = spendAmount;
        require(tokensReceived >= minTokensReceived, "Slippage too high");

        // Burn the tokens
        _burn(tokensReceived, "Buyback and Burn");

        // Update stats
        buybackStats.totalBought += tokensReceived;
        buybackStats.totalBurned += tokensReceived;
        buybackStats.totalSpent += spendAmount;
        buybackStats.lastBuybackTime = block.timestamp;
        buybackStats.buybackCount++;

        // Update average price
        if (buybackStats.buybackCount == 1) {
            buybackStats.averagePrice = spendAmount * 1e18 / tokensReceived;
        } else {
            buybackStats.averagePrice = (buybackStats.totalSpent * 1e18) /
                                        buybackStats.totalBought;
        }

        emit BuybackExecuted(tokensReceived, spendAmount * 1e18 / tokensReceived, tokensReceived);

        return tokensReceived;
    }

    /**
     * Distribute protocol revenue
     */
    function distributeRevenue(uint256 amount) external nonReentrant onlyRole(TREASURY_ROLE) {
        require(amount > 0, "Zero amount");

        uint256 toStakers = (amount * revenueAllocation.stakersPercent) / 10000;
        uint256 toBuyback = (amount * revenueAllocation.buybackPercent) / 10000;
        uint256 toTreasury = (amount * revenueAllocation.treasuryPercent) / 10000;
        uint256 toLiquidity = (amount * revenueAllocation.liquidityPercent) / 10000;
        uint256 toDevelopment = amount - toStakers - toBuyback - toTreasury - toLiquidity;

        // Transfer allocations
        if (toStakers > 0 && stakingContract != address(0)) {
            protocolToken.safeTransfer(stakingContract, toStakers);
        }

        if (toTreasury > 0) {
            distribution.treasuryBalance += toTreasury;
            protocolToken.safeTransfer(treasury, toTreasury);
        }

        if (toLiquidity > 0 && liquidityPool != address(0)) {
            distribution.liquidityReserve += toLiquidity;
            protocolToken.safeTransfer(liquidityPool, toLiquidity);
        }

        emit RevenueDistributed(toStakers, toBuyback, toTreasury, toLiquidity, toDevelopment);
    }

    /**
     * Mint inflation (annual)
     */
    function mintInflation() external onlyRole(TREASURY_ROLE) {
        require(
            block.timestamp >= inflationSchedule.lastMintTime + 365 days,
            "Too soon"
        );

        // Calculate current inflation rate
        uint256 yearsElapsed = (block.timestamp - inflationSchedule.lastMintTime) / 365 days;
        uint256 currentRate = inflationSchedule.baseRate;

        if (yearsElapsed > 0) {
            uint256 decay = yearsElapsed * inflationSchedule.decayRate;
            if (decay >= currentRate - inflationSchedule.minRate) {
                currentRate = inflationSchedule.minRate;
            } else {
                currentRate -= decay;
            }
        }

        // Calculate mint amount
        uint256 mintAmount = (distribution.totalSupply * currentRate) / 10000;

        // Update state
        distribution.totalSupply += mintAmount;
        inflationSchedule.lastMintTime = block.timestamp;
        inflationSchedule.totalMinted += mintAmount;

        // In production: mint tokens through ERC20Mintable
        // Here we assume tokens are pre-allocated

        emit InflationMinted(mintAmount, treasury);
    }

    /**
     * Burn tokens
     */
    function burn(uint256 amount, string memory reason) external {
        protocolToken.safeTransferFrom(msg.sender, address(this), amount);
        _burn(amount, reason);
    }

    /**
     * Get vesting schedule info
     */
    function getVestingSchedule(bytes32 scheduleId) external view returns (
        address beneficiary,
        uint256 totalAmount,
        uint256 released,
        uint256 releasable,
        uint256 startTime,
        uint256 cliffEnd,
        uint256 vestingEnd,
        bool revoked
    ) {
        VestingSchedule storage schedule = vestingSchedules[scheduleId];

        return (
            schedule.beneficiary,
            schedule.totalAmount,
            schedule.released,
            computeReleasableAmount(schedule),
            schedule.startTime,
            schedule.startTime + schedule.cliffDuration,
            schedule.startTime + schedule.vestingDuration,
            schedule.revoked
        );
    }

    /**
     * Get circulating supply
     */
    function getCirculatingSupply() external view returns (uint256) {
        return distribution.totalSupply -
               distribution.burnedSupply -
               distribution.treasuryBalance -
               vestingSchedulesTotalAmount;
    }

    /**
     * Get token metrics
     */
    function getTokenMetrics() external view returns (
        uint256 totalSupply,
        uint256 circulatingSupply,
        uint256 burnedSupply,
        uint256 vestingLocked,
        uint256 inflationRate
    ) {
        return (
            distribution.totalSupply,
            distribution.circulatingSupply,
            distribution.burnedSupply,
            vestingSchedulesTotalAmount,
            _getCurrentInflationRate()
        );
    }

    /**
     * Update revenue allocation
     */
    function updateRevenueAllocation(
        uint256 stakersPercent,
        uint256 buybackPercent,
        uint256 treasuryPercent,
        uint256 liquidityPercent,
        uint256 developmentPercent
    ) external onlyRole(TREASURY_ROLE) {
        require(
            stakersPercent + buybackPercent + treasuryPercent +
            liquidityPercent + developmentPercent == 10000,
            "Must sum to 100%"
        );

        revenueAllocation = RevenueAllocation({
            stakersPercent: stakersPercent,
            buybackPercent: buybackPercent,
            treasuryPercent: treasuryPercent,
            liquidityPercent: liquidityPercent,
            developmentPercent: developmentPercent
        });

        emit AllocationUpdated(
            stakersPercent,
            buybackPercent,
            treasuryPercent,
            liquidityPercent,
            developmentPercent
        );
    }

    /**
     * Set staking contract
     */
    function setStakingContract(address _stakingContract) external onlyRole(DEFAULT_ADMIN_ROLE) {
        stakingContract = _stakingContract;
    }

    /**
     * Set liquidity pool
     */
    function setLiquidityPool(address _liquidityPool) external onlyRole(DEFAULT_ADMIN_ROLE) {
        liquidityPool = _liquidityPool;
    }

    /**
     * Update max buyback amount
     */
    function setMaxBuybackAmount(uint256 amount) external onlyRole(TREASURY_ROLE) {
        maxBuybackAmount = amount;
    }

    /**
     * Internal: Compute releasable amount
     */
    function computeReleasableAmount(VestingSchedule storage schedule) internal view returns (uint256) {
        if (schedule.revoked) return 0;

        uint256 currentTime = block.timestamp;

        // Before cliff
        if (currentTime < schedule.startTime + schedule.cliffDuration) {
            return 0;
        }

        // After vesting end
        if (currentTime >= schedule.startTime + schedule.vestingDuration) {
            return schedule.totalAmount - schedule.released;
        }

        // During vesting
        uint256 timeFromStart = currentTime - schedule.startTime;
        uint256 secondsPerSlice = schedule.slicePeriod;
        uint256 vestedSlicePeriods = timeFromStart / secondsPerSlice;
        uint256 vestedSeconds = vestedSlicePeriods * secondsPerSlice;

        uint256 vestedAmount = (schedule.totalAmount * vestedSeconds) /
                               schedule.vestingDuration;

        return vestedAmount - schedule.released;
    }

    /**
     * Internal: Compute vesting schedule ID
     */
    function computeVestingScheduleId(address beneficiary, uint256 index) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(beneficiary, index));
    }

    /**
     * Internal: Burn tokens
     */
    function _burn(uint256 amount, string memory reason) internal {
        // Send to dead address or call burn function
        // Simplified: track as burned
        totalBurned += amount;
        distribution.burnedSupply += amount;

        // Track monthly burns
        uint256 month = block.timestamp / 30 days;
        monthlyBurns[month] += amount;

        emit TokensBurned(msg.sender, amount, reason);
    }

    /**
     * Internal: Get current inflation rate
     */
    function _getCurrentInflationRate() internal view returns (uint256) {
        uint256 yearsElapsed = (block.timestamp - inflationSchedule.lastMintTime) / 365 days;
        uint256 decay = yearsElapsed * inflationSchedule.decayRate;

        if (decay >= inflationSchedule.baseRate - inflationSchedule.minRate) {
            return inflationSchedule.minRate;
        }

        return inflationSchedule.baseRate - decay;
    }
}
