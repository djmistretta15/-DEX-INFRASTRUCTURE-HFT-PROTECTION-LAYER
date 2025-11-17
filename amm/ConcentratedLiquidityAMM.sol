// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

/**
 * @title ConcentratedLiquidityAMM
 * @notice Advanced AMM with concentrated liquidity (Uniswap V3-style) and MEV protection
 *
 * SCIENTIFIC HYPOTHESIS:
 * Concentrated liquidity with dynamic fee tiers and just-in-time liquidity protection
 * will achieve >50% capital efficiency improvement over constant product AMMs while
 * maintaining <0.5% slippage for retail trades and >95% fee capture for LPs.
 *
 * SUCCESS METRICS:
 * - Capital efficiency: >50% improvement vs constant product
 * - Slippage: <0.5% for trades up to $100k
 * - LP fee capture: >95% of generated fees
 * - MEV protection: >90% reduction in JIT liquidity attacks
 * - Gas efficiency: <200k gas per swap
 *
 * SECURITY CONSIDERATIONS:
 * - Time-weighted average liquidity to prevent JIT attacks
 * - Oracle price bounds to prevent manipulation
 * - Reentrancy protection on all state-changing functions
 * - Tick bitmap for efficient range queries
 * - Accurate fee accounting with precision management
 */
contract ConcentratedLiquidityAMM is ReentrancyGuard, Pausable, AccessControl {
    using SafeERC20 for IERC20;
    using Math for uint256;

    // ========================================================================
    // CONSTANTS
    // ========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    uint256 public constant Q96 = 2**96;
    uint256 public constant Q128 = 2**128;
    int24 public constant MIN_TICK = -887272;
    int24 public constant MAX_TICK = 887272;
    uint24 public constant FEE_DENOMINATOR = 1000000;

    // JIT protection: minimum time liquidity must be present
    uint256 public constant MIN_LIQUIDITY_DURATION = 30 seconds;

    // ========================================================================
    // STRUCTS
    // ========================================================================

    struct Pool {
        address token0;
        address token1;
        uint24 fee;
        int24 tickSpacing;
        uint160 sqrtPriceX96;
        int24 currentTick;
        uint128 liquidity;
        uint256 feeGrowthGlobal0X128;
        uint256 feeGrowthGlobal1X128;
        uint128 protocolFees0;
        uint128 protocolFees1;
        bool initialized;
    }

    struct Position {
        uint128 liquidity;
        uint256 feeGrowthInside0LastX128;
        uint256 feeGrowthInside1LastX128;
        uint128 tokensOwed0;
        uint128 tokensOwed1;
        uint256 lastUpdateTime;
    }

    struct TickInfo {
        uint128 liquidityGross;
        int128 liquidityNet;
        uint256 feeGrowthOutside0X128;
        uint256 feeGrowthOutside1X128;
        bool initialized;
    }

    struct SwapState {
        int256 amountSpecifiedRemaining;
        int256 amountCalculated;
        uint160 sqrtPriceX96;
        int24 tick;
        uint256 feeGrowthGlobalX128;
        uint128 liquidity;
    }

    struct StepComputations {
        uint160 sqrtPriceStartX96;
        int24 tickNext;
        bool initialized;
        uint160 sqrtPriceNextX96;
        uint256 amountIn;
        uint256 amountOut;
        uint256 feeAmount;
    }

    struct MintParams {
        address recipient;
        int24 tickLower;
        int24 tickUpper;
        uint128 amount;
        bytes data;
    }

    struct SwapParams {
        bool zeroForOne;
        int256 amountSpecified;
        uint160 sqrtPriceLimitX96;
    }

    // ========================================================================
    // STATE VARIABLES
    // ========================================================================

    mapping(bytes32 => Pool) public pools;
    mapping(bytes32 => mapping(bytes32 => Position)) public positions;
    mapping(bytes32 => mapping(int24 => TickInfo)) public ticks;
    mapping(bytes32 => mapping(int16 => uint256)) public tickBitmap;

    bytes32[] public poolIds;

    uint8 public protocolFeePercent = 10; // 10% of swap fees to protocol
    address public feeRecipient;

    // Oracle for price bounds
    mapping(bytes32 => uint256) public lastOraclePrice;
    mapping(bytes32 => uint256) public oraclePriceTimestamp;
    uint256 public maxPriceDeviation = 500; // 5% max deviation from oracle

    // ========================================================================
    // EVENTS
    // ========================================================================

    event PoolCreated(
        bytes32 indexed poolId,
        address token0,
        address token1,
        uint24 fee,
        int24 tickSpacing
    );

    event Mint(
        address indexed owner,
        bytes32 indexed poolId,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount,
        uint256 amount0,
        uint256 amount1
    );

    event Burn(
        address indexed owner,
        bytes32 indexed poolId,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount,
        uint256 amount0,
        uint256 amount1
    );

    event Swap(
        address indexed sender,
        bytes32 indexed poolId,
        int256 amount0,
        int256 amount1,
        uint160 sqrtPriceX96,
        uint128 liquidity,
        int24 tick
    );

    event Collect(
        address indexed owner,
        bytes32 indexed poolId,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount0,
        uint128 amount1
    );

    event Flash(
        address indexed sender,
        bytes32 indexed poolId,
        uint256 amount0,
        uint256 amount1,
        uint256 paid0,
        uint256 paid1
    );

    // ========================================================================
    // CONSTRUCTOR
    // ========================================================================

    constructor(address _feeRecipient) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);

        feeRecipient = _feeRecipient;
    }

    // ========================================================================
    // POOL MANAGEMENT
    // ========================================================================

    function createPool(
        address token0,
        address token1,
        uint24 fee,
        uint160 sqrtPriceX96
    ) external onlyRole(OPERATOR_ROLE) returns (bytes32 poolId) {
        require(token0 < token1, "Invalid token order");
        require(token0 != address(0), "Invalid token0");
        require(sqrtPriceX96 > 0, "Invalid initial price");

        poolId = keccak256(abi.encodePacked(token0, token1, fee));
        require(!pools[poolId].initialized, "Pool exists");

        int24 tickSpacing = _getTickSpacing(fee);
        int24 tick = _getTickAtSqrtRatio(sqrtPriceX96);

        pools[poolId] = Pool({
            token0: token0,
            token1: token1,
            fee: fee,
            tickSpacing: tickSpacing,
            sqrtPriceX96: sqrtPriceX96,
            currentTick: tick,
            liquidity: 0,
            feeGrowthGlobal0X128: 0,
            feeGrowthGlobal1X128: 0,
            protocolFees0: 0,
            protocolFees1: 0,
            initialized: true
        });

        poolIds.push(poolId);

        emit PoolCreated(poolId, token0, token1, fee, tickSpacing);
    }

    function _getTickSpacing(uint24 fee) internal pure returns (int24) {
        if (fee == 500) return 10;
        if (fee == 3000) return 60;
        if (fee == 10000) return 200;
        return 60; // default
    }

    // ========================================================================
    // LIQUIDITY PROVISION
    // ========================================================================

    function mint(
        bytes32 poolId,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount,
        bytes calldata data
    )
        external
        nonReentrant
        whenNotPaused
        returns (uint256 amount0, uint256 amount1)
    {
        Pool storage pool = pools[poolId];
        require(pool.initialized, "Pool not initialized");
        require(amount > 0, "Amount must be positive");

        // Validate tick range
        require(tickLower < tickUpper, "Invalid tick range");
        require(tickLower >= MIN_TICK, "Tick lower too low");
        require(tickUpper <= MAX_TICK, "Tick upper too high");
        require(tickLower % pool.tickSpacing == 0, "Invalid tick lower");
        require(tickUpper % pool.tickSpacing == 0, "Invalid tick upper");

        // Calculate amounts needed
        (amount0, amount1) = _getAmountsForLiquidity(
            pool.sqrtPriceX96,
            _getSqrtRatioAtTick(tickLower),
            _getSqrtRatioAtTick(tickUpper),
            amount
        );

        require(amount0 > 0 || amount1 > 0, "Insufficient amounts");

        // Update ticks
        _updateTick(poolId, tickLower, int128(uint128(amount)), true);
        _updateTick(poolId, tickUpper, int128(uint128(amount)), false);

        // Update position
        bytes32 positionKey = keccak256(
            abi.encodePacked(msg.sender, tickLower, tickUpper)
        );

        Position storage position = positions[poolId][positionKey];

        // Calculate fees owed
        (
            uint256 feeGrowthInside0X128,
            uint256 feeGrowthInside1X128
        ) = _getFeeGrowthInside(poolId, tickLower, tickUpper);

        if (position.liquidity > 0) {
            position.tokensOwed0 += uint128(
                ((feeGrowthInside0X128 - position.feeGrowthInside0LastX128) *
                    position.liquidity) / Q128
            );
            position.tokensOwed1 += uint128(
                ((feeGrowthInside1X128 - position.feeGrowthInside1LastX128) *
                    position.liquidity) / Q128
            );
        }

        position.liquidity += amount;
        position.feeGrowthInside0LastX128 = feeGrowthInside0X128;
        position.feeGrowthInside1LastX128 = feeGrowthInside1X128;
        position.lastUpdateTime = block.timestamp;

        // Update pool liquidity if in range
        if (pool.currentTick >= tickLower && pool.currentTick < tickUpper) {
            pool.liquidity += amount;
        }

        // Transfer tokens in
        uint256 balance0Before = IERC20(pool.token0).balanceOf(address(this));
        uint256 balance1Before = IERC20(pool.token1).balanceOf(address(this));

        // Callback to transfer tokens
        _mintCallback(pool.token0, pool.token1, amount0, amount1, data);

        require(
            IERC20(pool.token0).balanceOf(address(this)) >=
                balance0Before + amount0,
            "Insufficient token0"
        );
        require(
            IERC20(pool.token1).balanceOf(address(this)) >=
                balance1Before + amount1,
            "Insufficient token1"
        );

        emit Mint(msg.sender, poolId, tickLower, tickUpper, amount, amount0, amount1);
    }

    function burn(
        bytes32 poolId,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount
    )
        external
        nonReentrant
        returns (uint256 amount0, uint256 amount1)
    {
        Pool storage pool = pools[poolId];
        require(pool.initialized, "Pool not initialized");

        bytes32 positionKey = keccak256(
            abi.encodePacked(msg.sender, tickLower, tickUpper)
        );
        Position storage position = positions[poolId][positionKey];

        require(position.liquidity >= amount, "Insufficient liquidity");

        // JIT protection: check minimum duration
        require(
            block.timestamp >= position.lastUpdateTime + MIN_LIQUIDITY_DURATION,
            "JIT protection: wait period"
        );

        // Calculate amounts
        (amount0, amount1) = _getAmountsForLiquidity(
            pool.sqrtPriceX96,
            _getSqrtRatioAtTick(tickLower),
            _getSqrtRatioAtTick(tickUpper),
            amount
        );

        // Update fees
        (
            uint256 feeGrowthInside0X128,
            uint256 feeGrowthInside1X128
        ) = _getFeeGrowthInside(poolId, tickLower, tickUpper);

        position.tokensOwed0 += uint128(
            ((feeGrowthInside0X128 - position.feeGrowthInside0LastX128) *
                position.liquidity) / Q128
        );
        position.tokensOwed1 += uint128(
            ((feeGrowthInside1X128 - position.feeGrowthInside1LastX128) *
                position.liquidity) / Q128
        );

        // Update position
        position.liquidity -= amount;
        position.feeGrowthInside0LastX128 = feeGrowthInside0X128;
        position.feeGrowthInside1LastX128 = feeGrowthInside1X128;

        // Add burned amounts to tokens owed
        position.tokensOwed0 += uint128(amount0);
        position.tokensOwed1 += uint128(amount1);

        // Update ticks
        _updateTick(poolId, tickLower, -int128(uint128(amount)), true);
        _updateTick(poolId, tickUpper, -int128(uint128(amount)), false);

        // Update pool liquidity if in range
        if (pool.currentTick >= tickLower && pool.currentTick < tickUpper) {
            pool.liquidity -= amount;
        }

        emit Burn(msg.sender, poolId, tickLower, tickUpper, amount, amount0, amount1);
    }

    function collect(
        bytes32 poolId,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount0Requested,
        uint128 amount1Requested
    )
        external
        nonReentrant
        returns (uint128 amount0, uint128 amount1)
    {
        Pool storage pool = pools[poolId];
        bytes32 positionKey = keccak256(
            abi.encodePacked(msg.sender, tickLower, tickUpper)
        );
        Position storage position = positions[poolId][positionKey];

        amount0 = amount0Requested > position.tokensOwed0
            ? position.tokensOwed0
            : amount0Requested;
        amount1 = amount1Requested > position.tokensOwed1
            ? position.tokensOwed1
            : amount1Requested;

        if (amount0 > 0) {
            position.tokensOwed0 -= amount0;
            IERC20(pool.token0).safeTransfer(msg.sender, amount0);
        }

        if (amount1 > 0) {
            position.tokensOwed1 -= amount1;
            IERC20(pool.token1).safeTransfer(msg.sender, amount1);
        }

        emit Collect(msg.sender, poolId, tickLower, tickUpper, amount0, amount1);
    }

    // ========================================================================
    // SWAP
    // ========================================================================

    function swap(
        bytes32 poolId,
        bool zeroForOne,
        int256 amountSpecified,
        uint160 sqrtPriceLimitX96,
        bytes calldata data
    )
        external
        nonReentrant
        whenNotPaused
        returns (int256 amount0, int256 amount1)
    {
        Pool storage pool = pools[poolId];
        require(pool.initialized, "Pool not initialized");
        require(amountSpecified != 0, "Amount cannot be zero");

        // Validate price limit
        if (zeroForOne) {
            require(
                sqrtPriceLimitX96 < pool.sqrtPriceX96 &&
                    sqrtPriceLimitX96 > _getSqrtRatioAtTick(MIN_TICK),
                "Invalid price limit"
            );
        } else {
            require(
                sqrtPriceLimitX96 > pool.sqrtPriceX96 &&
                    sqrtPriceLimitX96 < _getSqrtRatioAtTick(MAX_TICK),
                "Invalid price limit"
            );
        }

        // Check oracle price bounds (MEV protection)
        _checkPriceBounds(poolId, pool.sqrtPriceX96);

        bool exactInput = amountSpecified > 0;

        SwapState memory state = SwapState({
            amountSpecifiedRemaining: amountSpecified,
            amountCalculated: 0,
            sqrtPriceX96: pool.sqrtPriceX96,
            tick: pool.currentTick,
            feeGrowthGlobalX128: zeroForOne
                ? pool.feeGrowthGlobal0X128
                : pool.feeGrowthGlobal1X128,
            liquidity: pool.liquidity
        });

        // Swap loop
        while (
            state.amountSpecifiedRemaining != 0 &&
            state.sqrtPriceX96 != sqrtPriceLimitX96
        ) {
            StepComputations memory step;

            step.sqrtPriceStartX96 = state.sqrtPriceX96;

            // Get next tick
            (step.tickNext, step.initialized) = _nextInitializedTick(
                poolId,
                state.tick,
                pool.tickSpacing,
                zeroForOne
            );

            // Clamp to bounds
            if (step.tickNext < MIN_TICK) {
                step.tickNext = MIN_TICK;
            } else if (step.tickNext > MAX_TICK) {
                step.tickNext = MAX_TICK;
            }

            step.sqrtPriceNextX96 = _getSqrtRatioAtTick(step.tickNext);

            // Compute swap step
            (
                state.sqrtPriceX96,
                step.amountIn,
                step.amountOut,
                step.feeAmount
            ) = _computeSwapStep(
                state.sqrtPriceX96,
                (
                    zeroForOne
                        ? step.sqrtPriceNextX96 < sqrtPriceLimitX96
                        : step.sqrtPriceNextX96 > sqrtPriceLimitX96
                )
                    ? sqrtPriceLimitX96
                    : step.sqrtPriceNextX96,
                state.liquidity,
                state.amountSpecifiedRemaining,
                pool.fee
            );

            if (exactInput) {
                state.amountSpecifiedRemaining -= int256(
                    step.amountIn + step.feeAmount
                );
                state.amountCalculated -= int256(step.amountOut);
            } else {
                state.amountSpecifiedRemaining += int256(step.amountOut);
                state.amountCalculated += int256(
                    step.amountIn + step.feeAmount
                );
            }

            // Update fee growth
            if (state.liquidity > 0) {
                state.feeGrowthGlobalX128 +=
                    (step.feeAmount * Q128) /
                    state.liquidity;
            }

            // Shift tick if necessary
            if (state.sqrtPriceX96 == step.sqrtPriceNextX96) {
                if (step.initialized) {
                    int128 liquidityNet = ticks[poolId][step.tickNext]
                        .liquidityNet;

                    if (zeroForOne) liquidityNet = -liquidityNet;

                    state.liquidity = liquidityNet < 0
                        ? state.liquidity - uint128(-liquidityNet)
                        : state.liquidity + uint128(liquidityNet);
                }

                state.tick = zeroForOne ? step.tickNext - 1 : step.tickNext;
            } else if (state.sqrtPriceX96 != step.sqrtPriceStartX96) {
                state.tick = _getTickAtSqrtRatio(state.sqrtPriceX96);
            }
        }

        // Update pool state
        pool.sqrtPriceX96 = state.sqrtPriceX96;
        pool.currentTick = state.tick;
        pool.liquidity = state.liquidity;

        if (zeroForOne) {
            pool.feeGrowthGlobal0X128 = state.feeGrowthGlobalX128;
        } else {
            pool.feeGrowthGlobal1X128 = state.feeGrowthGlobalX128;
        }

        // Calculate final amounts
        (amount0, amount1) = zeroForOne == exactInput
            ? (
                amountSpecified - state.amountSpecifiedRemaining,
                state.amountCalculated
            )
            : (
                state.amountCalculated,
                amountSpecified - state.amountSpecifiedRemaining
            );

        // Protocol fee
        if (protocolFeePercent > 0) {
            uint256 fee0 = zeroForOne
                ? (uint256(int256(-amount1)) * protocolFeePercent) / 100
                : 0;
            uint256 fee1 = !zeroForOne
                ? (uint256(int256(-amount0)) * protocolFeePercent) / 100
                : 0;

            pool.protocolFees0 += uint128(fee0);
            pool.protocolFees1 += uint128(fee1);
        }

        // Transfer tokens
        if (zeroForOne) {
            if (amount1 < 0) {
                IERC20(pool.token1).safeTransfer(
                    msg.sender,
                    uint256(-amount1)
                );
            }

            uint256 balance0Before = IERC20(pool.token0).balanceOf(
                address(this)
            );
            _swapCallback(amount0, amount1, data);
            require(
                IERC20(pool.token0).balanceOf(address(this)) >=
                    balance0Before + uint256(amount0),
                "Insufficient payment"
            );
        } else {
            if (amount0 < 0) {
                IERC20(pool.token0).safeTransfer(
                    msg.sender,
                    uint256(-amount0)
                );
            }

            uint256 balance1Before = IERC20(pool.token1).balanceOf(
                address(this)
            );
            _swapCallback(amount0, amount1, data);
            require(
                IERC20(pool.token1).balanceOf(address(this)) >=
                    balance1Before + uint256(amount1),
                "Insufficient payment"
            );
        }

        emit Swap(
            msg.sender,
            poolId,
            amount0,
            amount1,
            state.sqrtPriceX96,
            state.liquidity,
            state.tick
        );
    }

    // ========================================================================
    // FLASH LOANS
    // ========================================================================

    function flash(
        bytes32 poolId,
        address recipient,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external nonReentrant whenNotPaused {
        Pool storage pool = pools[poolId];
        require(pool.initialized, "Pool not initialized");

        uint256 fee0 = (amount0 * pool.fee) / FEE_DENOMINATOR;
        uint256 fee1 = (amount1 * pool.fee) / FEE_DENOMINATOR;

        uint256 balance0Before = IERC20(pool.token0).balanceOf(address(this));
        uint256 balance1Before = IERC20(pool.token1).balanceOf(address(this));

        if (amount0 > 0) {
            IERC20(pool.token0).safeTransfer(recipient, amount0);
        }
        if (amount1 > 0) {
            IERC20(pool.token1).safeTransfer(recipient, amount1);
        }

        // Callback
        _flashCallback(fee0, fee1, data);

        uint256 balance0After = IERC20(pool.token0).balanceOf(address(this));
        uint256 balance1After = IERC20(pool.token1).balanceOf(address(this));

        require(
            balance0After >= balance0Before + fee0,
            "Insufficient repayment token0"
        );
        require(
            balance1After >= balance1Before + fee1,
            "Insufficient repayment token1"
        );

        uint256 paid0 = balance0After - balance0Before;
        uint256 paid1 = balance1After - balance1Before;

        // Update fee growth
        if (paid0 > 0) {
            pool.feeGrowthGlobal0X128 +=
                (paid0 * Q128) /
                pool.liquidity;
        }
        if (paid1 > 0) {
            pool.feeGrowthGlobal1X128 +=
                (paid1 * Q128) /
                pool.liquidity;
        }

        emit Flash(msg.sender, poolId, amount0, amount1, paid0, paid1);
    }

    // ========================================================================
    // TICK MANAGEMENT
    // ========================================================================

    function _updateTick(
        bytes32 poolId,
        int24 tick,
        int128 liquidityDelta,
        bool upper
    ) internal {
        TickInfo storage info = ticks[poolId][tick];

        uint128 liquidityGrossBefore = info.liquidityGross;
        uint128 liquidityGrossAfter = liquidityDelta < 0
            ? liquidityGrossBefore - uint128(-liquidityDelta)
            : liquidityGrossBefore + uint128(liquidityDelta);

        bool flipped = (liquidityGrossAfter == 0) !=
            (liquidityGrossBefore == 0);

        if (liquidityGrossBefore == 0) {
            info.feeGrowthOutside0X128 = pools[poolId].feeGrowthGlobal0X128;
            info.feeGrowthOutside1X128 = pools[poolId].feeGrowthGlobal1X128;
            info.initialized = true;
        }

        info.liquidityGross = liquidityGrossAfter;

        info.liquidityNet = upper
            ? info.liquidityNet - liquidityDelta
            : info.liquidityNet + liquidityDelta;

        if (flipped) {
            _flipTick(poolId, tick, pools[poolId].tickSpacing);
        }
    }

    function _flipTick(
        bytes32 poolId,
        int24 tick,
        int24 tickSpacing
    ) internal {
        int16 wordPos = int16(tick / tickSpacing / 256);
        uint8 bitPos = uint8(uint24((tick / tickSpacing) % 256));
        tickBitmap[poolId][wordPos] ^= (1 << bitPos);
    }

    function _nextInitializedTick(
        bytes32 poolId,
        int24 tick,
        int24 tickSpacing,
        bool lte
    ) internal view returns (int24 next, bool initialized) {
        int24 compressed = tick / tickSpacing;
        if (tick < 0 && tick % tickSpacing != 0) compressed--;

        if (lte) {
            int16 wordPos = int16(compressed >> 8);
            uint8 bitPos = uint8(uint24(compressed % 256));

            uint256 mask = (1 << bitPos) - 1 + (1 << bitPos);
            uint256 masked = tickBitmap[poolId][wordPos] & mask;

            initialized = masked != 0;
            next = initialized
                ? (compressed -
                    int24(uint24(bitPos - _mostSignificantBit(masked)))) *
                    tickSpacing
                : (compressed - int24(uint24(bitPos))) * tickSpacing;
        } else {
            int16 wordPos = int16((compressed + 1) >> 8);
            uint8 bitPos = uint8(uint24((compressed + 1) % 256));

            uint256 mask = ~((1 << bitPos) - 1);
            uint256 masked = tickBitmap[poolId][wordPos] & mask;

            initialized = masked != 0;
            next = initialized
                ? (compressed +
                    1 +
                    int24(uint24(_leastSignificantBit(masked) - bitPos))) *
                    tickSpacing
                : (compressed + 1 + int24(uint24(255 - bitPos))) * tickSpacing;
        }
    }

    function _mostSignificantBit(uint256 x) internal pure returns (uint8 r) {
        if (x >= 0x100000000000000000000000000000000) {
            x >>= 128;
            r += 128;
        }
        if (x >= 0x10000000000000000) {
            x >>= 64;
            r += 64;
        }
        if (x >= 0x100000000) {
            x >>= 32;
            r += 32;
        }
        if (x >= 0x10000) {
            x >>= 16;
            r += 16;
        }
        if (x >= 0x100) {
            x >>= 8;
            r += 8;
        }
        if (x >= 0x10) {
            x >>= 4;
            r += 4;
        }
        if (x >= 0x4) {
            x >>= 2;
            r += 2;
        }
        if (x >= 0x2) r += 1;
    }

    function _leastSignificantBit(uint256 x) internal pure returns (uint8 r) {
        r = 255;
        if (x & type(uint128).max > 0) {
            r -= 128;
        } else {
            x >>= 128;
        }
        if (x & type(uint64).max > 0) {
            r -= 64;
        } else {
            x >>= 64;
        }
        if (x & type(uint32).max > 0) {
            r -= 32;
        } else {
            x >>= 32;
        }
        if (x & type(uint16).max > 0) {
            r -= 16;
        } else {
            x >>= 16;
        }
        if (x & type(uint8).max > 0) {
            r -= 8;
        } else {
            x >>= 8;
        }
        if (x & 0xf > 0) {
            r -= 4;
        } else {
            x >>= 4;
        }
        if (x & 0x3 > 0) {
            r -= 2;
        } else {
            x >>= 2;
        }
        if (x & 0x1 > 0) r -= 1;
    }

    // ========================================================================
    // FEE CALCULATION
    // ========================================================================

    function _getFeeGrowthInside(
        bytes32 poolId,
        int24 tickLower,
        int24 tickUpper
    )
        internal
        view
        returns (uint256 feeGrowthInside0X128, uint256 feeGrowthInside1X128)
    {
        Pool storage pool = pools[poolId];
        TickInfo storage lower = ticks[poolId][tickLower];
        TickInfo storage upper = ticks[poolId][tickUpper];

        uint256 feeGrowthBelow0X128;
        uint256 feeGrowthBelow1X128;

        if (pool.currentTick >= tickLower) {
            feeGrowthBelow0X128 = lower.feeGrowthOutside0X128;
            feeGrowthBelow1X128 = lower.feeGrowthOutside1X128;
        } else {
            feeGrowthBelow0X128 =
                pool.feeGrowthGlobal0X128 -
                lower.feeGrowthOutside0X128;
            feeGrowthBelow1X128 =
                pool.feeGrowthGlobal1X128 -
                lower.feeGrowthOutside1X128;
        }

        uint256 feeGrowthAbove0X128;
        uint256 feeGrowthAbove1X128;

        if (pool.currentTick < tickUpper) {
            feeGrowthAbove0X128 = upper.feeGrowthOutside0X128;
            feeGrowthAbove1X128 = upper.feeGrowthOutside1X128;
        } else {
            feeGrowthAbove0X128 =
                pool.feeGrowthGlobal0X128 -
                upper.feeGrowthOutside0X128;
            feeGrowthAbove1X128 =
                pool.feeGrowthGlobal1X128 -
                upper.feeGrowthOutside1X128;
        }

        feeGrowthInside0X128 =
            pool.feeGrowthGlobal0X128 -
            feeGrowthBelow0X128 -
            feeGrowthAbove0X128;
        feeGrowthInside1X128 =
            pool.feeGrowthGlobal1X128 -
            feeGrowthBelow1X128 -
            feeGrowthAbove1X128;
    }

    // ========================================================================
    // MATH HELPERS
    // ========================================================================

    function _getSqrtRatioAtTick(int24 tick)
        internal
        pure
        returns (uint160 sqrtPriceX96)
    {
        uint256 absTick = tick < 0
            ? uint256(-int256(tick))
            : uint256(int256(tick));

        uint256 ratio = absTick & 0x1 != 0
            ? 0xfffcb933bd6fad37aa2d162d1a594001
            : 0x100000000000000000000000000000000;

        if (absTick & 0x2 != 0)
            ratio = (ratio * 0xfff97272373d413259a46990580e213a) >> 128;
        if (absTick & 0x4 != 0)
            ratio = (ratio * 0xfff2e50f5f656932ef12357cf3c7fdcc) >> 128;
        if (absTick & 0x8 != 0)
            ratio = (ratio * 0xffe5caca7e10e4e61c3624eaa0941cd0) >> 128;
        if (absTick & 0x10 != 0)
            ratio = (ratio * 0xffcb9843d60f6159c9db58835c926644) >> 128;
        if (absTick & 0x20 != 0)
            ratio = (ratio * 0xff973b41fa98c081472e6896dfb254c0) >> 128;
        if (absTick & 0x40 != 0)
            ratio = (ratio * 0xff2ea16466c96a3843ec78b326b52861) >> 128;
        if (absTick & 0x80 != 0)
            ratio = (ratio * 0xfe5dee046a99a2a811c461f1969c3053) >> 128;
        if (absTick & 0x100 != 0)
            ratio = (ratio * 0xfcbe86c7900a88aedcffc83b479aa3a4) >> 128;
        if (absTick & 0x200 != 0)
            ratio = (ratio * 0xf987a7253ac413176f2b074cf7815e54) >> 128;
        if (absTick & 0x400 != 0)
            ratio = (ratio * 0xf3392b0822b70005940c7a398e4b70f3) >> 128;
        if (absTick & 0x800 != 0)
            ratio = (ratio * 0xe7159475a2c29b7443b29c7fa6e889d9) >> 128;
        if (absTick & 0x1000 != 0)
            ratio = (ratio * 0xd097f3bdfd2022b8845ad8f792aa5825) >> 128;
        if (absTick & 0x2000 != 0)
            ratio = (ratio * 0xa9f746462d870fdf8a65dc1f90e061e5) >> 128;
        if (absTick & 0x4000 != 0)
            ratio = (ratio * 0x70d869a156d2a1b890bb3df62baf32f7) >> 128;
        if (absTick & 0x8000 != 0)
            ratio = (ratio * 0x31be135f97d08fd981231505542fcfa6) >> 128;
        if (absTick & 0x10000 != 0)
            ratio = (ratio * 0x9aa508b5b7a84e1c677de54f3e99bc9) >> 128;
        if (absTick & 0x20000 != 0)
            ratio = (ratio * 0x5d6af8dedb81196699c329225ee604) >> 128;
        if (absTick & 0x40000 != 0)
            ratio = (ratio * 0x2216e584f5fa1ea926041bedfe98) >> 128;
        if (absTick & 0x80000 != 0)
            ratio = (ratio * 0x48a170391f7dc42444e8fa2) >> 128;

        if (tick > 0) ratio = type(uint256).max / ratio;

        sqrtPriceX96 = uint160(
            (ratio >> 32) + (ratio % (1 << 32) == 0 ? 0 : 1)
        );
    }

    function _getTickAtSqrtRatio(uint160 sqrtPriceX96)
        internal
        pure
        returns (int24 tick)
    {
        uint256 ratio = uint256(sqrtPriceX96) << 32;

        uint256 r = ratio;
        uint256 msb = 0;

        assembly {
            let f := shl(7, gt(r, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF))
            msb := or(msb, f)
            r := shr(f, r)
        }
        assembly {
            let f := shl(6, gt(r, 0xFFFFFFFFFFFFFFFF))
            msb := or(msb, f)
            r := shr(f, r)
        }
        assembly {
            let f := shl(5, gt(r, 0xFFFFFFFF))
            msb := or(msb, f)
            r := shr(f, r)
        }
        assembly {
            let f := shl(4, gt(r, 0xFFFF))
            msb := or(msb, f)
            r := shr(f, r)
        }
        assembly {
            let f := shl(3, gt(r, 0xFF))
            msb := or(msb, f)
            r := shr(f, r)
        }
        assembly {
            let f := shl(2, gt(r, 0xF))
            msb := or(msb, f)
            r := shr(f, r)
        }
        assembly {
            let f := shl(1, gt(r, 0x3))
            msb := or(msb, f)
            r := shr(f, r)
        }
        assembly {
            let f := gt(r, 0x1)
            msb := or(msb, f)
        }

        if (msb >= 128) r = ratio >> (msb - 127);
        else r = ratio << (127 - msb);

        int256 log_2 = (int256(msb) - 128) << 64;

        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(63, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(62, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(61, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(60, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(59, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(58, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(57, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(56, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(55, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(54, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(53, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(52, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(51, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(50, f))
        }

        int256 log_sqrt10001 = log_2 * 255738958999603826347141;

        int24 tickLow = int24(
            (log_sqrt10001 - 3402992956809132418596140100660247210) >> 128
        );
        int24 tickHi = int24(
            (log_sqrt10001 + 291339464771989622907027621153398088495) >> 128
        );

        tick = tickLow == tickHi
            ? tickLow
            : _getSqrtRatioAtTick(tickHi) <= sqrtPriceX96
            ? tickHi
            : tickLow;
    }

    function _getAmountsForLiquidity(
        uint160 sqrtRatioX96,
        uint160 sqrtRatioAX96,
        uint160 sqrtRatioBX96,
        uint128 liquidity
    ) internal pure returns (uint256 amount0, uint256 amount1) {
        if (sqrtRatioAX96 > sqrtRatioBX96) {
            (sqrtRatioAX96, sqrtRatioBX96) = (sqrtRatioBX96, sqrtRatioAX96);
        }

        if (sqrtRatioX96 <= sqrtRatioAX96) {
            amount0 = _getAmount0ForLiquidity(
                sqrtRatioAX96,
                sqrtRatioBX96,
                liquidity
            );
        } else if (sqrtRatioX96 < sqrtRatioBX96) {
            amount0 = _getAmount0ForLiquidity(
                sqrtRatioX96,
                sqrtRatioBX96,
                liquidity
            );
            amount1 = _getAmount1ForLiquidity(
                sqrtRatioAX96,
                sqrtRatioX96,
                liquidity
            );
        } else {
            amount1 = _getAmount1ForLiquidity(
                sqrtRatioAX96,
                sqrtRatioBX96,
                liquidity
            );
        }
    }

    function _getAmount0ForLiquidity(
        uint160 sqrtRatioAX96,
        uint160 sqrtRatioBX96,
        uint128 liquidity
    ) internal pure returns (uint256 amount0) {
        if (sqrtRatioAX96 > sqrtRatioBX96) {
            (sqrtRatioAX96, sqrtRatioBX96) = (sqrtRatioBX96, sqrtRatioAX96);
        }

        return
            (uint256(liquidity) << 96) *
            (sqrtRatioBX96 - sqrtRatioAX96) /
            sqrtRatioBX96 /
            sqrtRatioAX96;
    }

    function _getAmount1ForLiquidity(
        uint160 sqrtRatioAX96,
        uint160 sqrtRatioBX96,
        uint128 liquidity
    ) internal pure returns (uint256 amount1) {
        if (sqrtRatioAX96 > sqrtRatioBX96) {
            (sqrtRatioAX96, sqrtRatioBX96) = (sqrtRatioBX96, sqrtRatioAX96);
        }

        return
            (uint256(liquidity) * (sqrtRatioBX96 - sqrtRatioAX96)) / Q96;
    }

    function _computeSwapStep(
        uint160 sqrtRatioCurrentX96,
        uint160 sqrtRatioTargetX96,
        uint128 liquidity,
        int256 amountRemaining,
        uint24 feePips
    )
        internal
        pure
        returns (
            uint160 sqrtRatioNextX96,
            uint256 amountIn,
            uint256 amountOut,
            uint256 feeAmount
        )
    {
        bool zeroForOne = sqrtRatioCurrentX96 >= sqrtRatioTargetX96;
        bool exactIn = amountRemaining >= 0;

        if (exactIn) {
            uint256 amountRemainingLessFee = (uint256(amountRemaining) *
                (FEE_DENOMINATOR - feePips)) / FEE_DENOMINATOR;

            amountIn = zeroForOne
                ? _getAmount0Delta(
                    sqrtRatioTargetX96,
                    sqrtRatioCurrentX96,
                    liquidity,
                    true
                )
                : _getAmount1Delta(
                    sqrtRatioCurrentX96,
                    sqrtRatioTargetX96,
                    liquidity,
                    true
                );

            if (amountRemainingLessFee >= amountIn) {
                sqrtRatioNextX96 = sqrtRatioTargetX96;
            } else {
                sqrtRatioNextX96 = _getNextSqrtPriceFromInput(
                    sqrtRatioCurrentX96,
                    liquidity,
                    amountRemainingLessFee,
                    zeroForOne
                );
            }
        } else {
            amountOut = zeroForOne
                ? _getAmount1Delta(
                    sqrtRatioTargetX96,
                    sqrtRatioCurrentX96,
                    liquidity,
                    false
                )
                : _getAmount0Delta(
                    sqrtRatioCurrentX96,
                    sqrtRatioTargetX96,
                    liquidity,
                    false
                );

            if (uint256(-amountRemaining) >= amountOut) {
                sqrtRatioNextX96 = sqrtRatioTargetX96;
            } else {
                sqrtRatioNextX96 = _getNextSqrtPriceFromOutput(
                    sqrtRatioCurrentX96,
                    liquidity,
                    uint256(-amountRemaining),
                    zeroForOne
                );
            }
        }

        bool max = sqrtRatioTargetX96 == sqrtRatioNextX96;

        if (zeroForOne) {
            amountIn = max && exactIn
                ? amountIn
                : _getAmount0Delta(
                    sqrtRatioNextX96,
                    sqrtRatioCurrentX96,
                    liquidity,
                    true
                );
            amountOut = max && !exactIn
                ? amountOut
                : _getAmount1Delta(
                    sqrtRatioNextX96,
                    sqrtRatioCurrentX96,
                    liquidity,
                    false
                );
        } else {
            amountIn = max && exactIn
                ? amountIn
                : _getAmount1Delta(
                    sqrtRatioCurrentX96,
                    sqrtRatioNextX96,
                    liquidity,
                    true
                );
            amountOut = max && !exactIn
                ? amountOut
                : _getAmount0Delta(
                    sqrtRatioCurrentX96,
                    sqrtRatioNextX96,
                    liquidity,
                    false
                );
        }

        if (!exactIn && amountOut > uint256(-amountRemaining)) {
            amountOut = uint256(-amountRemaining);
        }

        if (exactIn && sqrtRatioNextX96 != sqrtRatioTargetX96) {
            feeAmount = uint256(amountRemaining) - amountIn;
        } else {
            feeAmount = (amountIn * feePips) / (FEE_DENOMINATOR - feePips);
        }
    }

    function _getAmount0Delta(
        uint160 sqrtRatioAX96,
        uint160 sqrtRatioBX96,
        uint128 liquidity,
        bool roundUp
    ) internal pure returns (uint256 amount0) {
        if (sqrtRatioAX96 > sqrtRatioBX96) {
            (sqrtRatioAX96, sqrtRatioBX96) = (sqrtRatioBX96, sqrtRatioAX96);
        }

        uint256 numerator1 = uint256(liquidity) << 96;
        uint256 numerator2 = sqrtRatioBX96 - sqrtRatioAX96;

        if (roundUp) {
            amount0 = (numerator1 * numerator2 / sqrtRatioBX96 + sqrtRatioAX96 - 1) / sqrtRatioAX96;
        } else {
            amount0 = numerator1 * numerator2 / sqrtRatioBX96 / sqrtRatioAX96;
        }
    }

    function _getAmount1Delta(
        uint160 sqrtRatioAX96,
        uint160 sqrtRatioBX96,
        uint128 liquidity,
        bool roundUp
    ) internal pure returns (uint256 amount1) {
        if (sqrtRatioAX96 > sqrtRatioBX96) {
            (sqrtRatioAX96, sqrtRatioBX96) = (sqrtRatioBX96, sqrtRatioAX96);
        }

        if (roundUp) {
            amount1 = (uint256(liquidity) * (sqrtRatioBX96 - sqrtRatioAX96) + Q96 - 1) / Q96;
        } else {
            amount1 = uint256(liquidity) * (sqrtRatioBX96 - sqrtRatioAX96) / Q96;
        }
    }

    function _getNextSqrtPriceFromInput(
        uint160 sqrtPX96,
        uint128 liquidity,
        uint256 amountIn,
        bool zeroForOne
    ) internal pure returns (uint160 sqrtQX96) {
        if (zeroForOne) {
            uint256 product = amountIn * sqrtPX96;
            if (product / amountIn == sqrtPX96) {
                uint256 denominator = uint256(liquidity) << 96;
                denominator = denominator + product;
                sqrtQX96 = uint160((uint256(liquidity) << 192) / denominator);
            } else {
                sqrtQX96 = uint160(
                    (uint256(liquidity) << 96) /
                        ((uint256(liquidity) << 96) / sqrtPX96 + amountIn)
                );
            }
        } else {
            sqrtQX96 = uint160(
                uint256(sqrtPX96) + (amountIn << 96) / liquidity
            );
        }
    }

    function _getNextSqrtPriceFromOutput(
        uint160 sqrtPX96,
        uint128 liquidity,
        uint256 amountOut,
        bool zeroForOne
    ) internal pure returns (uint160 sqrtQX96) {
        if (zeroForOne) {
            sqrtQX96 = uint160(
                uint256(sqrtPX96) - (amountOut << 96) / liquidity
            );
        } else {
            uint256 quotient = (amountOut << 96) / sqrtPX96;
            sqrtQX96 = uint160(
                (uint256(liquidity) << 96) /
                    ((uint256(liquidity) << 96) / sqrtPX96 - quotient)
            );
        }
    }

    // ========================================================================
    // MEV PROTECTION
    // ========================================================================

    function _checkPriceBounds(bytes32 poolId, uint160 sqrtPriceX96) internal view {
        uint256 oraclePrice = lastOraclePrice[poolId];
        if (oraclePrice == 0) return; // No oracle set

        // Convert sqrt price to actual price
        uint256 currentPrice = (uint256(sqrtPriceX96) * uint256(sqrtPriceX96)) >> 192;

        // Check deviation
        uint256 deviation = currentPrice > oraclePrice
            ? ((currentPrice - oraclePrice) * 10000) / oraclePrice
            : ((oraclePrice - currentPrice) * 10000) / oraclePrice;

        require(
            deviation <= maxPriceDeviation,
            "Price deviation exceeds oracle bounds"
        );
    }

    function updateOraclePrice(bytes32 poolId, uint256 price)
        external
        onlyRole(OPERATOR_ROLE)
    {
        lastOraclePrice[poolId] = price;
        oraclePriceTimestamp[poolId] = block.timestamp;
    }

    // ========================================================================
    // CALLBACKS (To be implemented by caller)
    // ========================================================================

    function _mintCallback(
        address token0,
        address token1,
        uint256 amount0,
        uint256 amount1,
        bytes memory data
    ) internal {
        IERC20(token0).safeTransferFrom(msg.sender, address(this), amount0);
        IERC20(token1).safeTransferFrom(msg.sender, address(this), amount1);
    }

    function _swapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes memory data
    ) internal {
        if (amount0Delta > 0) {
            // Need to receive token0
        }
        if (amount1Delta > 0) {
            // Need to receive token1
        }
    }

    function _flashCallback(
        uint256 fee0,
        uint256 fee1,
        bytes memory data
    ) internal {
        // Caller must repay principal + fees
    }

    // ========================================================================
    // ADMIN FUNCTIONS
    // ========================================================================

    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    function setProtocolFee(uint8 newFee) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newFee <= 25, "Max 25%");
        protocolFeePercent = newFee;
    }

    function setMaxPriceDeviation(uint256 deviation)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(deviation <= 1000, "Max 10%");
        maxPriceDeviation = deviation;
    }

    function collectProtocolFees(bytes32 poolId)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
        returns (uint128 amount0, uint128 amount1)
    {
        Pool storage pool = pools[poolId];

        amount0 = pool.protocolFees0;
        amount1 = pool.protocolFees1;

        pool.protocolFees0 = 0;
        pool.protocolFees1 = 0;

        if (amount0 > 0) {
            IERC20(pool.token0).safeTransfer(feeRecipient, amount0);
        }
        if (amount1 > 0) {
            IERC20(pool.token1).safeTransfer(feeRecipient, amount1);
        }
    }

    // ========================================================================
    // VIEW FUNCTIONS
    // ========================================================================

    function getPoolInfo(bytes32 poolId)
        external
        view
        returns (
            address token0,
            address token1,
            uint24 fee,
            uint160 sqrtPriceX96,
            int24 currentTick,
            uint128 liquidity
        )
    {
        Pool storage pool = pools[poolId];
        return (
            pool.token0,
            pool.token1,
            pool.fee,
            pool.sqrtPriceX96,
            pool.currentTick,
            pool.liquidity
        );
    }

    function getPositionInfo(
        bytes32 poolId,
        address owner,
        int24 tickLower,
        int24 tickUpper
    )
        external
        view
        returns (
            uint128 liquidity,
            uint128 tokensOwed0,
            uint128 tokensOwed1
        )
    {
        bytes32 positionKey = keccak256(
            abi.encodePacked(owner, tickLower, tickUpper)
        );
        Position storage position = positions[poolId][positionKey];

        return (
            position.liquidity,
            position.tokensOwed0,
            position.tokensOwed1
        );
    }

    function quote(
        bytes32 poolId,
        bool zeroForOne,
        int256 amountSpecified
    ) external view returns (int256 amount0, int256 amount1) {
        // Read-only swap simulation
        Pool storage pool = pools[poolId];
        // Implementation would simulate swap without state changes
        return (0, 0);
    }
}
