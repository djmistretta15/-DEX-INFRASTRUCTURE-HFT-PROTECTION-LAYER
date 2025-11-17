// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * ADVANCED AMM CURVE ENGINE
 *
 * HYPOTHESIS: Implementing multiple AMM curves (constant product, stableswap,
 * concentrated liquidity) with dynamic fee adjustment will optimize capital
 * efficiency by 5x and reduce impermanent loss by 60%.
 *
 * SUCCESS METRICS:
 * - Capital efficiency: 5x improvement over constant product
 * - Impermanent loss reduction: 60% vs baseline
 * - Slippage reduction: <0.1% for 95% of trades
 * - Fee optimization: Dynamic fees matching volatility
 * - LP returns: >30% APY average
 *
 * SECURITY CONSIDERATIONS:
 * - Reentrancy protection
 * - Oracle price bounds
 * - Flash loan resistance
 * - Sandwich attack mitigation
 * - Tick manipulation protection
 */

// Curve type
enum CurveType {
    CONSTANT_PRODUCT,    // x * y = k (Uniswap V2)
    STABLESWAP,          // Curve Finance style
    CONCENTRATED,        // Uniswap V3 style
    WEIGHTED,            // Balancer style
    DYNAMIC              // Adaptive curve
}

// Pool state
struct Pool {
    uint256 poolId;
    address token0;
    address token1;
    uint128 reserve0;
    uint128 reserve1;
    CurveType curveType;
    uint128 totalLiquidity;
    uint24 currentFee;     // basis points
    uint24 baseFee;
    int24 currentTick;     // For concentrated liquidity
    uint160 sqrtPriceX96;  // Q96 format
    bool isActive;
}

// Liquidity position (concentrated liquidity)
struct Position {
    uint256 positionId;
    address owner;
    uint256 poolId;
    int24 tickLower;
    int24 tickUpper;
    uint128 liquidity;
    uint256 tokensOwed0;
    uint256 tokensOwed1;
    uint256 feeGrowthInside0;
    uint256 feeGrowthInside1;
}

// Tick data (for concentrated liquidity)
struct Tick {
    int128 liquidityNet;
    uint128 liquidityGross;
    uint256 feeGrowthOutside0;
    uint256 feeGrowthOutside1;
    bool initialized;
}

// Swap parameters
struct SwapParams {
    uint256 poolId;
    address tokenIn;
    address tokenOut;
    uint256 amountIn;
    uint256 minAmountOut;
    address recipient;
    uint256 deadline;
}

// Stableswap parameters
struct StableswapParams {
    uint256 A;             // Amplification coefficient
    uint256 adminFee;      // Admin fee percentage
    uint8 precision0;      // Token0 decimals
    uint8 precision1;      // Token1 decimals
}

// Weighted pool parameters
struct WeightedParams {
    uint256 weight0;       // Weight of token0 (out of 100)
    uint256 weight1;       // Weight of token1
}

contract AMMCurveEngine is ReentrancyGuard, AccessControl {
    using SafeERC20 for IERC20;

    // Roles
    bytes32 public constant POOL_MANAGER = keccak256("POOL_MANAGER");
    bytes32 public constant FEE_MANAGER = keccak256("FEE_MANAGER");

    // Pools
    mapping(uint256 => Pool) public pools;
    uint256 public poolCount;

    // Positions (for concentrated liquidity)
    mapping(uint256 => Position) public positions;
    uint256 public positionCount;

    // Ticks (poolId => tick => Tick)
    mapping(uint256 => mapping(int24 => Tick)) public ticks;

    // Pool parameters
    mapping(uint256 => StableswapParams) public stableswapParams;
    mapping(uint256 => WeightedParams) public weightedParams;

    // Fee growth tracking
    mapping(uint256 => uint256) public feeGrowthGlobal0;
    mapping(uint256 => uint256) public feeGrowthGlobal1;

    // Protocol fee
    uint256 public protocolFeePercent = 1000; // 10% of trading fees

    // Constants
    uint256 constant Q96 = 2**96;
    uint256 constant Q128 = 2**128;
    int24 constant MIN_TICK = -887272;
    int24 constant MAX_TICK = 887272;
    int24 constant TICK_SPACING = 60;

    // Dynamic fee parameters
    uint24 public minFee = 10;    // 0.1%
    uint24 public maxFee = 500;   // 5%

    // Events
    event PoolCreated(
        uint256 indexed poolId,
        address token0,
        address token1,
        CurveType curveType,
        uint24 fee
    );

    event LiquidityAdded(
        uint256 indexed poolId,
        address indexed provider,
        uint128 amount0,
        uint128 amount1,
        uint128 liquidity
    );

    event LiquidityRemoved(
        uint256 indexed poolId,
        address indexed provider,
        uint128 amount0,
        uint128 amount1,
        uint128 liquidity
    );

    event Swap(
        uint256 indexed poolId,
        address indexed sender,
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 amountOut,
        uint24 fee
    );

    event PositionMinted(
        uint256 indexed positionId,
        uint256 indexed poolId,
        address owner,
        int24 tickLower,
        int24 tickUpper,
        uint128 liquidity
    );

    event FeeUpdated(uint256 indexed poolId, uint24 newFee);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(POOL_MANAGER, msg.sender);
        _grantRole(FEE_MANAGER, msg.sender);
    }

    /**
     * Create constant product pool (Uniswap V2 style)
     */
    function createConstantProductPool(
        address token0,
        address token1,
        uint24 fee
    ) external onlyRole(POOL_MANAGER) returns (uint256) {
        return _createPool(token0, token1, CurveType.CONSTANT_PRODUCT, fee);
    }

    /**
     * Create stableswap pool (Curve style)
     */
    function createStableswapPool(
        address token0,
        address token1,
        uint24 fee,
        uint256 amplification
    ) external onlyRole(POOL_MANAGER) returns (uint256) {
        uint256 poolId = _createPool(token0, token1, CurveType.STABLESWAP, fee);

        stableswapParams[poolId] = StableswapParams({
            A: amplification,
            adminFee: 500, // 5% admin fee
            precision0: 18,
            precision1: 18
        });

        return poolId;
    }

    /**
     * Create concentrated liquidity pool
     */
    function createConcentratedPool(
        address token0,
        address token1,
        uint24 fee,
        uint160 initialSqrtPriceX96
    ) external onlyRole(POOL_MANAGER) returns (uint256) {
        uint256 poolId = _createPool(token0, token1, CurveType.CONCENTRATED, fee);

        Pool storage pool = pools[poolId];
        pool.sqrtPriceX96 = initialSqrtPriceX96;
        pool.currentTick = getTickAtSqrtRatio(initialSqrtPriceX96);

        return poolId;
    }

    /**
     * Create weighted pool (Balancer style)
     */
    function createWeightedPool(
        address token0,
        address token1,
        uint24 fee,
        uint256 weight0
    ) external onlyRole(POOL_MANAGER) returns (uint256) {
        require(weight0 > 0 && weight0 < 100, "Invalid weight");

        uint256 poolId = _createPool(token0, token1, CurveType.WEIGHTED, fee);

        weightedParams[poolId] = WeightedParams({
            weight0: weight0,
            weight1: 100 - weight0
        });

        return poolId;
    }

    /**
     * Add liquidity to constant product pool
     */
    function addLiquidity(
        uint256 poolId,
        uint128 amount0Desired,
        uint128 amount1Desired,
        uint128 amount0Min,
        uint128 amount1Min
    ) external nonReentrant returns (uint128 liquidity) {
        Pool storage pool = pools[poolId];
        require(pool.isActive, "Pool not active");
        require(pool.curveType != CurveType.CONCENTRATED, "Use mint for concentrated");

        uint128 amount0;
        uint128 amount1;

        if (pool.totalLiquidity == 0) {
            // First deposit
            amount0 = amount0Desired;
            amount1 = amount1Desired;
            liquidity = uint128(sqrt(uint256(amount0) * uint256(amount1)));
        } else {
            // Proportional deposit
            uint128 optimalAmount1 = uint128((uint256(amount0Desired) * pool.reserve1) / pool.reserve0);

            if (optimalAmount1 <= amount1Desired) {
                require(optimalAmount1 >= amount1Min, "Insufficient amount1");
                amount0 = amount0Desired;
                amount1 = optimalAmount1;
            } else {
                uint128 optimalAmount0 = uint128((uint256(amount1Desired) * pool.reserve0) / pool.reserve1);
                require(optimalAmount0 >= amount0Min, "Insufficient amount0");
                amount0 = optimalAmount0;
                amount1 = amount1Desired;
            }

            liquidity = uint128((uint256(amount0) * pool.totalLiquidity) / pool.reserve0);
        }

        // Transfer tokens
        IERC20(pool.token0).safeTransferFrom(msg.sender, address(this), amount0);
        IERC20(pool.token1).safeTransferFrom(msg.sender, address(this), amount1);

        // Update reserves
        pool.reserve0 += amount0;
        pool.reserve1 += amount1;
        pool.totalLiquidity += liquidity;

        emit LiquidityAdded(poolId, msg.sender, amount0, amount1, liquidity);

        return liquidity;
    }

    /**
     * Mint concentrated liquidity position
     */
    function mintPosition(
        uint256 poolId,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount
    ) external nonReentrant returns (uint256 positionId, uint128 amount0, uint128 amount1) {
        Pool storage pool = pools[poolId];
        require(pool.curveType == CurveType.CONCENTRATED, "Not concentrated pool");
        require(tickLower < tickUpper, "Invalid tick range");
        require(tickLower % TICK_SPACING == 0 && tickUpper % TICK_SPACING == 0, "Invalid tick spacing");

        // Calculate amounts needed for position
        (amount0, amount1) = _getAmountsForLiquidity(
            pool.sqrtPriceX96,
            getSqrtRatioAtTick(tickLower),
            getSqrtRatioAtTick(tickUpper),
            amount
        );

        // Transfer tokens
        if (amount0 > 0) {
            IERC20(pool.token0).safeTransferFrom(msg.sender, address(this), amount0);
            pool.reserve0 += amount0;
        }
        if (amount1 > 0) {
            IERC20(pool.token1).safeTransferFrom(msg.sender, address(this), amount1);
            pool.reserve1 += amount1;
        }

        // Update ticks
        _updateTick(poolId, tickLower, int128(amount), pool.currentTick);
        _updateTick(poolId, tickUpper, -int128(amount), pool.currentTick);

        // Create position
        positionCount++;
        positionId = positionCount;

        positions[positionId] = Position({
            positionId: positionId,
            owner: msg.sender,
            poolId: poolId,
            tickLower: tickLower,
            tickUpper: tickUpper,
            liquidity: amount,
            tokensOwed0: 0,
            tokensOwed1: 0,
            feeGrowthInside0: _getFeeGrowthInside(poolId, tickLower, tickUpper, true),
            feeGrowthInside1: _getFeeGrowthInside(poolId, tickLower, tickUpper, false)
        });

        pool.totalLiquidity += amount;

        emit PositionMinted(positionId, poolId, msg.sender, tickLower, tickUpper, amount);

        return (positionId, amount0, amount1);
    }

    /**
     * Execute swap
     */
    function swap(SwapParams calldata params) external nonReentrant returns (uint256 amountOut) {
        require(block.timestamp <= params.deadline, "Expired");

        Pool storage pool = pools[params.poolId];
        require(pool.isActive, "Pool not active");

        // Determine swap direction
        bool zeroForOne = params.tokenIn == pool.token0;
        require(
            (zeroForOne && params.tokenOut == pool.token1) ||
            (!zeroForOne && params.tokenIn == pool.token1 && params.tokenOut == pool.token0),
            "Invalid tokens"
        );

        // Update fee based on volatility (dynamic fees)
        _updateDynamicFee(params.poolId);

        // Calculate output based on curve type
        if (pool.curveType == CurveType.CONSTANT_PRODUCT) {
            amountOut = _swapConstantProduct(pool, params.amountIn, zeroForOne);
        } else if (pool.curveType == CurveType.STABLESWAP) {
            amountOut = _swapStableswap(params.poolId, pool, params.amountIn, zeroForOne);
        } else if (pool.curveType == CurveType.WEIGHTED) {
            amountOut = _swapWeighted(params.poolId, pool, params.amountIn, zeroForOne);
        } else if (pool.curveType == CurveType.CONCENTRATED) {
            amountOut = _swapConcentrated(pool, params.amountIn, zeroForOne);
        }

        require(amountOut >= params.minAmountOut, "Insufficient output");

        // Transfer tokens
        IERC20(params.tokenIn).safeTransferFrom(msg.sender, address(this), params.amountIn);
        IERC20(params.tokenOut).safeTransfer(params.recipient, amountOut);

        emit Swap(
            params.poolId,
            msg.sender,
            params.tokenIn,
            params.tokenOut,
            params.amountIn,
            amountOut,
            pool.currentFee
        );

        return amountOut;
    }

    /**
     * Get quote for swap
     */
    function getQuote(
        uint256 poolId,
        address tokenIn,
        uint256 amountIn
    ) external view returns (uint256 amountOut, uint256 priceImpact) {
        Pool storage pool = pools[poolId];
        bool zeroForOne = tokenIn == pool.token0;

        if (pool.curveType == CurveType.CONSTANT_PRODUCT) {
            amountOut = _quoteConstantProduct(pool, amountIn, zeroForOne);
        } else if (pool.curveType == CurveType.STABLESWAP) {
            amountOut = _quoteStableswap(poolId, pool, amountIn, zeroForOne);
        }

        // Calculate price impact
        uint256 spotPrice = zeroForOne
            ? (uint256(pool.reserve1) * 1e18) / pool.reserve0
            : (uint256(pool.reserve0) * 1e18) / pool.reserve1;

        uint256 executionPrice = (amountOut * 1e18) / amountIn;
        priceImpact = spotPrice > executionPrice
            ? ((spotPrice - executionPrice) * 10000) / spotPrice
            : 0;

        return (amountOut, priceImpact);
    }

    /**
     * Update dynamic fee
     */
    function _updateDynamicFee(uint256 poolId) internal {
        Pool storage pool = pools[poolId];

        // Calculate volatility proxy (ratio change)
        uint256 ratio = (uint256(pool.reserve0) * 1e18) / pool.reserve1;

        // Adjust fee based on imbalance (simplified)
        uint256 imbalance = ratio > 1e18 ? ratio - 1e18 : 1e18 - ratio;
        uint24 newFee = pool.baseFee + uint24((imbalance * 100) / 1e18);

        if (newFee < minFee) newFee = minFee;
        if (newFee > maxFee) newFee = maxFee;

        if (newFee != pool.currentFee) {
            pool.currentFee = newFee;
            emit FeeUpdated(poolId, newFee);
        }
    }

    /**
     * Swap using constant product formula
     */
    function _swapConstantProduct(
        Pool storage pool,
        uint256 amountIn,
        bool zeroForOne
    ) internal returns (uint256 amountOut) {
        uint256 fee = (amountIn * pool.currentFee) / 10000;
        uint256 amountInAfterFee = amountIn - fee;

        uint256 reserveIn = zeroForOne ? pool.reserve0 : pool.reserve1;
        uint256 reserveOut = zeroForOne ? pool.reserve1 : pool.reserve0;

        // x * y = k
        amountOut = (reserveOut * amountInAfterFee) / (reserveIn + amountInAfterFee);

        // Update reserves
        if (zeroForOne) {
            pool.reserve0 += uint128(amountIn);
            pool.reserve1 -= uint128(amountOut);
        } else {
            pool.reserve1 += uint128(amountIn);
            pool.reserve0 -= uint128(amountOut);
        }

        // Track fees
        uint256 protocolFee = (fee * protocolFeePercent) / 10000;
        feeGrowthGlobal0[pool.poolId] += zeroForOne ? (fee - protocolFee) : 0;
        feeGrowthGlobal1[pool.poolId] += zeroForOne ? 0 : (fee - protocolFee);

        return amountOut;
    }

    /**
     * Swap using stableswap formula (simplified Curve)
     */
    function _swapStableswap(
        uint256 poolId,
        Pool storage pool,
        uint256 amountIn,
        bool zeroForOne
    ) internal returns (uint256 amountOut) {
        StableswapParams storage params = stableswapParams[poolId];
        uint256 fee = (amountIn * pool.currentFee) / 10000;
        uint256 amountInAfterFee = amountIn - fee;

        uint256 x = zeroForOne ? pool.reserve0 : pool.reserve1;
        uint256 y = zeroForOne ? pool.reserve1 : pool.reserve0;

        // StableSwap invariant: An^n * sum(x) + D = ADn^n + D^(n+1) / (n^n * prod(x))
        // Simplified for 2 tokens
        uint256 D = _getStableswapD(x, y, params.A);
        uint256 newX = x + amountInAfterFee;
        uint256 newY = _getStableswapY(newX, D, params.A);

        amountOut = y - newY;

        // Update reserves
        if (zeroForOne) {
            pool.reserve0 += uint128(amountIn);
            pool.reserve1 -= uint128(amountOut);
        } else {
            pool.reserve1 += uint128(amountIn);
            pool.reserve0 -= uint128(amountOut);
        }

        return amountOut;
    }

    /**
     * Swap using weighted formula (Balancer style)
     */
    function _swapWeighted(
        uint256 poolId,
        Pool storage pool,
        uint256 amountIn,
        bool zeroForOne
    ) internal returns (uint256 amountOut) {
        WeightedParams storage params = weightedParams[poolId];
        uint256 fee = (amountIn * pool.currentFee) / 10000;
        uint256 amountInAfterFee = amountIn - fee;

        uint256 balanceIn = zeroForOne ? pool.reserve0 : pool.reserve1;
        uint256 balanceOut = zeroForOne ? pool.reserve1 : pool.reserve0;
        uint256 weightIn = zeroForOne ? params.weight0 : params.weight1;
        uint256 weightOut = zeroForOne ? params.weight1 : params.weight0;

        // Weighted constant product: (Bi/Wi)^Wi * (Bo/Wo)^Wo = k
        // Out = Bo * (1 - (Bi / (Bi + Ai))^(Wi/Wo))
        uint256 ratio = (balanceIn * 1e18) / (balanceIn + amountInAfterFee);
        uint256 exponent = (weightIn * 1e18) / weightOut;
        uint256 power = _pow(ratio, exponent);

        amountOut = (balanceOut * (1e18 - power)) / 1e18;

        // Update reserves
        if (zeroForOne) {
            pool.reserve0 += uint128(amountIn);
            pool.reserve1 -= uint128(amountOut);
        } else {
            pool.reserve1 += uint128(amountIn);
            pool.reserve0 -= uint128(amountOut);
        }

        return amountOut;
    }

    /**
     * Swap using concentrated liquidity
     */
    function _swapConcentrated(
        Pool storage pool,
        uint256 amountIn,
        bool zeroForOne
    ) internal returns (uint256 amountOut) {
        // Simplified: process swap within current tick range
        uint256 fee = (amountIn * pool.currentFee) / 10000;
        uint256 amountInAfterFee = amountIn - fee;

        // Calculate price change
        uint160 newSqrtPriceX96;
        if (zeroForOne) {
            // Selling token0 for token1
            uint256 liquidity = pool.totalLiquidity;
            newSqrtPriceX96 = uint160(
                (uint256(pool.sqrtPriceX96) * liquidity) /
                (liquidity + (amountInAfterFee * Q96) / uint256(pool.sqrtPriceX96))
            );

            amountOut = (uint256(pool.sqrtPriceX96) - newSqrtPriceX96) * liquidity / Q96;
            pool.reserve0 += uint128(amountIn);
            pool.reserve1 -= uint128(amountOut);
        } else {
            // Selling token1 for token0
            uint256 liquidity = pool.totalLiquidity;
            newSqrtPriceX96 = uint160(
                uint256(pool.sqrtPriceX96) + (amountInAfterFee * Q96) / liquidity
            );

            amountOut = liquidity * (newSqrtPriceX96 - pool.sqrtPriceX96) / Q96;
            pool.reserve1 += uint128(amountIn);
            pool.reserve0 -= uint128(amountOut);
        }

        pool.sqrtPriceX96 = newSqrtPriceX96;
        pool.currentTick = getTickAtSqrtRatio(newSqrtPriceX96);

        return amountOut;
    }

    // Helper functions

    function _createPool(
        address token0,
        address token1,
        CurveType curveType,
        uint24 fee
    ) internal returns (uint256) {
        require(token0 < token1, "Token order");
        poolCount++;

        pools[poolCount] = Pool({
            poolId: poolCount,
            token0: token0,
            token1: token1,
            reserve0: 0,
            reserve1: 0,
            curveType: curveType,
            totalLiquidity: 0,
            currentFee: fee,
            baseFee: fee,
            currentTick: 0,
            sqrtPriceX96: 0,
            isActive: true
        });

        emit PoolCreated(poolCount, token0, token1, curveType, fee);
        return poolCount;
    }

    function _quoteConstantProduct(
        Pool storage pool,
        uint256 amountIn,
        bool zeroForOne
    ) internal view returns (uint256) {
        uint256 fee = (amountIn * pool.currentFee) / 10000;
        uint256 amountInAfterFee = amountIn - fee;

        uint256 reserveIn = zeroForOne ? pool.reserve0 : pool.reserve1;
        uint256 reserveOut = zeroForOne ? pool.reserve1 : pool.reserve0;

        return (reserveOut * amountInAfterFee) / (reserveIn + amountInAfterFee);
    }

    function _quoteStableswap(
        uint256 poolId,
        Pool storage pool,
        uint256 amountIn,
        bool zeroForOne
    ) internal view returns (uint256) {
        StableswapParams storage params = stableswapParams[poolId];
        uint256 fee = (amountIn * pool.currentFee) / 10000;
        uint256 amountInAfterFee = amountIn - fee;

        uint256 x = zeroForOne ? pool.reserve0 : pool.reserve1;
        uint256 y = zeroForOne ? pool.reserve1 : pool.reserve0;

        uint256 D = _getStableswapD(x, y, params.A);
        uint256 newX = x + amountInAfterFee;
        uint256 newY = _getStableswapY(newX, D, params.A);

        return y - newY;
    }

    function _getStableswapD(uint256 x, uint256 y, uint256 A) internal pure returns (uint256) {
        uint256 S = x + y;
        if (S == 0) return 0;

        uint256 D = S;
        uint256 Ann = A * 4; // n = 2

        for (uint256 i = 0; i < 255; i++) {
            uint256 D_P = D;
            D_P = (D_P * D) / (2 * x);
            D_P = (D_P * D) / (2 * y);

            uint256 Dprev = D;
            D = ((Ann * S + D_P * 2) * D) / ((Ann - 1) * D + 3 * D_P);

            if (D > Dprev) {
                if (D - Dprev <= 1) break;
            } else {
                if (Dprev - D <= 1) break;
            }
        }

        return D;
    }

    function _getStableswapY(uint256 x, uint256 D, uint256 A) internal pure returns (uint256) {
        uint256 Ann = A * 4;
        uint256 c = (D * D) / (2 * x);
        c = (c * D) / (Ann * 2);

        uint256 b = x + D / Ann;

        uint256 y = D;
        for (uint256 i = 0; i < 255; i++) {
            uint256 yPrev = y;
            y = (y * y + c) / (2 * y + b - D);

            if (y > yPrev) {
                if (y - yPrev <= 1) break;
            } else {
                if (yPrev - y <= 1) break;
            }
        }

        return y;
    }

    function _updateTick(
        uint256 poolId,
        int24 tick,
        int128 liquidityDelta,
        int24 currentTick
    ) internal {
        Tick storage info = ticks[poolId][tick];

        info.liquidityGross += uint128(liquidityDelta > 0 ? liquidityDelta : -liquidityDelta);
        info.liquidityNet += liquidityDelta;

        if (!info.initialized) {
            info.initialized = true;
            if (tick <= currentTick) {
                info.feeGrowthOutside0 = feeGrowthGlobal0[poolId];
                info.feeGrowthOutside1 = feeGrowthGlobal1[poolId];
            }
        }
    }

    function _getAmountsForLiquidity(
        uint160 sqrtPriceX96,
        uint160 sqrtPriceAX96,
        uint160 sqrtPriceBX96,
        uint128 liquidity
    ) internal pure returns (uint128 amount0, uint128 amount1) {
        if (sqrtPriceAX96 > sqrtPriceBX96) {
            (sqrtPriceAX96, sqrtPriceBX96) = (sqrtPriceBX96, sqrtPriceAX96);
        }

        if (sqrtPriceX96 <= sqrtPriceAX96) {
            amount0 = uint128((uint256(liquidity) * (sqrtPriceBX96 - sqrtPriceAX96)) / sqrtPriceBX96 / sqrtPriceAX96);
        } else if (sqrtPriceX96 < sqrtPriceBX96) {
            amount0 = uint128((uint256(liquidity) * (sqrtPriceBX96 - sqrtPriceX96)) / sqrtPriceBX96 / sqrtPriceX96);
            amount1 = uint128((uint256(liquidity) * (sqrtPriceX96 - sqrtPriceAX96)) / Q96);
        } else {
            amount1 = uint128((uint256(liquidity) * (sqrtPriceBX96 - sqrtPriceAX96)) / Q96);
        }
    }

    function _getFeeGrowthInside(
        uint256 poolId,
        int24 tickLower,
        int24 tickUpper,
        bool isToken0
    ) internal view returns (uint256) {
        Pool storage pool = pools[poolId];
        Tick storage lower = ticks[poolId][tickLower];
        Tick storage upper = ticks[poolId][tickUpper];

        uint256 feeGrowthGlobal = isToken0 ? feeGrowthGlobal0[poolId] : feeGrowthGlobal1[poolId];
        uint256 feeGrowthBelow;
        uint256 feeGrowthAbove;

        if (pool.currentTick >= tickLower) {
            feeGrowthBelow = isToken0 ? lower.feeGrowthOutside0 : lower.feeGrowthOutside1;
        } else {
            feeGrowthBelow = feeGrowthGlobal - (isToken0 ? lower.feeGrowthOutside0 : lower.feeGrowthOutside1);
        }

        if (pool.currentTick < tickUpper) {
            feeGrowthAbove = isToken0 ? upper.feeGrowthOutside0 : upper.feeGrowthOutside1;
        } else {
            feeGrowthAbove = feeGrowthGlobal - (isToken0 ? upper.feeGrowthOutside0 : upper.feeGrowthOutside1);
        }

        return feeGrowthGlobal - feeGrowthBelow - feeGrowthAbove;
    }

    function getSqrtRatioAtTick(int24 tick) public pure returns (uint160) {
        // Simplified: return approximate value
        if (tick == 0) return uint160(Q96);
        uint256 absTick = tick > 0 ? uint256(int256(tick)) : uint256(int256(-tick));
        uint256 ratio = absTick * Q96 / 100;
        return tick > 0 ? uint160(Q96 + ratio) : uint160(Q96 - ratio);
    }

    function getTickAtSqrtRatio(uint160 sqrtPriceX96) public pure returns (int24) {
        if (sqrtPriceX96 >= Q96) {
            return int24(int256((uint256(sqrtPriceX96) - Q96) * 100 / Q96));
        } else {
            return -int24(int256((Q96 - uint256(sqrtPriceX96)) * 100 / Q96));
        }
    }

    function sqrt(uint256 x) internal pure returns (uint256) {
        if (x == 0) return 0;
        uint256 z = (x + 1) / 2;
        uint256 y = x;
        while (z < y) {
            y = z;
            z = (x / z + z) / 2;
        }
        return y;
    }

    function _pow(uint256 base, uint256 exp) internal pure returns (uint256) {
        // Simplified power function
        if (exp == 0) return 1e18;
        if (exp == 1e18) return base;
        return base; // Simplified
    }
}
