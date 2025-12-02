// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * PERPETUAL SWAP ENGINE
 *
 * HYPOTHESIS: A high-performance perpetual swap engine with dynamic funding
 * rates and efficient liquidation will enable deep liquidity with spreads
 * <5 basis points and >$1B daily volume capacity.
 *
 * SUCCESS METRICS:
 * - Average spread: <5 basis points
 * - Daily volume capacity: >$1B
 * - Funding rate convergence: <1% deviation from spot
 * - Liquidation efficiency: >98%
 * - System solvency: 100%
 *
 * SECURITY CONSIDERATIONS:
 * - Price manipulation protection
 * - Funding rate bounds
 * - Insurance fund backstop
 * - Auto-deleveraging mechanism
 * - Oracle redundancy
 */

// Position info
struct Position {
    uint128 size; // Position size in contracts
    uint128 margin; // Collateral amount
    uint128 openNotional; // Entry value
    int128 lastCumulativeFunding; // Last funding checkpoint
    bool isLong;
}

// Market state
struct Market {
    uint128 baseAssetReserve;
    uint128 quoteAssetReserve;
    int128 totalLongPositionSize;
    int128 totalShortPositionSize;
    uint128 openInterest;
    int128 cumulativeFundingRate;
    uint128 fundingPeriod;
    uint128 lastFundingTime;
    uint128 maxFundingRate;
    uint128 minFundingRate;
    bool isActive;
}

// Insurance fund
struct InsuranceFund {
    uint128 balance;
    uint128 minBalance;
    uint128 maxWithdrawal;
}

// Trade params
struct TradeParams {
    address trader;
    uint128 amount;
    uint128 leverage;
    bool isLong;
    bool isOpen;
    uint128 minOutput;
}

// Funding payment info
struct FundingPayment {
    int128 payment;
    int128 rate;
    uint128 timestamp;
}

// Oracle interface
interface IOracle {
    function getPrice(address asset) external view returns (uint256);
    function getTWAP(address asset, uint256 interval) external view returns (uint256);
}

contract PerpetualSwapEngine is ReentrancyGuard, Pausable, AccessControl {
    using SafeERC20 for IERC20;

    // Roles
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant LIQUIDATOR_ROLE = keccak256("LIQUIDATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    // Settlement token (USDC)
    IERC20 public immutable settlementToken;

    // Oracle
    IOracle public oracle;

    // Markets (base asset => market)
    mapping(address => Market) public markets;
    address[] public marketList;

    // Positions (market => trader => position)
    mapping(address => mapping(address => Position)) public positions;

    // Insurance funds (market => fund)
    mapping(address => InsuranceFund) public insuranceFunds;

    // Configuration
    uint128 public constant PRICE_PRECISION = 1e18;
    uint128 public constant FUNDING_PRECISION = 1e18;
    uint128 public constant LEVERAGE_PRECISION = 100; // 1x = 100
    uint128 public maxLeverage = 12500; // 125x
    uint128 public minMargin = 10e18; // $10
    uint128 public maintenanceMarginRatio = 500; // 5%
    uint128 public partialLiquidationRatio = 5000; // 50%
    uint128 public liquidationFeeRatio = 100; // 1%
    uint128 public tradingFeeRatio = 10; // 0.1%

    // AMM parameters (for virtual AMM)
    uint128 public constant K_PRECISION = 1e36;
    uint128 public fluctuationLimit = 1000; // 10% max price impact

    // Events
    event PositionOpened(
        address indexed trader,
        address indexed market,
        bool isLong,
        uint128 size,
        uint128 margin,
        uint128 openNotional,
        uint128 avgPrice
    );

    event PositionClosed(
        address indexed trader,
        address indexed market,
        uint128 size,
        int128 realizedPnL,
        uint128 closingPrice
    );

    event PositionLiquidated(
        address indexed trader,
        address indexed market,
        address indexed liquidator,
        uint128 size,
        uint128 penalty,
        uint128 insuranceFundContribution
    );

    event FundingPaid(
        address indexed market,
        int128 fundingRate,
        int128 cumulativeFunding,
        uint128 timestamp
    );

    event MarketCreated(
        address indexed baseAsset,
        uint128 baseReserve,
        uint128 quoteReserve
    );

    constructor(address _settlementToken, address _oracle) {
        settlementToken = IERC20(_settlementToken);
        oracle = IOracle(_oracle);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);
    }

    /**
     * Create new perpetual market
     */
    function createMarket(
        address baseAsset,
        uint128 baseReserve,
        uint128 quoteReserve,
        uint128 fundingPeriod
    ) external onlyRole(OPERATOR_ROLE) {
        require(baseReserve > 0 && quoteReserve > 0, "Invalid reserves");
        require(!markets[baseAsset].isActive, "Market exists");

        markets[baseAsset] = Market({
            baseAssetReserve: baseReserve,
            quoteAssetReserve: quoteReserve,
            totalLongPositionSize: 0,
            totalShortPositionSize: 0,
            openInterest: 0,
            cumulativeFundingRate: 0,
            fundingPeriod: fundingPeriod,
            lastFundingTime: uint128(block.timestamp),
            maxFundingRate: 100, // 1% max
            minFundingRate: 100, // -1% min (stored as positive)
            isActive: true
        });

        insuranceFunds[baseAsset] = InsuranceFund({
            balance: 0,
            minBalance: 100000e18, // $100k min
            maxWithdrawal: 10000e18 // $10k max per withdrawal
        });

        marketList.push(baseAsset);

        emit MarketCreated(baseAsset, baseReserve, quoteReserve);
    }

    /**
     * Open or increase position
     */
    function openPosition(
        address baseAsset,
        uint128 amount,
        uint128 leverage,
        bool isLong,
        uint128 minBaseAmount
    ) external nonReentrant whenNotPaused returns (uint128 baseAssetAmount) {
        Market storage market = markets[baseAsset];
        require(market.isActive, "Market not active");
        require(leverage >= LEVERAGE_PRECISION && leverage <= maxLeverage, "Invalid leverage");

        // Settle funding before trade
        _settleFunding(baseAsset);

        // Calculate trade
        uint128 quoteAmount = amount * leverage / LEVERAGE_PRECISION;
        baseAssetAmount = _swapInput(market, isLong, quoteAmount);

        require(baseAssetAmount >= minBaseAmount, "Slippage too high");

        // Check price impact
        _checkFluctuation(market, baseAsset);

        // Transfer margin
        settlementToken.safeTransferFrom(msg.sender, address(this), amount);

        // Calculate fees
        uint128 fees = quoteAmount * tradingFeeRatio / 10000;
        insuranceFunds[baseAsset].balance += uint128(fees);

        // Update position
        Position storage position = positions[baseAsset][msg.sender];

        if (position.size == 0) {
            // New position
            position.size = baseAssetAmount;
            position.margin = amount - uint128(fees);
            position.openNotional = quoteAmount;
            position.isLong = isLong;
            position.lastCumulativeFunding = market.cumulativeFundingRate;
        } else {
            // Increase existing position
            require(position.isLong == isLong, "Use close position to reverse");

            position.size += baseAssetAmount;
            position.margin += amount - uint128(fees);
            position.openNotional += quoteAmount;
        }

        // Update market state
        if (isLong) {
            market.totalLongPositionSize += int128(uint128(baseAssetAmount));
        } else {
            market.totalShortPositionSize += int128(uint128(baseAssetAmount));
        }
        market.openInterest += quoteAmount;

        // Validate margin ratio
        require(_isMarginSafe(position, market, baseAsset), "Insufficient margin");

        emit PositionOpened(
            msg.sender,
            baseAsset,
            isLong,
            baseAssetAmount,
            amount,
            quoteAmount,
            quoteAmount * PRICE_PRECISION / baseAssetAmount
        );

        return baseAssetAmount;
    }

    /**
     * Close or reduce position
     */
    function closePosition(
        address baseAsset,
        uint128 amount,
        uint128 minQuoteAmount
    ) external nonReentrant whenNotPaused returns (int128 realizedPnL) {
        Market storage market = markets[baseAsset];
        Position storage position = positions[baseAsset][msg.sender];

        require(position.size > 0, "No position");
        require(amount <= position.size, "Amount exceeds position");

        // Settle funding
        _settleFunding(baseAsset);
        int128 fundingPayment = _calculateFundingPayment(position, market);

        // Calculate closing value
        uint128 quoteAmount = _swapOutput(market, position.isLong, amount);
        require(quoteAmount >= minQuoteAmount, "Slippage too high");

        // Calculate PnL
        uint128 openNotionalForAmount = position.openNotional * amount / position.size;

        if (position.isLong) {
            realizedPnL = int128(quoteAmount) - int128(openNotionalForAmount);
        } else {
            realizedPnL = int128(openNotionalForAmount) - int128(quoteAmount);
        }

        // Apply funding payment
        realizedPnL += fundingPayment;

        // Calculate fees
        uint128 fees = quoteAmount * tradingFeeRatio / 10000;
        insuranceFunds[baseAsset].balance += uint128(fees);
        realizedPnL -= int128(uint128(fees));

        // Update position
        uint128 marginToReturn;
        if (amount == position.size) {
            // Full close
            marginToReturn = position.margin;
            delete positions[baseAsset][msg.sender];
        } else {
            // Partial close
            uint128 marginPortion = position.margin * amount / position.size;
            position.margin -= marginPortion;
            position.size -= amount;
            position.openNotional -= openNotionalForAmount;
            marginToReturn = marginPortion;
        }

        // Update market state
        if (position.isLong) {
            market.totalLongPositionSize -= int128(uint128(amount));
        } else {
            market.totalShortPositionSize -= int128(uint128(amount));
        }
        market.openInterest -= openNotionalForAmount;

        // Transfer funds
        if (realizedPnL >= 0) {
            uint128 totalReturn = marginToReturn + uint128(realizedPnL);
            settlementToken.safeTransfer(msg.sender, totalReturn);
        } else {
            uint128 loss = uint128(-realizedPnL);
            if (loss >= marginToReturn) {
                // Loss exceeds margin - use insurance fund
                uint128 shortfall = loss - marginToReturn;
                if (insuranceFunds[baseAsset].balance >= shortfall) {
                    insuranceFunds[baseAsset].balance -= shortfall;
                }
            } else {
                settlementToken.safeTransfer(msg.sender, marginToReturn - loss);
            }
        }

        emit PositionClosed(
            msg.sender,
            baseAsset,
            amount,
            realizedPnL,
            quoteAmount * PRICE_PRECISION / amount
        );

        return realizedPnL;
    }

    /**
     * Liquidate undercollateralized position
     */
    function liquidate(
        address baseAsset,
        address trader
    ) external nonReentrant onlyRole(LIQUIDATOR_ROLE) {
        Market storage market = markets[baseAsset];
        Position storage position = positions[baseAsset][trader];

        require(position.size > 0, "No position");
        require(!_isMarginSafe(position, market, baseAsset), "Position is safe");

        // Settle funding
        _settleFunding(baseAsset);

        // Calculate liquidation amount (partial or full)
        uint128 liquidationSize;
        if (_getMarginRatio(position, market, baseAsset) < maintenanceMarginRatio / 2) {
            // Full liquidation
            liquidationSize = position.size;
        } else {
            // Partial liquidation
            liquidationSize = position.size * uint128(partialLiquidationRatio) / 10000;
        }

        // Close position at mark price
        uint128 quoteAmount = _swapOutput(market, position.isLong, liquidationSize);

        // Calculate penalty
        uint128 penalty = quoteAmount * liquidationFeeRatio / 10000;
        uint128 liquidatorReward = penalty / 2;
        uint128 insuranceContribution = penalty - liquidatorReward;

        // Update position
        uint128 openNotionalForAmount = position.openNotional * liquidationSize / position.size;

        if (liquidationSize == position.size) {
            // Full liquidation
            insuranceFunds[baseAsset].balance += position.margin - liquidatorReward;
            delete positions[baseAsset][trader];
        } else {
            // Partial liquidation
            uint128 marginPortion = position.margin * liquidationSize / position.size;
            position.margin -= marginPortion;
            position.size -= liquidationSize;
            position.openNotional -= openNotionalForAmount;
            insuranceFunds[baseAsset].balance += marginPortion - liquidatorReward;
        }

        // Update market state
        if (position.isLong) {
            market.totalLongPositionSize -= int128(uint128(liquidationSize));
        } else {
            market.totalShortPositionSize -= int128(uint128(liquidationSize));
        }
        market.openInterest -= openNotionalForAmount;

        // Pay liquidator
        settlementToken.safeTransfer(msg.sender, liquidatorReward);

        emit PositionLiquidated(
            trader,
            baseAsset,
            msg.sender,
            liquidationSize,
            penalty,
            insuranceContribution
        );
    }

    /**
     * Settle funding rate
     */
    function settleFunding(address baseAsset) external {
        _settleFunding(baseAsset);
    }

    /**
     * Get mark price (from AMM)
     */
    function getMarkPrice(address baseAsset) public view returns (uint128) {
        Market storage market = markets[baseAsset];
        return uint128(market.quoteAssetReserve * PRICE_PRECISION / market.baseAssetReserve);
    }

    /**
     * Get index price (from oracle)
     */
    function getIndexPrice(address baseAsset) public view returns (uint128) {
        return uint128(oracle.getPrice(baseAsset));
    }

    /**
     * Get position info
     */
    function getPosition(
        address baseAsset,
        address trader
    ) external view returns (
        uint128 size,
        uint128 margin,
        uint128 openNotional,
        bool isLong,
        int128 unrealizedPnL,
        uint128 marginRatio
    ) {
        Position storage position = positions[baseAsset][trader];
        Market storage market = markets[baseAsset];

        if (position.size == 0) {
            return (0, 0, 0, false, 0, 0);
        }

        unrealizedPnL = _calculateUnrealizedPnL(position, market);
        marginRatio = _getMarginRatio(position, market, baseAsset);

        return (
            position.size,
            position.margin,
            position.openNotional,
            position.isLong,
            unrealizedPnL,
            marginRatio
        );
    }

    /**
     * Get funding rate
     */
    function getFundingRate(address baseAsset) external view returns (int128) {
        Market storage market = markets[baseAsset];
        uint128 markPrice = getMarkPrice(baseAsset);
        uint128 indexPrice = getIndexPrice(baseAsset);

        return _calculateFundingRate(markPrice, indexPrice, market);
    }

    /**
     * Add margin to position
     */
    function addMargin(address baseAsset, uint128 amount) external nonReentrant {
        Position storage position = positions[baseAsset][msg.sender];
        require(position.size > 0, "No position");

        settlementToken.safeTransferFrom(msg.sender, address(this), amount);
        position.margin += amount;
    }

    /**
     * Remove margin from position
     */
    function removeMargin(address baseAsset, uint128 amount) external nonReentrant {
        Position storage position = positions[baseAsset][msg.sender];
        Market storage market = markets[baseAsset];
        require(position.size > 0, "No position");

        position.margin -= amount;
        require(_isMarginSafe(position, market, baseAsset), "Insufficient margin");

        settlementToken.safeTransfer(msg.sender, amount);
    }

    /**
     * Get market statistics
     */
    function getMarketStats(address baseAsset) external view returns (
        uint128 markPrice,
        uint128 indexPrice,
        int128 totalLongSize,
        int128 totalShortSize,
        uint128 openInterest,
        int128 fundingRate
    ) {
        Market storage market = markets[baseAsset];

        return (
            getMarkPrice(baseAsset),
            getIndexPrice(baseAsset),
            market.totalLongPositionSize,
            market.totalShortPositionSize,
            market.openInterest,
            _calculateFundingRate(getMarkPrice(baseAsset), getIndexPrice(baseAsset), market)
        );
    }

    // Internal functions

    function _swapInput(
        Market storage market,
        bool isLong,
        uint128 quoteAmount
    ) internal returns (uint128 baseAmount) {
        uint256 k = uint256(market.baseAssetReserve) * uint256(market.quoteAssetReserve);

        if (isLong) {
            // Buy base asset
            uint128 newQuoteReserve = market.quoteAssetReserve + quoteAmount;
            uint128 newBaseReserve = uint128(k / uint256(newQuoteReserve));
            baseAmount = market.baseAssetReserve - newBaseReserve;

            market.quoteAssetReserve = newQuoteReserve;
            market.baseAssetReserve = newBaseReserve;
        } else {
            // Sell base asset
            uint128 newQuoteReserve = market.quoteAssetReserve - quoteAmount;
            uint128 newBaseReserve = uint128(k / uint256(newQuoteReserve));
            baseAmount = newBaseReserve - market.baseAssetReserve;

            market.quoteAssetReserve = newQuoteReserve;
            market.baseAssetReserve = newBaseReserve;
        }
    }

    function _swapOutput(
        Market storage market,
        bool isLong,
        uint128 baseAmount
    ) internal returns (uint128 quoteAmount) {
        uint256 k = uint256(market.baseAssetReserve) * uint256(market.quoteAssetReserve);

        if (isLong) {
            // Sell base asset (close long)
            uint128 newBaseReserve = market.baseAssetReserve + baseAmount;
            uint128 newQuoteReserve = uint128(k / uint256(newBaseReserve));
            quoteAmount = market.quoteAssetReserve - newQuoteReserve;

            market.baseAssetReserve = newBaseReserve;
            market.quoteAssetReserve = newQuoteReserve;
        } else {
            // Buy base asset (close short)
            uint128 newBaseReserve = market.baseAssetReserve - baseAmount;
            uint128 newQuoteReserve = uint128(k / uint256(newBaseReserve));
            quoteAmount = newQuoteReserve - market.quoteAssetReserve;

            market.baseAssetReserve = newBaseReserve;
            market.quoteAssetReserve = newQuoteReserve;
        }
    }

    function _settleFunding(address baseAsset) internal {
        Market storage market = markets[baseAsset];

        if (block.timestamp < market.lastFundingTime + market.fundingPeriod) {
            return;
        }

        uint128 markPrice = getMarkPrice(baseAsset);
        uint128 indexPrice = getIndexPrice(baseAsset);

        int128 fundingRate = _calculateFundingRate(markPrice, indexPrice, market);

        // Apply funding rate limits
        if (fundingRate > int128(uint128(market.maxFundingRate))) {
            fundingRate = int128(uint128(market.maxFundingRate));
        } else if (fundingRate < -int128(uint128(market.minFundingRate))) {
            fundingRate = -int128(uint128(market.minFundingRate));
        }

        market.cumulativeFundingRate += fundingRate;
        market.lastFundingTime = uint128(block.timestamp);

        emit FundingPaid(
            baseAsset,
            fundingRate,
            market.cumulativeFundingRate,
            uint128(block.timestamp)
        );
    }

    function _calculateFundingRate(
        uint128 markPrice,
        uint128 indexPrice,
        Market storage market
    ) internal view returns (int128) {
        // Funding rate = (mark price - index price) / index price / funding period
        int128 priceDiff = int128(markPrice) - int128(indexPrice);
        int128 rate = (priceDiff * int128(FUNDING_PRECISION)) / int128(indexPrice);

        // Adjust for funding period (e.g., 8 hours = 3 periods per day)
        return rate / int128(uint128(24 hours / market.fundingPeriod));
    }

    function _calculateFundingPayment(
        Position storage position,
        Market storage market
    ) internal view returns (int128) {
        int128 fundingDelta = market.cumulativeFundingRate - position.lastCumulativeFunding;

        if (position.isLong) {
            // Longs pay when funding is positive
            return -int128(uint128(position.size)) * fundingDelta / int128(FUNDING_PRECISION);
        } else {
            // Shorts receive when funding is positive
            return int128(uint128(position.size)) * fundingDelta / int128(FUNDING_PRECISION);
        }
    }

    function _calculateUnrealizedPnL(
        Position storage position,
        Market storage market
    ) internal view returns (int128) {
        uint128 currentNotional = position.size * market.quoteAssetReserve / market.baseAssetReserve;

        if (position.isLong) {
            return int128(currentNotional) - int128(position.openNotional);
        } else {
            return int128(position.openNotional) - int128(currentNotional);
        }
    }

    function _getMarginRatio(
        Position storage position,
        Market storage market,
        address baseAsset
    ) internal view returns (uint128) {
        int128 unrealizedPnL = _calculateUnrealizedPnL(position, market);
        int128 fundingPayment = _calculateFundingPayment(position, market);

        int128 accountValue = int128(position.margin) + unrealizedPnL + fundingPayment;

        if (accountValue <= 0) {
            return 0;
        }

        uint128 positionNotional = position.size * market.quoteAssetReserve / market.baseAssetReserve;

        return uint128(accountValue) * 10000 / positionNotional;
    }

    function _isMarginSafe(
        Position storage position,
        Market storage market,
        address baseAsset
    ) internal view returns (bool) {
        return _getMarginRatio(position, market, baseAsset) >= maintenanceMarginRatio;
    }

    function _checkFluctuation(Market storage market, address baseAsset) internal view {
        uint128 markPrice = getMarkPrice(baseAsset);
        uint128 indexPrice = getIndexPrice(baseAsset);

        uint128 diff = markPrice > indexPrice
            ? markPrice - indexPrice
            : indexPrice - markPrice;

        uint128 ratio = diff * 10000 / indexPrice;
        require(ratio <= fluctuationLimit, "Price impact too high");
    }

    /**
     * Pause market
     */
    function pauseMarket(address baseAsset) external onlyRole(GUARDIAN_ROLE) {
        markets[baseAsset].isActive = false;
    }

    /**
     * Unpause market
     */
    function unpauseMarket(address baseAsset) external onlyRole(GUARDIAN_ROLE) {
        markets[baseAsset].isActive = true;
    }

    /**
     * Update oracle
     */
    function updateOracle(address newOracle) external onlyRole(OPERATOR_ROLE) {
        oracle = IOracle(newOracle);
    }

    /**
     * Emergency pause all
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * Unpause all
     */
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }
}
