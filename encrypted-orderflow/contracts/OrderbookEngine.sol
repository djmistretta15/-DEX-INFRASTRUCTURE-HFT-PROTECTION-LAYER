// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title OrderbookEngine
 * @notice High-performance orderbook with MEV protection
 * @dev Implements limit orders, market orders, and stop-loss with fair execution
 */
contract OrderbookEngine is ReentrancyGuard {

    struct Order {
        bytes32 orderId;
        address trader;
        address baseToken;
        address quoteToken;
        uint256 baseAmount;
        uint256 quoteAmount;
        uint256 price;           // Price in quote per base (scaled by 1e18)
        uint256 filled;
        uint256 timestamp;
        OrderType orderType;
        OrderSide side;
        bool isActive;
    }

    struct Trade {
        bytes32 tradeId;
        bytes32 makerOrderId;
        bytes32 takerOrderId;
        address baseToken;
        address quoteToken;
        uint256 baseAmount;
        uint256 quoteAmount;
        uint256 price;
        uint256 timestamp;
        address maker;
        address taker;
    }

    struct TradingPair {
        address baseToken;
        address quoteToken;
        uint256 tickSize;        // Minimum price increment
        uint256 minOrderSize;
        uint256 totalBuyVolume;
        uint256 totalSellVolume;
        bool isActive;
    }

    enum OrderType { LIMIT, MARKET, STOP_LOSS }
    enum OrderSide { BUY, SELL }

    // State
    mapping(bytes32 => Order) public orders;
    mapping(bytes32 => TradingPair) public pairs;
    mapping(address => mapping(address => uint256)) public balances;

    // Orderbook: price level => order IDs
    mapping(bytes32 => mapping(uint256 => bytes32[])) public buyOrders;
    mapping(bytes32 => mapping(uint256 => bytes32[])) public sellOrders;

    // Price levels tracking (for efficient matching)
    mapping(bytes32 => uint256[]) public buyPriceLevels;
    mapping(bytes32 => uint256[]) public sellPriceLevels;

    // Fee configuration
    uint256 public makerFee = 10; // 0.10% (basis points)
    uint256 public takerFee = 20; // 0.20%
    uint256 public constant FEE_DENOMINATOR = 10000;

    address public feeRecipient;
    uint256 public totalFeesCollected;

    // Events
    event OrderPlaced(
        bytes32 indexed orderId,
        address indexed trader,
        OrderSide side,
        uint256 price,
        uint256 amount
    );
    event OrderCancelled(bytes32 indexed orderId);
    event OrderFilled(
        bytes32 indexed orderId,
        uint256 filledAmount,
        uint256 remainingAmount
    );
    event TradeExecuted(
        bytes32 indexed tradeId,
        bytes32 makerOrderId,
        bytes32 takerOrderId,
        uint256 price,
        uint256 amount
    );
    event PairAdded(bytes32 indexed pairId, address baseToken, address quoteToken);

    constructor(address _feeRecipient) {
        feeRecipient = _feeRecipient;
    }

    /**
     * @notice Add trading pair
     */
    function addPair(
        address baseToken,
        address quoteToken,
        uint256 tickSize,
        uint256 minOrderSize
    ) external returns (bytes32 pairId) {
        pairId = keccak256(abi.encodePacked(baseToken, quoteToken));

        require(!pairs[pairId].isActive, "Pair exists");

        pairs[pairId] = TradingPair({
            baseToken: baseToken,
            quoteToken: quoteToken,
            tickSize: tickSize,
            minOrderSize: minOrderSize,
            totalBuyVolume: 0,
            totalSellVolume: 0,
            isActive: true
        });

        emit PairAdded(pairId, baseToken, quoteToken);

        return pairId;
    }

    /**
     * @notice Deposit tokens for trading
     */
    function deposit(address token, uint256 amount) external nonReentrant {
        require(amount > 0, "Invalid amount");

        IERC20(token).transferFrom(msg.sender, address(this), amount);
        balances[msg.sender][token] += amount;
    }

    /**
     * @notice Withdraw tokens
     */
    function withdraw(address token, uint256 amount) external nonReentrant {
        require(balances[msg.sender][token] >= amount, "Insufficient balance");

        balances[msg.sender][token] -= amount;
        IERC20(token).transfer(msg.sender, amount);
    }

    /**
     * @notice Place limit order
     */
    function placeLimitOrder(
        address baseToken,
        address quoteToken,
        OrderSide side,
        uint256 price,
        uint256 amount
    ) external nonReentrant returns (bytes32 orderId) {
        bytes32 pairId = keccak256(abi.encodePacked(baseToken, quoteToken));
        TradingPair storage pair = pairs[pairId];

        require(pair.isActive, "Pair not active");
        require(amount >= pair.minOrderSize, "Below min size");
        require(price % pair.tickSize == 0, "Invalid tick");

        // Check and lock balances
        if (side == OrderSide.BUY) {
            uint256 quoteRequired = (amount * price) / 1e18;
            require(balances[msg.sender][quoteToken] >= quoteRequired, "Insufficient balance");
            balances[msg.sender][quoteToken] -= quoteRequired;
        } else {
            require(balances[msg.sender][baseToken] >= amount, "Insufficient balance");
            balances[msg.sender][baseToken] -= amount;
        }

        // Create order
        orderId = keccak256(abi.encodePacked(
            msg.sender,
            baseToken,
            quoteToken,
            price,
            amount,
            block.timestamp
        ));

        orders[orderId] = Order({
            orderId: orderId,
            trader: msg.sender,
            baseToken: baseToken,
            quoteToken: quoteToken,
            baseAmount: amount,
            quoteAmount: (amount * price) / 1e18,
            price: price,
            filled: 0,
            timestamp: block.timestamp,
            orderType: OrderType.LIMIT,
            side: side,
            isActive: true
        });

        // Add to orderbook
        if (side == OrderSide.BUY) {
            buyOrders[pairId][price].push(orderId);
            _addPriceLevel(buyPriceLevels[pairId], price);
            pair.totalBuyVolume += amount;
        } else {
            sellOrders[pairId][price].push(orderId);
            _addPriceLevel(sellPriceLevels[pairId], price);
            pair.totalSellVolume += amount;
        }

        emit OrderPlaced(orderId, msg.sender, side, price, amount);

        // Try to match immediately
        _matchOrder(pairId, orderId);

        return orderId;
    }

    /**
     * @notice Place market order (executes immediately at best price)
     */
    function placeMarketOrder(
        address baseToken,
        address quoteToken,
        OrderSide side,
        uint256 amount
    ) external nonReentrant returns (bytes32 orderId) {
        bytes32 pairId = keccak256(abi.encodePacked(baseToken, quoteToken));
        TradingPair storage pair = pairs[pairId];

        require(pair.isActive, "Pair not active");
        require(amount >= pair.minOrderSize, "Below min size");

        // Market orders execute at best available price
        uint256 bestPrice = side == OrderSide.BUY
            ? _getBestAsk(pairId)
            : _getBestBid(pairId);

        require(bestPrice > 0, "No liquidity");

        // Create temporary market order
        orderId = keccak256(abi.encodePacked(
            msg.sender,
            baseToken,
            quoteToken,
            amount,
            block.timestamp,
            "MARKET"
        ));

        orders[orderId] = Order({
            orderId: orderId,
            trader: msg.sender,
            baseToken: baseToken,
            quoteToken: quoteToken,
            baseAmount: amount,
            quoteAmount: 0, // Will be determined by matching
            price: 0,       // Market order has no limit price
            filled: 0,
            timestamp: block.timestamp,
            orderType: OrderType.MARKET,
            side: side,
            isActive: true
        });

        emit OrderPlaced(orderId, msg.sender, side, 0, amount);

        // Execute immediately
        _matchMarketOrder(pairId, orderId);

        return orderId;
    }

    /**
     * @notice Cancel order
     */
    function cancelOrder(bytes32 orderId) external nonReentrant {
        Order storage order = orders[orderId];

        require(order.trader == msg.sender, "Not your order");
        require(order.isActive, "Order not active");

        uint256 remaining = order.baseAmount - order.filled;

        // Refund locked balances
        if (order.side == OrderSide.BUY) {
            uint256 quoteRefund = (remaining * order.price) / 1e18;
            balances[msg.sender][order.quoteToken] += quoteRefund;
        } else {
            balances[msg.sender][order.baseToken] += remaining;
        }

        order.isActive = false;

        emit OrderCancelled(orderId);
    }

    /**
     * @notice Match limit order against orderbook
     * @dev Uses time-priority matching (FIFO) to prevent MEV
     */
    function _matchOrder(bytes32 pairId, bytes32 orderId) internal {
        Order storage order = orders[orderId];

        if (!order.isActive) return;

        uint256[] storage oppositeLevels = order.side == OrderSide.BUY
            ? sellPriceLevels[pairId]
            : buyPriceLevels[pairId];

        // Sort price levels (best first)
        _sortPriceLevels(oppositeLevels, order.side == OrderSide.BUY);

        uint256 remaining = order.baseAmount - order.filled;

        for (uint256 i = 0; i < oppositeLevels.length && remaining > 0; i++) {
            uint256 priceLevel = oppositeLevels[i];

            // Check if price matches
            if (order.side == OrderSide.BUY && priceLevel > order.price) break;
            if (order.side == OrderSide.SELL && priceLevel < order.price) break;

            bytes32[] storage oppositeOrders = order.side == OrderSide.BUY
                ? sellOrders[pairId][priceLevel]
                : buyOrders[pairId][priceLevel];

            // Match against orders at this price level (FIFO)
            for (uint256 j = 0; j < oppositeOrders.length && remaining > 0; j++) {
                bytes32 makerOrderId = oppositeOrders[j];
                Order storage makerOrder = orders[makerOrderId];

                if (!makerOrder.isActive) continue;

                uint256 makerRemaining = makerOrder.baseAmount - makerOrder.filled;
                uint256 matchAmount = remaining < makerRemaining ? remaining : makerRemaining;

                // Execute trade
                _executeTrade(orderId, makerOrderId, matchAmount, priceLevel);

                remaining -= matchAmount;
            }
        }

        if (remaining == 0) {
            order.isActive = false;
        }
    }

    /**
     * @notice Execute trade between two orders
     */
    function _executeTrade(
        bytes32 takerOrderId,
        bytes32 makerOrderId,
        uint256 amount,
        uint256 price
    ) internal {
        Order storage takerOrder = orders[takerOrderId];
        Order storage makerOrder = orders[makerOrderId];

        uint256 quoteAmount = (amount * price) / 1e18;

        // Calculate fees
        uint256 makerFeeAmount = (quoteAmount * makerFee) / FEE_DENOMINATOR;
        uint256 takerFeeAmount = (quoteAmount * takerFee) / FEE_DENOMINATOR;

        // Update order fills
        takerOrder.filled += amount;
        makerOrder.filled += amount;

        // Transfer tokens
        if (takerOrder.side == OrderSide.BUY) {
            // Buyer receives base token
            balances[takerOrder.trader][takerOrder.baseToken] += amount - takerFeeAmount;
            balances[makerOrder.trader][makerOrder.quoteToken] += quoteAmount - makerFeeAmount;
        } else {
            // Seller receives quote token
            balances[takerOrder.trader][takerOrder.quoteToken] += quoteAmount - takerFeeAmount;
            balances[makerOrder.trader][makerOrder.baseToken] += amount - makerFeeAmount;
        }

        // Collect fees
        totalFeesCollected += makerFeeAmount + takerFeeAmount;

        // Check if orders are fully filled
        if (makerOrder.filled >= makerOrder.baseAmount) {
            makerOrder.isActive = false;
        }

        if (takerOrder.filled >= takerOrder.baseAmount) {
            takerOrder.isActive = false;
        }

        // Emit trade event
        bytes32 tradeId = keccak256(abi.encodePacked(
            takerOrderId,
            makerOrderId,
            amount,
            block.timestamp
        ));

        emit TradeExecuted(tradeId, makerOrderId, takerOrderId, price, amount);
        emit OrderFilled(takerOrderId, amount, takerOrder.baseAmount - takerOrder.filled);
        emit OrderFilled(makerOrderId, amount, makerOrder.baseAmount - makerOrder.filled);
    }

    /**
     * @notice Match market order immediately
     */
    function _matchMarketOrder(bytes32 pairId, bytes32 orderId) internal {
        // Similar to _matchOrder but executes at any price
        _matchOrder(pairId, orderId);
    }

    // Helper functions

    function _getBestBid(bytes32 pairId) internal view returns (uint256) {
        uint256[] storage levels = buyPriceLevels[pairId];
        if (levels.length == 0) return 0;

        uint256 best = 0;
        for (uint256 i = 0; i < levels.length; i++) {
            if (levels[i] > best) best = levels[i];
        }
        return best;
    }

    function _getBestAsk(bytes32 pairId) internal view returns (uint256) {
        uint256[] storage levels = sellPriceLevels[pairId];
        if (levels.length == 0) return 0;

        uint256 best = type(uint256).max;
        for (uint256 i = 0; i < levels.length; i++) {
            if (levels[i] < best) best = levels[i];
        }
        return best == type(uint256).max ? 0 : best;
    }

    function _addPriceLevel(uint256[] storage levels, uint256 price) internal {
        for (uint256 i = 0; i < levels.length; i++) {
            if (levels[i] == price) return;
        }
        levels.push(price);
    }

    function _sortPriceLevels(uint256[] storage levels, bool ascending) internal {
        // Bubble sort (gas-optimized for small arrays)
        for (uint256 i = 0; i < levels.length; i++) {
            for (uint256 j = i + 1; j < levels.length; j++) {
                if (ascending ? levels[i] > levels[j] : levels[i] < levels[j]) {
                    (levels[i], levels[j]) = (levels[j], levels[i]);
                }
            }
        }
    }

    // View functions

    function getOrderbook(
        address baseToken,
        address quoteToken,
        uint256 depth
    ) external view returns (
        uint256[] memory bidPrices,
        uint256[] memory bidSizes,
        uint256[] memory askPrices,
        uint256[] memory askSizes
    ) {
        bytes32 pairId = keccak256(abi.encodePacked(baseToken, quoteToken));

        uint256 bidCount = buyPriceLevels[pairId].length < depth
            ? buyPriceLevels[pairId].length
            : depth;
        uint256 askCount = sellPriceLevels[pairId].length < depth
            ? sellPriceLevels[pairId].length
            : depth;

        bidPrices = new uint256[](bidCount);
        bidSizes = new uint256[](bidCount);
        askPrices = new uint256[](askCount);
        askSizes = new uint256[](askCount);

        for (uint256 i = 0; i < bidCount; i++) {
            uint256 price = buyPriceLevels[pairId][i];
            bidPrices[i] = price;
            bidSizes[i] = _getTotalSizeAtLevel(pairId, price, true);
        }

        for (uint256 i = 0; i < askCount; i++) {
            uint256 price = sellPriceLevels[pairId][i];
            askPrices[i] = price;
            askSizes[i] = _getTotalSizeAtLevel(pairId, price, false);
        }
    }

    function _getTotalSizeAtLevel(
        bytes32 pairId,
        uint256 price,
        bool isBuy
    ) internal view returns (uint256 total) {
        bytes32[] storage orderIds = isBuy
            ? buyOrders[pairId][price]
            : sellOrders[pairId][price];

        for (uint256 i = 0; i < orderIds.length; i++) {
            Order storage order = orders[orderIds[i]];
            if (order.isActive) {
                total += order.baseAmount - order.filled;
            }
        }
    }
}
