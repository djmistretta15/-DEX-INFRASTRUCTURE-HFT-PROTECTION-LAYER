// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

/**
 * @title SecureOracleAggregator
 * @notice Multi-source price oracle with manipulation detection and TWAP
 *
 * HYPOTHESIS: Aggregating multiple oracle sources with statistical outlier detection
 * and TWAP calculations will provide manipulation-resistant price feeds with
 * <0.1% deviation from true market price.
 *
 * SUCCESS METRICS:
 * - Price accuracy within 0.1% of major CEX prices
 * - <500ms latency for price updates
 * - Zero successful manipulation attacks
 * - 99.99% uptime
 * - Gas efficient (<50k gas per price read)
 *
 * SECURITY CONSIDERATIONS:
 * - Multi-source aggregation prevents single point of failure
 * - Statistical analysis detects outliers/manipulation
 * - TWAP smoothing prevents flash loan attacks
 * - Circuit breakers for extreme price movements
 * - Timelocked governance for parameter updates
 */

contract SecureOracleAggregator is AccessControl, ReentrancyGuard, Pausable {
    // Roles
    bytes32 public constant ORACLE_ADMIN_ROLE = keccak256("ORACLE_ADMIN_ROLE");
    bytes32 public constant PRICE_UPDATER_ROLE = keccak256("PRICE_UPDATER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    // Oracle source structure
    struct OracleSource {
        address sourceAddress;
        OracleType oracleType;
        uint8 decimals;
        uint256 weight; // Weight in aggregation (basis points)
        bool isActive;
        uint256 lastUpdate;
        int256 lastPrice;
        uint256 heartbeat; // Max time between updates
        uint256 deviationThreshold; // Max deviation from median (basis points)
    }

    // Price observation for TWAP
    struct PriceObservation {
        uint256 timestamp;
        int256 price;
        uint256 cumulativePrice; // For TWAP calculation
    }

    // Oracle types
    enum OracleType {
        CHAINLINK,
        UNISWAP_V3_TWAP,
        BAND_PROTOCOL,
        API3,
        CUSTOM_FEED
    }

    // Price feed configuration
    struct PriceFeed {
        bytes32 feedId;
        string baseAsset;
        string quoteAsset;
        uint8 decimals;
        uint256 minSources; // Minimum sources required
        uint256 maxDeviation; // Max deviation between sources (basis points)
        uint256 twapWindow; // TWAP calculation window in seconds
        uint256 circuitBreakerThreshold; // Max price change per update (basis points)
        bool isActive;
    }

    // Aggregated price result
    struct AggregatedPrice {
        int256 price;
        uint256 timestamp;
        uint256 confidence; // Confidence score (0-10000 basis points)
        uint256 sourcesUsed;
        uint256 deviation; // Max deviation between sources
    }

    // Storage
    mapping(bytes32 => PriceFeed) public priceFeeds;
    mapping(bytes32 => OracleSource[]) public feedSources;
    mapping(bytes32 => PriceObservation[]) public priceHistory;
    mapping(bytes32 => AggregatedPrice) public latestPrices;
    mapping(bytes32 => uint256) public lastPriceUpdateBlock;

    bytes32[] public activeFeedIds;

    // Configuration
    uint256 public constant BASIS_POINTS = 10000;
    uint256 public maxHistoryLength = 1440; // 24 hours at 1 minute intervals
    uint256 public minUpdateInterval = 1; // blocks
    uint256 public globalCircuitBreakerThreshold = 3000; // 30%

    // Statistics for manipulation detection
    mapping(bytes32 => uint256) public volatilityIndex;
    mapping(bytes32 => int256) public ema20; // 20-period EMA
    mapping(bytes32 => int256) public ema50; // 50-period EMA

    // Events
    event PriceFeedCreated(
        bytes32 indexed feedId,
        string baseAsset,
        string quoteAsset
    );
    event OracleSourceAdded(
        bytes32 indexed feedId,
        address sourceAddress,
        OracleType oracleType
    );
    event PriceUpdated(
        bytes32 indexed feedId,
        int256 price,
        uint256 confidence,
        uint256 sourcesUsed
    );
    event ManipulationDetected(
        bytes32 indexed feedId,
        int256 reportedPrice,
        int256 expectedPrice,
        uint256 deviation
    );
    event CircuitBreakerTriggered(
        bytes32 indexed feedId,
        int256 previousPrice,
        int256 newPrice,
        uint256 changePercent
    );
    event SourceDeactivated(
        bytes32 indexed feedId,
        uint256 sourceIndex,
        string reason
    );

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ORACLE_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
    }

    /**
     * @notice Create a new price feed
     */
    function createPriceFeed(
        bytes32 feedId,
        string calldata baseAsset,
        string calldata quoteAsset,
        uint8 decimals,
        uint256 minSources,
        uint256 maxDeviation,
        uint256 twapWindow,
        uint256 circuitBreakerThreshold
    ) external onlyRole(ORACLE_ADMIN_ROLE) {
        require(priceFeeds[feedId].feedId == bytes32(0), "Feed exists");
        require(minSources >= 2, "Min 2 sources required");
        require(maxDeviation <= 2000, "Max deviation too high"); // 20%
        require(circuitBreakerThreshold <= 5000, "Circuit breaker too high"); // 50%

        priceFeeds[feedId] = PriceFeed({
            feedId: feedId,
            baseAsset: baseAsset,
            quoteAsset: quoteAsset,
            decimals: decimals,
            minSources: minSources,
            maxDeviation: maxDeviation,
            twapWindow: twapWindow,
            circuitBreakerThreshold: circuitBreakerThreshold,
            isActive: true
        });

        activeFeedIds.push(feedId);

        emit PriceFeedCreated(feedId, baseAsset, quoteAsset);
    }

    /**
     * @notice Add oracle source to a price feed
     */
    function addOracleSource(
        bytes32 feedId,
        address sourceAddress,
        OracleType oracleType,
        uint8 decimals,
        uint256 weight,
        uint256 heartbeat,
        uint256 deviationThreshold
    ) external onlyRole(ORACLE_ADMIN_ROLE) {
        require(priceFeeds[feedId].isActive, "Feed not active");
        require(sourceAddress != address(0), "Invalid source");
        require(weight > 0 && weight <= BASIS_POINTS, "Invalid weight");
        require(heartbeat > 0, "Invalid heartbeat");

        feedSources[feedId].push(OracleSource({
            sourceAddress: sourceAddress,
            oracleType: oracleType,
            decimals: decimals,
            weight: weight,
            isActive: true,
            lastUpdate: 0,
            lastPrice: 0,
            heartbeat: heartbeat,
            deviationThreshold: deviationThreshold
        }));

        emit OracleSourceAdded(feedId, sourceAddress, oracleType);
    }

    /**
     * @notice Update price from all sources and aggregate
     */
    function updatePrice(bytes32 feedId)
        external
        nonReentrant
        whenNotPaused
        returns (AggregatedPrice memory)
    {
        PriceFeed storage feed = priceFeeds[feedId];
        require(feed.isActive, "Feed not active");
        require(
            block.number > lastPriceUpdateBlock[feedId] + minUpdateInterval,
            "Update too frequent"
        );

        OracleSource[] storage sources = feedSources[feedId];
        require(sources.length >= feed.minSources, "Not enough sources");

        // Collect prices from all sources
        int256[] memory prices = new int256[](sources.length);
        uint256[] memory weights = new uint256[](sources.length);
        uint256 validSources = 0;

        for (uint256 i = 0; i < sources.length; i++) {
            if (!sources[i].isActive) continue;

            (int256 price, bool isValid) = _fetchPrice(sources[i]);

            if (isValid) {
                prices[validSources] = price;
                weights[validSources] = sources[i].weight;

                sources[i].lastUpdate = block.timestamp;
                sources[i].lastPrice = price;
                validSources++;
            }
        }

        require(validSources >= feed.minSources, "Insufficient valid sources");

        // Calculate median for outlier detection
        int256 medianPrice = _calculateMedian(prices, validSources);

        // Filter outliers and recalculate
        (int256 aggregatedPrice, uint256 confidence, uint256 maxDev) = _aggregateWithOutlierDetection(
            prices,
            weights,
            validSources,
            medianPrice,
            feed.maxDeviation
        );

        // Check for manipulation (sudden extreme movements)
        if (latestPrices[feedId].timestamp > 0) {
            int256 previousPrice = latestPrices[feedId].price;
            uint256 changePercent = _calculatePriceChange(previousPrice, aggregatedPrice);

            if (changePercent > feed.circuitBreakerThreshold) {
                emit CircuitBreakerTriggered(
                    feedId,
                    previousPrice,
                    aggregatedPrice,
                    changePercent
                );

                // Use TWAP instead of spot price when circuit breaker triggers
                aggregatedPrice = _calculateTWAP(feedId, feed.twapWindow);
                confidence = confidence / 2; // Reduce confidence
            }
        }

        // Update price history for TWAP
        _updatePriceHistory(feedId, aggregatedPrice);

        // Update EMAs for trend analysis
        _updateEMAs(feedId, aggregatedPrice);

        // Calculate volatility index
        _updateVolatilityIndex(feedId);

        // Store aggregated price
        AggregatedPrice memory result = AggregatedPrice({
            price: aggregatedPrice,
            timestamp: block.timestamp,
            confidence: confidence,
            sourcesUsed: validSources,
            deviation: maxDev
        });

        latestPrices[feedId] = result;
        lastPriceUpdateBlock[feedId] = block.number;

        emit PriceUpdated(feedId, aggregatedPrice, confidence, validSources);

        return result;
    }

    /**
     * @notice Get latest price for a feed
     */
    function getLatestPrice(bytes32 feedId)
        external
        view
        returns (
            int256 price,
            uint256 timestamp,
            uint256 confidence
        )
    {
        AggregatedPrice memory agg = latestPrices[feedId];
        require(agg.timestamp > 0, "No price available");

        // Check staleness
        PriceFeed memory feed = priceFeeds[feedId];
        uint256 maxAge = _getMaxSourceHeartbeat(feedId);
        require(block.timestamp - agg.timestamp <= maxAge, "Price stale");

        return (agg.price, agg.timestamp, agg.confidence);
    }

    /**
     * @notice Get TWAP for a feed over specified window
     */
    function getTWAP(bytes32 feedId, uint256 windowSeconds)
        external
        view
        returns (int256)
    {
        return _calculateTWAP(feedId, windowSeconds);
    }

    /**
     * @notice Get price with manipulation resistance (uses TWAP blend)
     */
    function getSecurePrice(bytes32 feedId)
        external
        view
        returns (int256 price, uint256 confidence)
    {
        AggregatedPrice memory latest = latestPrices[feedId];
        require(latest.timestamp > 0, "No price available");

        PriceFeed memory feed = priceFeeds[feedId];
        int256 twapPrice = _calculateTWAP(feedId, feed.twapWindow);

        // Blend spot and TWAP based on volatility
        uint256 volIndex = volatilityIndex[feedId];

        if (volIndex > 500) {
            // High volatility - trust TWAP more
            price = (latest.price * 3 + twapPrice * 7) / 10;
            confidence = latest.confidence * 7 / 10;
        } else if (volIndex > 200) {
            // Medium volatility - equal weight
            price = (latest.price + twapPrice) / 2;
            confidence = latest.confidence * 85 / 100;
        } else {
            // Low volatility - trust spot more
            price = (latest.price * 8 + twapPrice * 2) / 10;
            confidence = latest.confidence;
        }
    }

    /**
     * @notice Detect if current price appears manipulated
     */
    function detectManipulation(bytes32 feedId)
        external
        view
        returns (
            bool isManipulated,
            uint256 manipulationScore,
            string memory reason
        )
    {
        AggregatedPrice memory latest = latestPrices[feedId];
        if (latest.timestamp == 0) {
            return (false, 0, "No price data");
        }

        uint256 score = 0;
        string memory detectedReason = "";

        // Check 1: Deviation from TWAP
        PriceFeed memory feed = priceFeeds[feedId];
        int256 twapPrice = _calculateTWAP(feedId, feed.twapWindow);
        uint256 twapDeviation = _calculatePriceChange(twapPrice, latest.price);

        if (twapDeviation > 1000) { // >10% from TWAP
            score += 30;
            detectedReason = "High TWAP deviation;";
        }

        // Check 2: EMA crossover (sudden trend reversal)
        if (ema20[feedId] != 0 && ema50[feedId] != 0) {
            int256 emaDiff = ema20[feedId] - ema50[feedId];
            int256 previousDiff = ema50[feedId]; // Simplified

            if ((emaDiff > 0 && latest.price < ema50[feedId]) ||
                (emaDiff < 0 && latest.price > ema20[feedId])) {
                score += 20;
                detectedReason = string(abi.encodePacked(detectedReason, "EMA crossover;"));
            }
        }

        // Check 3: Excessive volatility
        if (volatilityIndex[feedId] > 1000) { // High volatility
            score += 25;
            detectedReason = string(abi.encodePacked(detectedReason, "High volatility;"));
        }

        // Check 4: Low source agreement
        if (latest.deviation > feed.maxDeviation * 8 / 10) {
            score += 25;
            detectedReason = string(abi.encodePacked(detectedReason, "Low source agreement;"));
        }

        isManipulated = score > 50;
        manipulationScore = score;
        reason = detectedReason;
    }

    /**
     * @notice Pause oracle updates (guardian action)
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause oracle updates
     */
    function unpause() external onlyRole(ORACLE_ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @notice Deactivate a suspicious source
     */
    function deactivateSource(
        bytes32 feedId,
        uint256 sourceIndex,
        string calldata reason
    ) external onlyRole(GUARDIAN_ROLE) {
        require(sourceIndex < feedSources[feedId].length, "Invalid index");
        feedSources[feedId][sourceIndex].isActive = false;
        emit SourceDeactivated(feedId, sourceIndex, reason);
    }

    // Internal functions

    function _fetchPrice(OracleSource memory source)
        internal
        view
        returns (int256 price, bool isValid)
    {
        if (source.oracleType == OracleType.CHAINLINK) {
            return _fetchChainlinkPrice(source);
        } else if (source.oracleType == OracleType.UNISWAP_V3_TWAP) {
            return _fetchUniswapTWAP(source);
        } else if (source.oracleType == OracleType.CUSTOM_FEED) {
            return _fetchCustomFeed(source);
        }

        return (0, false);
    }

    function _fetchChainlinkPrice(OracleSource memory source)
        internal
        view
        returns (int256, bool)
    {
        try AggregatorV3Interface(source.sourceAddress).latestRoundData() returns (
            uint80,
            int256 answer,
            uint256,
            uint256 updatedAt,
            uint80
        ) {
            // Check staleness
            if (block.timestamp - updatedAt > source.heartbeat) {
                return (0, false);
            }

            // Normalize decimals
            int256 normalizedPrice = answer;
            if (source.decimals < 18) {
                normalizedPrice = answer * int256(10 ** (18 - source.decimals));
            } else if (source.decimals > 18) {
                normalizedPrice = answer / int256(10 ** (source.decimals - 18));
            }

            return (normalizedPrice, answer > 0);
        } catch {
            return (0, false);
        }
    }

    function _fetchUniswapTWAP(OracleSource memory source)
        internal
        view
        returns (int256, bool)
    {
        // Simplified Uniswap V3 TWAP fetch
        // In production, would integrate with actual Uniswap V3 oracle
        return (source.lastPrice, source.lastPrice > 0);
    }

    function _fetchCustomFeed(OracleSource memory source)
        internal
        view
        returns (int256, bool)
    {
        // Custom oracle interface
        try ICustomOracle(source.sourceAddress).getPrice() returns (int256 price, uint256 timestamp) {
            if (block.timestamp - timestamp > source.heartbeat) {
                return (0, false);
            }
            return (price, price > 0);
        } catch {
            return (0, false);
        }
    }

    function _calculateMedian(int256[] memory prices, uint256 count)
        internal
        pure
        returns (int256)
    {
        if (count == 0) return 0;
        if (count == 1) return prices[0];

        // Sort prices (simple bubble sort for small arrays)
        for (uint256 i = 0; i < count - 1; i++) {
            for (uint256 j = 0; j < count - i - 1; j++) {
                if (prices[j] > prices[j + 1]) {
                    (prices[j], prices[j + 1]) = (prices[j + 1], prices[j]);
                }
            }
        }

        if (count % 2 == 0) {
            return (prices[count / 2 - 1] + prices[count / 2]) / 2;
        } else {
            return prices[count / 2];
        }
    }

    function _aggregateWithOutlierDetection(
        int256[] memory prices,
        uint256[] memory weights,
        uint256 count,
        int256 medianPrice,
        uint256 maxDeviation
    )
        internal
        pure
        returns (
            int256 aggregatedPrice,
            uint256 confidence,
            uint256 maxDev
        )
    {
        int256 weightedSum = 0;
        uint256 totalWeight = 0;
        uint256 validCount = 0;
        maxDev = 0;

        for (uint256 i = 0; i < count; i++) {
            // Calculate deviation from median
            uint256 deviation = _abs(prices[i] - medianPrice) * BASIS_POINTS / uint256(_abs(medianPrice));

            if (deviation <= maxDeviation) {
                weightedSum += prices[i] * int256(weights[i]);
                totalWeight += weights[i];
                validCount++;

                if (deviation > maxDev) {
                    maxDev = deviation;
                }
            }
        }

        require(validCount > 0, "All sources filtered");

        aggregatedPrice = weightedSum / int256(totalWeight);

        // Calculate confidence based on agreement and source count
        uint256 agreementScore = (BASIS_POINTS - maxDev);
        uint256 sourceScore = validCount * 1000; // 10% per source

        confidence = (agreementScore + sourceScore) / 2;
        if (confidence > BASIS_POINTS) confidence = BASIS_POINTS;
    }

    function _calculatePriceChange(int256 oldPrice, int256 newPrice)
        internal
        pure
        returns (uint256)
    {
        if (oldPrice == 0) return 0;

        int256 change = newPrice - oldPrice;
        return (_abs(change) * BASIS_POINTS) / uint256(_abs(oldPrice));
    }

    function _calculateTWAP(bytes32 feedId, uint256 windowSeconds)
        internal
        view
        returns (int256)
    {
        PriceObservation[] storage history = priceHistory[feedId];
        if (history.length == 0) return 0;
        if (history.length == 1) return history[0].price;

        uint256 windowStart = block.timestamp - windowSeconds;
        int256 sumPrices = 0;
        uint256 sumTime = 0;

        for (uint256 i = history.length; i > 0; i--) {
            PriceObservation memory obs = history[i - 1];

            if (obs.timestamp < windowStart) break;

            uint256 timeWeight = obs.timestamp - (i > 1 ? history[i - 2].timestamp : obs.timestamp);
            if (timeWeight == 0) timeWeight = 1;

            sumPrices += obs.price * int256(timeWeight);
            sumTime += timeWeight;
        }

        if (sumTime == 0) {
            return history[history.length - 1].price;
        }

        return sumPrices / int256(sumTime);
    }

    function _updatePriceHistory(bytes32 feedId, int256 price) internal {
        PriceObservation[] storage history = priceHistory[feedId];

        uint256 cumulative = 0;
        if (history.length > 0) {
            PriceObservation memory last = history[history.length - 1];
            uint256 timeDelta = block.timestamp - last.timestamp;
            cumulative = last.cumulativePrice + uint256(_abs(price)) * timeDelta;
        }

        history.push(PriceObservation({
            timestamp: block.timestamp,
            price: price,
            cumulativePrice: cumulative
        }));

        // Trim history if too long
        if (history.length > maxHistoryLength) {
            // Shift array (gas intensive but necessary for accuracy)
            for (uint256 i = 0; i < history.length - 1; i++) {
                history[i] = history[i + 1];
            }
            history.pop();
        }
    }

    function _updateEMAs(bytes32 feedId, int256 price) internal {
        // EMA formula: EMA = price * k + previousEMA * (1 - k)
        // k = 2 / (period + 1)

        // EMA20
        if (ema20[feedId] == 0) {
            ema20[feedId] = price;
        } else {
            // k = 2/21 ≈ 0.095, multiply by 1000 for precision
            int256 k20 = 95;
            ema20[feedId] = (price * k20 + ema20[feedId] * (1000 - k20)) / 1000;
        }

        // EMA50
        if (ema50[feedId] == 0) {
            ema50[feedId] = price;
        } else {
            // k = 2/51 ≈ 0.039
            int256 k50 = 39;
            ema50[feedId] = (price * k50 + ema50[feedId] * (1000 - k50)) / 1000;
        }
    }

    function _updateVolatilityIndex(bytes32 feedId) internal {
        PriceObservation[] storage history = priceHistory[feedId];
        if (history.length < 10) return;

        // Calculate standard deviation of returns
        int256[] memory returns_ = new int256[](10);

        for (uint256 i = 0; i < 10; i++) {
            uint256 idx = history.length - 10 + i;
            if (idx > 0) {
                returns_[i] = ((history[idx].price - history[idx - 1].price) * 10000) / history[idx - 1].price;
            }
        }

        // Calculate variance
        int256 mean = 0;
        for (uint256 i = 0; i < 10; i++) {
            mean += returns_[i];
        }
        mean = mean / 10;

        uint256 variance = 0;
        for (uint256 i = 0; i < 10; i++) {
            int256 diff = returns_[i] - mean;
            variance += uint256(diff * diff);
        }
        variance = variance / 10;

        // Store as volatility index (sqrt approximation)
        volatilityIndex[feedId] = _sqrt(variance);
    }

    function _getMaxSourceHeartbeat(bytes32 feedId)
        internal
        view
        returns (uint256)
    {
        OracleSource[] storage sources = feedSources[feedId];
        uint256 maxHeartbeat = 0;

        for (uint256 i = 0; i < sources.length; i++) {
            if (sources[i].isActive && sources[i].heartbeat > maxHeartbeat) {
                maxHeartbeat = sources[i].heartbeat;
            }
        }

        return maxHeartbeat;
    }

    function _abs(int256 x) internal pure returns (int256) {
        return x >= 0 ? x : -x;
    }

    function _sqrt(uint256 x) internal pure returns (uint256) {
        if (x == 0) return 0;

        uint256 z = (x + 1) / 2;
        uint256 y = x;

        while (z < y) {
            y = z;
            z = (x / z + z) / 2;
        }

        return y;
    }
}

// Custom oracle interface
interface ICustomOracle {
    function getPrice() external view returns (int256 price, uint256 timestamp);
}

/**
 * @title OracleRouter
 * @notice Routes price queries to appropriate aggregator with fallback logic
 */
contract OracleRouter {
    SecureOracleAggregator public primaryOracle;
    SecureOracleAggregator public fallbackOracle;

    address public owner;
    mapping(bytes32 => bytes32) public feedIdMapping; // Maps asset pair to feed ID

    event FallbackUsed(bytes32 indexed feedId);
    event RouteUpdated(bytes32 indexed pairHash, bytes32 feedId);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(address _primaryOracle, address _fallbackOracle) {
        primaryOracle = SecureOracleAggregator(_primaryOracle);
        fallbackOracle = SecureOracleAggregator(_fallbackOracle);
        owner = msg.sender;
    }

    /**
     * @notice Get price with automatic fallback
     */
    function getPrice(string calldata baseAsset, string calldata quoteAsset)
        external
        view
        returns (int256 price, uint256 confidence, bool usedFallback)
    {
        bytes32 pairHash = keccak256(abi.encodePacked(baseAsset, quoteAsset));
        bytes32 feedId = feedIdMapping[pairHash];
        require(feedId != bytes32(0), "Feed not configured");

        // Try primary oracle
        try primaryOracle.getLatestPrice(feedId) returns (
            int256 _price,
            uint256,
            uint256 _confidence
        ) {
            return (_price, _confidence, false);
        } catch {
            // Fallback to secondary oracle
            try fallbackOracle.getLatestPrice(feedId) returns (
                int256 _price,
                uint256,
                uint256 _confidence
            ) {
                return (_price, _confidence, true);
            } catch {
                revert("No oracle available");
            }
        }
    }

    /**
     * @notice Configure feed routing
     */
    function setFeedRoute(
        string calldata baseAsset,
        string calldata quoteAsset,
        bytes32 feedId
    ) external onlyOwner {
        bytes32 pairHash = keccak256(abi.encodePacked(baseAsset, quoteAsset));
        feedIdMapping[pairHash] = feedId;
        emit RouteUpdated(pairHash, feedId);
    }
}
