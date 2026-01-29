// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title HighTVLVulnerable
 * @notice Demonstrates CRITICAL vulnerabilities found in high-TVL DeFi protocols
 * @dev INTENTIONALLY VULNERABLE - For testing Web3CRIT Scanner advanced detectors
 *
 * This contract simulates patterns from real exploits:
 * - Cream Finance ($130M) - Flash loan oracle manipulation
 * - Warp Finance ($7.7M) - LP token price manipulation
 * - Inverse Finance ($15M) - Liquidation manipulation
 * - Curve/Vyper ($70M) - Read-only reentrancy
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IERC1155 {
    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data) external;
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function totalSupply() external view returns (uint256);
}

interface IAToken {
    function balanceOf(address account) external view returns (uint256);
    function scaledBalanceOf(address account) external view returns (uint256);
}

interface ICurvePool {
    function get_virtual_price() external view returns (uint256);
    function remove_liquidity(uint256 amount, uint256[2] calldata min_amounts) external returns (uint256[2] memory);
}

/**
 * VULNERABILITY 1: ERC1155 Callback Reentrancy
 * Pattern: Cream Finance, Uniswap/Lendf.Me style attacks
 */
contract VulnerableNFTVault {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    IERC1155 public nftToken;

    function depositNFT(uint256 tokenId, uint256 amount) external {
        uint256 sharesToMint = amount; // Simplified

        // VULNERABILITY: ERC1155 callback triggers before state update
        nftToken.safeTransferFrom(msg.sender, address(this), tokenId, amount, "");

        // State update AFTER external call (callback reentrancy vulnerable)
        shares[msg.sender] += sharesToMint;
        totalShares += sharesToMint;
    }

    function withdrawNFT(uint256 tokenId, uint256 shareAmount) external {
        require(shares[msg.sender] >= shareAmount, "Insufficient shares");

        // VULNERABILITY: Callback reentrancy - update after transfer
        nftToken.safeTransferFrom(address(this), msg.sender, tokenId, shareAmount, "");

        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
    }
}

/**
 * VULNERABILITY 2: LP Token Price Manipulation
 * Pattern: Warp Finance, Value DeFi, Cheese Bank attacks
 */
contract VulnerableLPLending {
    mapping(address => uint256) public collateralDeposits;
    mapping(address => uint256) public borrows;
    IUniswapV2Pair public lpToken;
    IERC20 public borrowToken;

    /**
     * VULNERABILITY: Uses spot LP token price from manipulable reserves
     */
    function getLPTokenPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1,) = lpToken.getReserves();
        uint256 totalSupply = lpToken.totalSupply();

        // VULNERABLE: LP price from reserves (flash loan manipulable)
        // Attack: Add liquidity → inflate reserves → overvalue LP → borrow more
        return (uint256(reserve0) + uint256(reserve1)) * 1e18 / totalSupply;
    }

    function depositLPAsCollateral(uint256 amount) external {
        IERC20(address(lpToken)).transferFrom(msg.sender, address(this), amount);
        collateralDeposits[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        uint256 collateralValue = collateralDeposits[msg.sender] * getLPTokenPrice() / 1e18;
        uint256 maxBorrow = collateralValue * 80 / 100; // 80% LTV

        require(borrows[msg.sender] + amount <= maxBorrow, "Exceeds borrow limit");

        borrows[msg.sender] += amount;
        borrowToken.transfer(msg.sender, amount);
    }

    /**
     * VULNERABILITY: Liquidation using spot prices
     * Pattern: Inverse Finance attack
     */
    function liquidate(address user, uint256 repayAmount) external {
        uint256 collateralValue = collateralDeposits[user] * getLPTokenPrice() / 1e18;
        uint256 borrowValue = borrows[user];

        // VULNERABLE: Uses manipulable spot price for liquidation decision
        require(borrowValue * 100 / collateralValue > 90, "Position healthy");

        // Liquidation logic...
        borrows[user] -= repayAmount;
        collateralDeposits[user] -= repayAmount * 110 / 100; // 10% bonus
    }
}

/**
 * VULNERABILITY 3: Rebasing Token Vault (Aave/Lido integration)
 * Pattern: Share dilution via rebase timing
 */
contract VulnerableAaveVault {
    mapping(address => uint256) public userShares;
    uint256 public totalShares;
    IAToken public aToken; // Aave's rebasing token

    /**
     * VULNERABILITY: Uses balanceOf with rebasing token
     * Attack: Deposit 1 wei → wait for rebase → next depositor gets diluted shares
     */
    function totalAssets() public view returns (uint256) {
        // VULNERABLE: aToken balance increases from interest without transfers
        return aToken.balanceOf(address(this));
    }

    function deposit(uint256 amount) external {
        uint256 shares;
        if (totalShares == 0) {
            shares = amount;
        } else {
            // VULNERABLE: Share calculation with rebasing balance
            // If balance increased from rebase, depositor gets fewer shares
            shares = amount * totalShares / totalAssets();
        }

        // Transfer aTokens (would use safeTransferFrom in reality)
        IERC20(address(aToken)).transferFrom(msg.sender, address(this), amount);

        userShares[msg.sender] += shares;
        totalShares += shares;
    }

    function withdraw(uint256 shareAmount) external {
        require(userShares[msg.sender] >= shareAmount, "Insufficient shares");

        uint256 assets = shareAmount * totalAssets() / totalShares;

        userShares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;

        IERC20(address(aToken)).transfer(msg.sender, assets);
    }
}

/**
 * VULNERABILITY 4: Curve Read-Only Reentrancy
 * Pattern: 2023 Curve/Vyper exploits
 */
contract VulnerableCurveIntegration {
    ICurvePool public curvePool;
    mapping(address => uint256) public deposits;

    /**
     * VULNERABILITY: Reads virtual_price during reentrancy-susceptible operation
     */
    function getShareValue(uint256 shares) public view returns (uint256) {
        // VULNERABLE: virtual_price can be stale during remove_liquidity callback
        uint256 virtualPrice = curvePool.get_virtual_price();
        return shares * virtualPrice / 1e18;
    }

    function withdrawFromCurve(uint256 lpAmount) external {
        require(deposits[msg.sender] >= lpAmount, "Insufficient deposit");

        // Calculate value BEFORE removal (uses virtual_price)
        uint256 valueToReceive = getShareValue(lpAmount);

        // VULNERABLE: remove_liquidity sends ETH which can callback
        // During callback, virtual_price is stale (not yet updated)
        // Attacker can reenter and read inflated virtual_price
        uint256[2] memory minAmounts;
        curvePool.remove_liquidity(lpAmount, minAmounts);

        deposits[msg.sender] -= lpAmount;

        // Send value based on potentially stale price
        payable(msg.sender).transfer(valueToReceive);
    }

    receive() external payable {}
}

/**
 * VULNERABILITY 5: Cross-Pool Price Manipulation
 * Pattern: Harvest Finance attack
 */
contract VulnerableCrossPoolOracle {
    IUniswapV2Pair public poolA; // ETH/USDC
    IUniswapV2Pair public poolB; // ETH/USDT

    /**
     * VULNERABILITY: Uses multiple spot prices from different pools
     * Attack: Manipulate poolA, read inflated price, arbitrage on poolB
     */
    function getAveragePrice() public view returns (uint256) {
        (uint112 reserveA0, uint112 reserveA1,) = poolA.getReserves();
        (uint112 reserveB0, uint112 reserveB1,) = poolB.getReserves();

        // VULNERABLE: Both pools can be manipulated independently
        uint256 priceA = uint256(reserveA1) * 1e18 / uint256(reserveA0);
        uint256 priceB = uint256(reserveB1) * 1e18 / uint256(reserveB0);

        return (priceA + priceB) / 2;
    }

    function executeWithPrice(uint256 amount) external {
        uint256 price = getAveragePrice();

        // VULNERABLE: Uses manipulable cross-pool price for execution
        uint256 value = amount * price / 1e18;

        // Execute trade/mint/borrow based on manipulable price...
    }
}

/**
 * VULNERABILITY 6: Flash Loan Callback Without Reentrancy Guard
 */
interface IFlashLender {
    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external;
}

contract VulnerableFlashBorrower {
    mapping(address => uint256) public balances;

    /**
     * VULNERABILITY: Flash loan callback modifies state without reentrancy guard
     */
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32) {
        // VULNERABLE: State modification in callback without guard
        // Attacker can reenter via token transfer hooks or nested flash loans
        balances[initiator] += amount;

        // Process flash loan...

        balances[initiator] -= amount + fee;

        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
