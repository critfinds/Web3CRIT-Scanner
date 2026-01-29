// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * INTENTIONALLY VULNERABLE - for scanner testing only.
 *
 * Uses a spot-price style oracle (getReserves) to compute how much value to transfer.
 * This is flash-loan manipulable and should be flagged as CRITICAL.
 */

interface IUniswapV2PairLike {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

contract OracleManipulationVulnerable {
    IUniswapV2PairLike public pair;

    constructor(address _pair) payable {
        pair = IUniswapV2PairLike(_pair);
    }

    // VULNERABLE: value transfer amount is derived from manipulable spot reserves
    function buy() external payable {
        (uint112 r0, uint112 r1,) = pair.getReserves();
        require(r0 > 0 && r1 > 0, "bad reserves");

        // Spot price (toy): price = r1 / r0
        uint256 price = uint256(r1) * 1e18 / uint256(r0);

        // Value-moving operation derived from oracle output (refund)
        uint256 refund = msg.value > price ? (msg.value - price) : 0;
        if (refund > 0) {
            payable(msg.sender).transfer(refund);
        }
    }

    receive() external payable {}
}


