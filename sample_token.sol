// SampleToken — TEST FIXTURE ONLY. A deliberately risky BEP20 used by
// test_agent.py and the Gradio "paste sample" example. Do NOT deploy this.
pragma solidity ^0.8.0;

contract SampleToken {
    string public name = "SampleToken";
    string public symbol = "SMPL";
    uint8 public decimals = 18;
    uint256 public totalSupply = 1000000 * 10 ** 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public blacklist;
    mapping(address => bool) public automatedMarketMakerPairs;
    address public owner;
    uint256 public buyFee = 5;
    uint256 public sellFee = 5;
    uint256 public maxTxAmount = 10000 * 10 ** 18;
    bool public tradingOpen = false;
    bool public paused = false;

    event Transfer(address indexed from, address indexed to, uint256 value);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
        balanceOf[msg.sender] = totalSupply;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    function setBuyFee(uint256 fee) external onlyOwner {
        buyFee = fee;
    }

    function setSellFee(uint256 fee) external onlyOwner {
        sellFee = fee;
    }

    function setBlacklist(address account, bool blocked) external onlyOwner {
        blacklist[account] = blocked;
    }

    function setMaxTx(uint256 amount) external onlyOwner {
        maxTxAmount = amount;
    }

    function enableTrading() external onlyOwner {
        tradingOpen = true;
    }

    function pause() external onlyOwner {
        paused = true;
    }

    function rescueToken(address token, uint256 amount) external onlyOwner {
        // withdraw any token held by this contract
        (bool ok, ) = token.call(
            abi.encodeWithSignature("transfer(address,uint256)", owner, amount)
        );
        require(ok, "rescue failed");
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(tradingOpen, "trading closed");
        require(!blacklist[msg.sender], "blacklisted");
        require(!paused, "paused");
        require(amount <= maxTxAmount, "over max tx");
        if (automatedMarketMakerPairs[to]) {
            uint256 fee = (amount * sellFee) / 100;
            balanceOf[msg.sender] -= amount;
            balanceOf[to] += amount - fee;
        } else {
            balanceOf[msg.sender] -= amount;
            balanceOf[to] += amount;
        }
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}
