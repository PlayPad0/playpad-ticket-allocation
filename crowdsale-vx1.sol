
contract PlayPadIdoContract is ReentrancyGuard, Ownable {
    //Deployed by Main Contract
    PlayPadIdoFactory deployerContract;
    using SafeERC20 for IERC20;
    using SafeMath for uint256;

    IERC20 public immutable busdToken; //Stable coin token contract address
    IERC20 public saleToken; //Sale token contract address
    bool public contractStatus; //Contract running status
    uint256 public startTime; //IDO participation start time
    uint256 public endTime; //IDO participation end time
    uint256 public lockTime; //unlock date to get claim
    uint256[] public claimRoundsDate; //all claim rounds
    uint256 public totalClaimPercent; //total to be claim percent
    uint256 private MERKLE_ROOT; // MERKLE ROOT
    address[] public investors;
    uint256 public participantCount;
    uint256 public totalSoldAmountUsd;
    uint256 public hardcapUsd;

    /**
    -> Merkle root data structure
    * userAddress --
    * timestamp
    * userTotalVesting
    * userLevel
    */

    //whitelisted user data per user
    struct whitelistedInvestorData {
        uint256 totalBuyingAmountUsd;
        uint256 totalBuyingAmountToken;
        uint256 claimRound;
        uint256 lastClaimDate;
        uint256 claimedValue;
    }

    struct saleStruct {
        uint256 hardcap;
        uint256 totalSellAmountToken;
        uint256 totalSoldAmountToken;
        uint256 totalSoldAmountUsd;
        uint256 maxBuyValue;
        uint256 minBuyValue;
    }

    //claim round periods
    struct roundDatas {
        uint256 roundStartDate;
        uint256 roundPercent;
    }
    //mappings to reach relevant information
    mapping(address => whitelistedInvestorData) public _investorData;
    mapping(uint256 => roundDatas) public _roundDatas;
    mapping(uint256 => saleStruct) public _sales; //0 -> whitelist sale details, 1 -> holders round details

    constructor(
        IERC20 _busdAddress,
        IERC20 _saleToken,
        bool _contractStatus,
        uint256 _startTime,
        uint256 _endTime,
        uint256 _hardcap
    ) public {
        require(
            _startTime < _endTime,
            "start block must be less than finish block"
        );
        require(
            _endTime > block.timestamp,
            "finish block must be more than current block"
        );
        busdToken = _busdAddress;
        saleToken = _saleToken;
        contractStatus = _contractStatus;
        startTime = _startTime;
        endTime = _endTime;
        hardcapUsd = _hardcap;
    }

    event NewBuying(
        address indexed investorAddress,
        uint256 amount,
        uint256 timestamp,
        uint256 totalSoldAmountUsd
    );

    //modifier to change contract status
    modifier mustNotPaused() {
        require(!contractStatus, "Paused!");
        _;
    }

    // function to change status of contract
    function changePause(bool _contractStatus) public onlyOwner nonReentrant {
        contractStatus = _contractStatus;
    }

    function changeSaleTokenAddress(IERC20 _contractAddress)
        external
        onlyOwner
        nonReentrant
    {
        saleToken = _contractAddress;
    }

    function changeStartTime(uint256 _startTime)
        external
        nonReentrant
        onlyOwner
    {
        startTime = _startTime;
    }

    function changeFinishTime(uint256 _finishTime)
        external
        nonReentrant
        onlyOwner
    {
        endTime = _finishTime;
    }

    function setSaleDetails(
        uint256 _hardcap,
        uint256 _totalSellAmountToken,
        uint256 _maxBuyAmount,
        uint256 _minBuyAmount,
        uint256 _saleRound
    ) external onlyOwner nonReentrant {
        saleStruct storage saleDetails = _sales[_saleRound];
        saleDetails.hardcap = _hardcap;
        saleDetails.totalSellAmountToken = _totalSellAmountToken;
        saleDetails.maxBuyValue = _maxBuyAmount;
        saleDetails.minBuyValue = _minBuyAmount;
    }

    //calculate token amount according to deposit amount
    function calculateTokenAmount(uint256 amount, uint256 _saleRound)
        public
        view
        returns (uint256)
    {
        saleStruct memory _saleDetails = _sales[_saleRound];
        return
            (_saleDetails.totalSellAmountToken.mul(amount)).div(
                _saleDetails.hardcap
            );
    }

    function returnUserInfo(address _addresss)
        public
        view
        returns (
            uint256,
            uint256,
            uint256,
            uint256,
            uint256
        )
    {
        whitelistedInvestorData storage investor = _investorData[_addresss];
        return (
            investor.totalBuyingAmountUsd,
            investor.totalBuyingAmountToken,
            investor.claimRound,
            investor.lastClaimDate,
            investor.claimedValue
        );
    }

    function returnAllUsers()
        public
        view
        returns (whitelistedInvestorData[] memory)
    {
        whitelistedInvestorData[] memory users = new whitelistedInvestorData[](
            investors.length
        );
        for (uint256 i = 0; i < investors.length; i++) {
            whitelistedInvestorData memory user = _investorData[investors[i]];
            users[i] = user;
        }
        return users;
    }

    //buys token if passing controls
    function buyToken(
        uint256[3] calldata _data,
        uint256[] memory _proof,
        uint256 busdAmount
    ) external nonReentrant mustNotPaused {
        require(block.timestamp >= startTime);
        require(block.timestamp <= endTime);
        whitelistedInvestorData storage investor = _investorData[msg.sender];
        uint256 userTotalVesting = _data[1];
        uint256 userLevel = _data[2];
        uint256 userLeaf = uint256(
            keccak256(abi.encodePacked(msg.sender, _data))
        );
        require(verifyMerkle(userLeaf, _proof), "leaf is not correct");
        saleStruct memory saleDetails = _sales[userLevel];
        require(
            userTotalVesting >= investor.totalBuyingAmountUsd.add(busdAmount),
            "Opps you cannot buy more than your allocation"
        );
        require(
            saleDetails.hardcap >=
                saleDetails.totalSoldAmountUsd.add(busdAmount),
            "hardcap value exceed"
        );
        require(
            saleDetails.maxBuyValue >=
                investor.totalBuyingAmountUsd.add(busdAmount),
            "you cannot buy more total limit at total"
        );
        require(
            busdAmount >= saleDetails.minBuyValue,
            "you cannot buy less than min limit"
        );
        require(busdToken.transferFrom(msg.sender, address(this), busdAmount));
        uint256 totalTokenAmount = calculateTokenAmount(busdAmount, userLevel);
        if (investor.totalBuyingAmountUsd == 0) {
            investors.push(msg.sender);
            participantCount.add(1);
        }
        saleDetails.totalSoldAmountUsd = saleDetails.totalSoldAmountUsd.add(
            busdAmount
        );
        saleDetails.totalSoldAmountToken = saleDetails.totalSoldAmountToken.add(
            busdAmount
        );
        investor.totalBuyingAmountUsd = investor.totalBuyingAmountUsd.add(
            busdAmount
        );
        investor.totalBuyingAmountToken = investor.totalBuyingAmountToken.add(
            totalTokenAmount
        );
        totalSoldAmountUsd = totalSoldAmountUsd.add(busdAmount);

        emit NewBuying(
            msg.sender,
            busdAmount,
            block.timestamp,
            totalSoldAmountUsd
        );
    }

    //emergency withdraw function in worst cases
    function emergencyWithdrawAllBusd() external nonReentrant onlyOwner {
        require(
            busdToken.transfer(msg.sender, busdToken.balanceOf(address(this)))
        );
    }

    //change lock time to prevent missing values
    function changeLockTime(uint256 _lockTime) external nonReentrant onlyOwner {
        lockTime = _lockTime;
    }

    //emergency withdraw for tokens in worst cases
    function withdrawTokens() external nonReentrant onlyOwner {
        require(
            saleToken.transfer(msg.sender, saleToken.balanceOf(address(this)))
        );
    }

    //claim tokens according to claim periods
    function claimTokens(uint256[3] calldata _data, uint256[] memory _proof)
        external
        nonReentrant
    {
        require(block.timestamp >= lockTime, "bad lock time");
        uint256 userLeaf = uint256(
            keccak256(abi.encodePacked(msg.sender, _data))
        );
        require(verifyMerkle(userLeaf, _proof), "leaf is not correct");
        whitelistedInvestorData memory investor = _investorData[msg.sender];
        uint256 investorRoundNumber = investor.claimRound;
        roundDatas storage roundDetail = _roundDatas[investorRoundNumber];
        require(
            roundDetail.roundStartDate != 0,
            "Claim rounds are not available yet."
        );
        require(
            block.timestamp >= roundDetail.roundStartDate,
            "round didn't start yet"
        );
        require(
            investor.totalBuyingAmountToken >=
                investor.claimedValue.add(
                    investor
                        .totalBuyingAmountToken
                        .mul(roundDetail.roundPercent)
                        .div(100)
                ),
            "already you got all your tokens"
        );
        require(
            saleToken.transfer(
                msg.sender,
                investor
                    .totalBuyingAmountToken
                    .mul(roundDetail.roundPercent)
                    .div(100)
            ),
            "bad transfer"
        );
        investor.claimRound = investor.claimRound.add(1);
        investor.lastClaimDate = block.timestamp;
        investor.claimedValue = investor.claimedValue.add(
            investor.totalBuyingAmountToken.mul(roundDetail.roundPercent).div(
                100
            )
        );
    }

    //add new claim round
    function addNewClaimRound(
        uint256 _roundNumber,
        uint256 _roundStartDate,
        uint256 _claimPercent
    ) external nonReentrant onlyOwner {
        require(_claimPercent > 0);
        totalClaimPercent = totalClaimPercent.add(_claimPercent);
        roundDatas storage roundDetail = _roundDatas[_roundNumber];
        roundDetail.roundStartDate = _roundStartDate;
        roundDetail.roundPercent = _claimPercent;
        claimRoundsDate.push(_roundStartDate);
    }

    function changeMaxMinBuyLimit(
        uint256 _maxBuyLimit,
        uint256 _minBuyLimit,
        uint256 _saleRoundNumber
    ) external onlyOwner nonReentrant {
        saleStruct memory saleDetails = _sales[_saleRoundNumber];
        saleDetails.maxBuyValue = _maxBuyLimit;
        saleDetails.minBuyValue = _minBuyLimit;
    }

    function pairHash(uint256 _a, uint256 _b) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(_a ^ _b)));
    }

    // Verify a Merkle proof
    function verifyMerkle(uint256 _value, uint256[] memory _proof)
        public
        view
        returns (bool)
    {
        uint256 temp = _value;
        uint256 i;

        for (i = 0; i < _proof.length; i++) {
            temp = pairHash(temp, _proof[i]);
        }

        return temp == MERKLE_ROOT;
    }

    function getMerkleRoot() external view returns (uint256) {
        return MERKLE_ROOT;
    }

    function setMerkleRoot(uint256 _merkleRoot)
        external
        onlyOwner
        nonReentrant
    {
        MERKLE_ROOT = _merkleRoot;
    }
}
