// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IReserveToken, TestUsdcReserve} from "../src/TestUsdcReserve.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address caller) external;
    function expectRevert(bytes4 selector) external;
    function expectRevert(bytes calldata reason) external;
    function expectEmit(bool topic1, bool topic2, bool topic3, bool data, address emitter) external;
    function chainId(uint256 newChainId) external;
}

contract MockUsdc is IReserveToken {
    event Transfer(address indexed from, address indexed to, uint256 value);

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    address public blocked;
    bool public inexactTransfer;

    function decimals() external pure returns (uint8) {
        return 6;
    }

    function mint(address recipient, uint256 amount) external {
        balanceOf[recipient] += amount;
        emit Transfer(address(0), recipient, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function setBlocked(address account) external {
        blocked = account;
    }

    function setInexactTransfer(bool enabled) external {
        inexactTransfer = enabled;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        return _transfer(from, to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        return _transfer(msg.sender, to, amount);
    }

    function _transfer(address from, address to, uint256 amount) private returns (bool) {
        if (to == blocked) return false;
        balanceOf[from] -= amount;
        uint256 credit = inexactTransfer ? amount - 1 : amount;
        balanceOf[to] += credit;
        emit Transfer(from, to, credit);
        return true;
    }
}

contract TestUsdcReserveTest {
    event Deposit(
        uint64 indexed nonce,
        address indexed depositor,
        bytes32 indexed assetId,
        uint32 reserveDomain,
        uint32 bsvNetwork,
        address reserveAsset,
        uint64 quantity,
        bytes owner
    );

    event Release(
        bytes32 indexed burnId,
        bytes32 indexed burnTxid,
        address indexed recipient,
        uint32 burnVout,
        uint64 quantity,
        uint64 fee,
        bytes32 attestationDigest
    );

    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    // Deliberately public fixture keys and identities for the local EVM.
    uint256 private constant RELEASE_KEY = 0xC0FFEE;
    uint256 private constant NEW_RELEASE_KEY = 0xBEEF;
    uint32 private constant RESERVE_DOMAIN = 7;
    uint32 private constant BSV_NETWORK = 1;
    bytes32 private constant ASSET_ID = keccak256("fixture BSV asset");
    address private constant GUARDIAN = address(0xA11CE);
    address private constant DEPOSITOR = address(0xD0);
    address private constant RECIPIENT = address(0xCAFE);
    address private constant FEE_RECIPIENT = address(0xFEE);
    bytes private constant OWNER = hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    MockUsdc private token;
    TestUsdcReserve private reserve;

    function setUp() public {
        token = new MockUsdc();
        reserve = new TestUsdcReserve(_config());
        token.mint(DEPOSITOR, 10_000);
        vm.prank(DEPOSITOR);
        token.approve(address(reserve), 10_000);
    }

    function testDepositAndReleaseTrackExactBalancesAndLog() public {
        vm.expectEmit(true, true, true, true, address(reserve));
        emit Deposit(1, DEPOSITOR, ASSET_ID, RESERVE_DOMAIN, BSV_NETWORK, address(token), 1024, OWNER);
        require(_deposit(1024) == 1);
        require(token.balanceOf(address(reserve)) == 1024 && reserve.netReserve() == 1024);

        TestUsdcReserve.Redemption memory claim = _redemption();
        bytes32 id = reserve.burnId(BSV_NETWORK, claim.burnTxid, claim.burnVout);
        bytes32 digest = reserve.releaseDigest(claim);
        bytes memory signature = _sign(RELEASE_KEY, digest);
        vm.expectEmit(true, true, true, true, address(reserve));
        emit Release(id, claim.burnTxid, RECIPIENT, claim.burnVout, 640, 0, digest);
        vm.prank(address(0xB07));
        require(reserve.release(claim, signature) == id);

        require(reserve.settled(id) && reserve.settledDigest(id) == digest);
        require(reserve.totalDeposited() == 1024 && reserve.totalReleased() == 640);
        require(reserve.netReserve() == 384 && token.balanceOf(address(reserve)) == 384);
        require(token.balanceOf(RECIPIENT) == 640);
        require(_deposit(16) == 2 && reserve.netReserve() == 400);
    }

    function testSeparateBurnOutputEventsAndReSignedReplay() public {
        _deposit(2000);
        TestUsdcReserve.Redemption memory claim = _redemption();
        bytes32 id = reserve.release(claim, _sign(RELEASE_KEY, reserve.releaseDigest(claim)));

        reserve.setReleaseSigner(vm.addr(NEW_RELEASE_KEY));
        claim.signerEpoch++;
        claim.burnBlockHash = keccak256("new observation for same event");
        bytes memory renewed = _sign(NEW_RELEASE_KEY, reserve.releaseDigest(claim));
        vm.expectRevert(abi.encodeWithSelector(TestUsdcReserve.AlreadySettled.selector, id));
        reserve.release(claim, renewed);
        require(reserve.netReserve() == 1360);

        claim.burnVout++;
        bytes32 distinct = reserve.release(claim, _sign(NEW_RELEASE_KEY, reserve.releaseDigest(claim)));
        require(distinct != id && reserve.netReserve() == 720);
    }

    function testPayoutFailureIsAtomicAndAllowsSameAttestationRetry() public {
        _deposit(1024);
        TestUsdcReserve.Redemption memory claim = _redemption();
        claim.fee = 5;
        bytes32 id = reserve.burnId(BSV_NETWORK, claim.burnTxid, claim.burnVout);
        bytes memory signature = _sign(RELEASE_KEY, reserve.releaseDigest(claim));
        token.setBlocked(FEE_RECIPIENT);
        vm.expectRevert(TestUsdcReserve.InexactTransfer.selector);
        reserve.release(claim, signature);
        require(!reserve.settled(id) && reserve.settledDigest(id) == bytes32(0));
        require(reserve.netReserve() == 1024 && reserve.totalReleaseFees() == 0);
        require(token.balanceOf(RECIPIENT) == 0 && token.balanceOf(address(reserve)) == 1024);

        token.setBlocked(address(0));
        require(reserve.release(claim, signature) == id);
        require(token.balanceOf(RECIPIENT) == 635 && token.balanceOf(FEE_RECIPIENT) == 5);
        require(reserve.netReserve() == 384 && reserve.totalReleaseFees() == 5);
    }

    function testAuthenticatesPayoutFieldsAndBindsContract() public {
        _deposit(1024);
        TestUsdcReserve.Redemption memory claim = _redemption();
        bytes memory signature = _sign(RELEASE_KEY, reserve.releaseDigest(claim));

        claim.recipient = address(0xBAD);
        _rejectSignature(claim, signature);
        claim = _redemption();
        claim.quantity++;
        _rejectSignature(claim, signature);
        claim = _redemption();
        claim.fee++;
        _rejectSignature(claim, signature);
        claim = _redemption();
        claim.burnVout++;
        _rejectSignature(claim, signature);
        claim = _redemption();
        claim.burnTxid = keccak256("different burn transaction");
        _rejectSignature(claim, signature);
        claim = _redemption();
        claim.burnBlockHash = keccak256("different BSV block");
        _rejectSignature(claim, signature);

        TestUsdcReserve other = new TestUsdcReserve(_config());
        claim = _redemption();
        vm.expectRevert(TestUsdcReserve.InvalidSignature.selector);
        other.release(claim, signature);
        _rejectSignature(claim, _sign(NEW_RELEASE_KEY, reserve.releaseDigest(claim)));
        require(reserve.netReserve() == 1024);
    }

    function testRejectsCorrectlySignedOutOfScopeAssetNetworkAndDomain() public {
        _deposit(1024);
        TestUsdcReserve.Redemption memory claim = _redemption();
        claim.assetId = keccak256("another bridge asset");
        _rejectScope(claim);
        claim = _redemption();
        claim.bsvNetwork++;
        _rejectScope(claim);
        claim = _redemption();
        claim.reserveDomain++;
        _rejectScope(claim);
        claim = _redemption();
        claim.fee = claim.quantity;
        _rejectScope(claim);
        claim = _redemption();
        claim.recipient = address(reserve);
        _rejectScope(claim);
        require(reserve.netReserve() == 1024);
    }

    function testEip712EncodingAndWrongChain() public {
        TestUsdcReserve.Redemption memory claim = _redemption();
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("BSV USDC Test Reserve"),
                keccak256("1"),
                block.chainid,
                address(reserve)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", domain, _manualStructHash(claim)));
        require(reserve.releaseDigest(claim) == digest);

        uint256 chain = block.chainid;
        bytes memory signature = _sign(RELEASE_KEY, digest);
        vm.chainId(chain + 1);
        require(reserve.releaseDigest(claim) != digest);
        vm.expectRevert(TestUsdcReserve.UnsupportedChain.selector);
        reserve.release(claim, signature);
        vm.expectRevert(TestUsdcReserve.UnsupportedChain.selector);
        reserve.deposit(1024, OWNER);
        vm.chainId(chain);
    }

    function testDepositAndReleasePauseAreIndependent() public {
        _deposit(1024);
        vm.prank(GUARDIAN);
        reserve.setDepositsPaused(true);
        vm.prank(GUARDIAN);
        vm.expectRevert(TestUsdcReserve.Unauthorized.selector);
        reserve.setDepositsPaused(false);
        vm.expectRevert(TestUsdcReserve.DepositPaused.selector);
        reserve.deposit(1, OWNER);

        TestUsdcReserve.Redemption memory claim = _redemption();
        reserve.release(claim, _sign(RELEASE_KEY, reserve.releaseDigest(claim)));
        reserve.setDepositsPaused(false);
        vm.prank(GUARDIAN);
        reserve.setReleasesPaused(true);
        require(_deposit(1024) == 2);

        claim.burnVout++;
        bytes memory signature = _sign(RELEASE_KEY, reserve.releaseDigest(claim));
        vm.expectRevert(TestUsdcReserve.ReleasePaused.selector);
        reserve.release(claim, signature);
        reserve.setReleasesPaused(false);
        reserve.release(claim, signature);
    }

    function testRotationRevocationAndAdminTransfer() public {
        _deposit(1024);
        TestUsdcReserve.Redemption memory claim = _redemption();
        bytes memory original = _sign(RELEASE_KEY, reserve.releaseDigest(claim));
        vm.prank(GUARDIAN);
        vm.expectRevert(TestUsdcReserve.Unauthorized.selector);
        reserve.setReleaseSigner(GUARDIAN);

        reserve.setReleaseSigner(address(0));
        _rejectScope(claim);
        claim.signerEpoch++;
        _rejectSignature(claim, _sign(RELEASE_KEY, reserve.releaseDigest(claim)));
        reserve.proposeAdmin(GUARDIAN);
        vm.prank(GUARDIAN);
        reserve.acceptAdmin();

        address nextSigner = vm.addr(NEW_RELEASE_KEY);
        vm.expectRevert(TestUsdcReserve.Unauthorized.selector);
        reserve.setReleaseSigner(nextSigner);
        vm.prank(GUARDIAN);
        reserve.setReleaseSigner(nextSigner);
        claim.signerEpoch++;
        _rejectSignature(claim, original);
        reserve.release(claim, _sign(NEW_RELEASE_KEY, reserve.releaseDigest(claim)));
    }

    function testDepositRequiresValidOwnerAndExactCredit() public {
        vm.expectRevert(TestUsdcReserve.InvalidDeposit.selector);
        reserve.deposit(0, OWNER);
        vm.expectRevert(TestUsdcReserve.InvalidDeposit.selector);
        reserve.deposit(1, hex"02");
        vm.expectRevert(TestUsdcReserve.InvalidDeposit.selector);
        reserve.deposit(1, hex"020000000000000000000000000000000000000000000000000000000000000000");
        vm.expectRevert(TestUsdcReserve.InvalidDeposit.selector);
        reserve.deposit(1, hex"02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        token.setInexactTransfer(true);
        vm.prank(DEPOSITOR);
        vm.expectRevert(TestUsdcReserve.InexactTransfer.selector);
        reserve.deposit(1024, OWNER);
        require(reserve.depositNonce() == 0 && reserve.netReserve() == 0);
        require(token.balanceOf(DEPOSITOR) == 10_000 && token.balanceOf(address(reserve)) == 0);

        token.setInexactTransfer(false);
        require(_deposit(1024) == 1);
    }

    function testDonationsDoNotAuthorizePayoutAndZeroReserveHandlesFullRelease() public {
        token.mint(address(reserve), 1000);
        require(reserve.netReserve() == 0);
        TestUsdcReserve.Redemption memory claim = _redemption();
        bytes memory signature = _sign(RELEASE_KEY, reserve.releaseDigest(claim));
        vm.expectRevert(TestUsdcReserve.InsufficientReserve.selector);
        reserve.release(claim, signature);

        _deposit(640);
        reserve.release(claim, signature);
        require(reserve.netReserve() == 0 && token.balanceOf(address(reserve)) == 1000);
    }

    function _manualStructHash(TestUsdcReserve.Redemption memory claim) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    "Redemption(uint32 bsvNetwork,bytes32 burnTxid,uint32 burnVout,bytes32 burnBlockHash,"
                    "bytes32 assetId,uint32 reserveDomain,address recipient,uint64 quantity,uint64 fee,uint64 signerEpoch)"
                ),
                claim.bsvNetwork,
                claim.burnTxid,
                claim.burnVout,
                claim.burnBlockHash,
                claim.assetId,
                claim.reserveDomain,
                claim.recipient,
                claim.quantity,
                claim.fee,
                claim.signerEpoch
            )
        );
    }

    function _config() private returns (TestUsdcReserve.Configuration memory) {
        return TestUsdcReserve.Configuration({
            chainId: block.chainid,
            reserveDomain: RESERVE_DOMAIN,
            bsvNetwork: BSV_NETWORK,
            assetId: ASSET_ID,
            token: token,
            admin: address(this),
            pauseGuardian: GUARDIAN,
            releaseSigner: vm.addr(RELEASE_KEY),
            feeRecipient: FEE_RECIPIENT
        });
    }

    function _deposit(uint64 quantity) private returns (uint64) {
        vm.prank(DEPOSITOR);
        return reserve.deposit(quantity, OWNER);
    }

    function _redemption() private pure returns (TestUsdcReserve.Redemption memory) {
        return TestUsdcReserve.Redemption({
            bsvNetwork: BSV_NETWORK,
            burnTxid: keccak256("BSV burn wire txid"),
            burnVout: 1,
            burnBlockHash: keccak256("BSV confirming block wire hash"),
            assetId: ASSET_ID,
            reserveDomain: RESERVE_DOMAIN,
            recipient: RECIPIENT,
            quantity: 640,
            fee: 0,
            signerEpoch: 1
        });
    }

    function _sign(uint256 key, bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _rejectSignature(TestUsdcReserve.Redemption memory claim, bytes memory signature) private {
        vm.expectRevert(TestUsdcReserve.InvalidSignature.selector);
        reserve.release(claim, signature);
    }

    function _rejectScope(TestUsdcReserve.Redemption memory claim) private {
        bytes memory signature = _sign(RELEASE_KEY, reserve.releaseDigest(claim));
        vm.expectRevert(TestUsdcReserve.InvalidRedemption.selector);
        reserve.release(claim, signature);
    }
}
