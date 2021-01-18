// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2020 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "chainparamsseeds.h"
#include "consensus/merkle.h"
#include "util.h"
#include "utilstrencodings.h"
#include <boost/assign/list_of.hpp>

#include <cassert>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.nVersion = nVersion;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of the genesis coinbase cannot
 * be spent as it did not originally exist in the database.
 *
 * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
 *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
 *   vMerkleTree: e0028e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "U.S. News & World Report Jan 28 2016 With His Absence, Trump Dominates Another Debate";
    const CScript genesisOutputScript = CScript() << ParseHex("04c10e83b2703ccf322f7dbd62dd5855ac7c10bd055814ce121ba32607d573b8810c02c0582aed05b4deb9c4b77b26d92428c61256cd42774babea0a073b2ed0c9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */
static Checkpoints::MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
                (0, uint256("0x0000b712bda549469a4533c0827bd8263299cd2d13030b15e72d93a3e094e914"))
                (50000, uint256("e13891ed03b98324162082f47ae4dd4250a075ae9a96f982961e284aa83259b5")) // Block 50.000
                (100000, uint256("c26704a2af85d7da0c4e15a7a6e7648f87e4dd15512fb4586d04fc5ec0b01211")) // Block 100.000
                (150000, uint256("69c550f21163c0f0c4bbb07184c7d178f0d372048a8bd1e52473517c33b87b3f")) // Block 150.000
                (200000, uint256("ffb7f3996cd225fa8e106117ec7e428a2e8db4f3e76e8c03b24c36ade5ecddd2")) // Block 200.000
                (250000, uint256("149cd7201a2978fea3ee0f098ab8f989b1b9436f2cc8cebf45986ff9aaad3ca1")) // Block 250.000
                (300000, uint256("a4379a7772bda6a59d7a03b59da3168585d97e9ece9906c327cbc07307169fff")) // Block 300.000
                (350000, uint256("fd0c691aad1762436b65939c0cc60df87d6b95397047c55f718c1831d75aa1bb")) // Block 350.000
                (400000, uint256("970dfe35eaeb3a3c0339fcb28800b669341e8ca61f2da3aac11a9253896bd669")) // Block 400.000
                (450000, uint256("05db87a93a517a551a68417a9ac21854e5a899ea8895d890639486a8a23e1a35")) // Block 450.000
                (500000, uint256("8263684c3f6f957babcff5f9d793b6b1e9129b8f10a67ca769e6ce5fd3c2dbd4")) // Block 500.000
                (550000, uint256("0d8789b2fa1e90ae584635b1d4945d80394678096291c9b16e387ab4a16c9abf")) // Block 550.000
                (600000, uint256("82485a51346003316f4ad962e1999e313fb0094e8cbc5893a82e57cb7ac2d62a")); // Block 550.000
static const Checkpoints::CCheckpointData data = {
        &mapCheckpoints,
        1565931910, // * UNIX timestamp of last checkpoint block (Done)
        1232063,    // * total number of transactions between genesis and last checkpoint TODO: keep using correct number
        //   (the tx=... number in the SetBestChain debug.log lines)
        2000        // * estimated number of transactions per day after checkpoint
};


static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
        boost::assign::map_list_of(0, uint256("0x001"));
static const Checkpoints::CCheckpointData dataTestnet = {
        &mapCheckpointsTestnet,
        1512932225,
        0,
        450};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256S("0x001"));
static const Checkpoints::CCheckpointData dataRegtest = {
        &mapCheckpointsRegtest,
        1411111111,
        0,
        100};

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";

        genesis = CreateGenesisBlock(1454124731, 2402015, 0x1e0ffff0, 1, 250 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0000041e482b9b9691d98eefb48473405c0b8ec31b76df3797c74a78680ef818"));
        assert(genesis.hashMerkleRoot == uint256S("0x1b2ef6e2f28be914103a277377ae7729dcd125dfeb8bf97bd5964ba72b6dc39b"));

        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.powLimit   = ~UINT256_ZERO >> 20;   // RPICOIN starting difficulty is 1 / 2^12
        consensus.posLimitV1 = ~UINT256_ZERO >> 24;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nBudgetCycleBlocks = 43200;       // approx. 1 every 30 days
        consensus.nBudgetFeeConfirmations = 6;      // Number of confirmations for the finalization fee
        consensus.nCoinbaseMaturity = 100;
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;
        consensus.nMasternodeCountDrift = 20;       // num of MN we allow the see-saw payments to be off by
        consensus.nMaxMoneyOut = 21000000 * COIN;
        consensus.nPoolMaxTransactions = 3;
        consensus.nProposalEstablishmentTime = 60 * 60 * 24;    // must be at least a day old to make it into a budget
        consensus.nStakeMinAge = 60 * 60;
        consensus.nStakeMinDepth = 600;
        consensus.nTargetTimespan = 40 * 60;
        consensus.nTargetTimespanV2 = 30 * 60;
        consensus.nTargetSpacing = 1 * 60;
        consensus.nTimeSlotLength = 15;

        // spork keys
        consensus.strSporkPubKey = "040F129DE6546FE405995329A887329BED4321325B1A73B0A257423C05C1FCFE9E40EF0678AEF59036A22C42E61DFD29DF7EFB09F56CC73CADF64E05741880E3E7";
        consensus.strSporkPubKeyOld = "0499A7AF4806FC6DE640D23BC5936C29B77ADF2174B4F45492727F897AE63CF8D27B2F05040606E0D14B547916379FA10716E344E745F880EDC037307186AA25B7";
        consensus.nTime_EnforceNewSporkKey = 1566860400;    //!> August 26, 2019 11:00:00 PM GMT
        consensus.nTime_RejectOldSporkKey = 1569538800;     //!> September 26, 2019 11:00:00 PM GMT

        // height-based activations
        consensus.height_last_ZC_AccumCheckpoint = 1686240;
        consensus.height_last_ZC_WrappedSerials = 1686229;
        consensus.height_start_InvalidUTXOsCheck = 902850;
        consensus.height_start_ZC_InvalidSerials = 891737;
        consensus.height_start_ZC_SerialRangeCheck = 895400;
        consensus.height_ZC_RecalcAccumulators = 908000;

        // validation by-pass
        consensus.nRpicoinBadBlockTime = 1471401614;    // Skip nBit validation of Block 259201 per PR #915
        consensus.nRpicoinBadBlockBits = 0x1c056dac;    // Skip nBit validation of Block 259201 per PR #915

        // Zerocoin-related params
        consensus.ZC_Modulus = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784"
                "4069182906412495150821892985591491761845028084891200728449926873928072877767359714183472702618963750149718246911"
                "6507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363"
                "7259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133"
                "8441436038339044149526344321901146575444541784240209246165157233507787077498171257724679629263863563732899121548"
                "31438167899885040445364023527381951378636564391212010397122822120720357";
        consensus.ZC_MaxPublicSpendsPerTx = 637;    // Assume about 220 bytes each input
        consensus.ZC_MaxSpendsPerTx = 7;            // Assume about 20kb each input
        consensus.ZC_MinMintConfirmations = 20;
        consensus.ZC_MinMintFee = 1 * CENT;
        consensus.ZC_MinStakeDepth = 200;
        consensus.ZC_TimeStart = 1508214600;        // October 17, 2017 4:30:00 AM
        consensus.ZC_WrappedSerialsSupply = 4131563 * COIN;   // zerocoin supply at height_last_ZC_WrappedSerials

        // Network upgrades
        consensus.vUpgrades[Consensus::BASE_NETWORK].nActivationHeight =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_POS].nActivationHeight           = 259201;
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].nActivationHeight        = 615800;
        consensus.vUpgrades[Consensus::UPGRADE_ZC].nActivationHeight            = 863787;
        consensus.vUpgrades[Consensus::UPGRADE_ZC_V2].nActivationHeight         = 1153160;
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].nActivationHeight         = 1808634;
        consensus.vUpgrades[Consensus::UPGRADE_ZC_PUBLIC].nActivationHeight     = 1880000;
        consensus.vUpgrades[Consensus::UPGRADE_V3_4].nActivationHeight          = 1967000;
        consensus.vUpgrades[Consensus::UPGRADE_V4_0].nActivationHeight          = 2153200;
        consensus.vUpgrades[Consensus::UPGRADE_V5_DUMMY].nActivationHeight =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_ZC].hashActivationBlock =
                uint256S("0x5b2482eca24caf2a46bb22e0545db7b7037282733faa3a42ec20542509999a64");
        consensus.vUpgrades[Consensus::UPGRADE_ZC_V2].hashActivationBlock =
                uint256S("0x37ea75fe1c9314171cff429a91b25b9f11331076d1c9de50ee4054d61877f8af");
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].hashActivationBlock =
                uint256S("0x82629b7a9978f5c7ea3f70a12db92633a7d2e436711500db28b97efd48b1e527");
        consensus.vUpgrades[Consensus::UPGRADE_ZC_PUBLIC].hashActivationBlock =
                uint256S("0xe2448b76d88d37aba4194ffed1041b680d779919157ddf5cbf423373d7f8078e");
        consensus.vUpgrades[Consensus::UPGRADE_V3_4].hashActivationBlock =
                uint256S("0x0ef2556e40f3b9f6e02ce611b832e0bbfe7734a8ea751c7b555310ee49b61456");
        consensus.vUpgrades[Consensus::UPGRADE_V4_0].hashActivationBlock =
                uint256S("0x14e477e597d24549cac5e59d97d32155e6ec2861c1003b42d0566f9bf39b65d5");

        consensus.nSubsidyHalvingInterval = 0;
        consensus.nEnforceBlockUpgradeMajority = 750;
        consensus.nRejectBlockOutdatedMajority = 950;
        consensus.nToCheckBlockUpgradeMajority = 1000;
        consensus.nMaxReorganizationDepth = 500;
        consensus.powLimit = ~uint256(0) >> 16; // RPICOIN starting difficulty is 1 / 2^12
        consensus.stakeLimit = ~uint256(0) >> 48;
        consensus.nTargetTimespanV1 =  16 * 60; // RPICOIN Old: 1 day
        consensus.nTargetTimespanV2 =  1 * 60; // RPICOIN New: 1 day
        consensus.nTargetSpacingV1 = 64;  // RPICOIN Old: 1 minute
        consensus.nTargetSpacingV2 = 1 * 60;  // RPICOIN New: 1 minute
        consensus.nMaturity = 10;
        consensus.nMasternodeCountDrift = 20;
        consensus.nMaxMoneyOut = 5999991337 * COIN;
        /** Height or Time Based Activations **/
        consensus.nLastPOWBlock = 100;
        consensus.nNewProtocolStartHeight = 600000;
        consensus.nNewProtocolStartTime = 1564511361; //Tuesday, July 30, 2019 18:29:21 PM #NOT USED
        consensus.nZerocoinStartHeight = consensus.nNewProtocolStartHeight;
        consensus.nZerocoinStartTime = consensus.nNewProtocolStartTime;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0x90;
        pchMessageStart[1] = 0xc4;
        pchMessageStart[2] = 0xfd;
        pchMessageStart[3] = 0xe9;
        nDefaultPort = 51472;
        pchMessageStart[0] = 0x14;
        pchMessageStart[1] = 0x37;
        pchMessageStart[2] = 0x25;
        pchMessageStart[3] = 0x61;
        vAlertPubKey=ParseHex("04890c0c7f2bf2304af7a7de92f3717d96b5d347e30a179cf975ab5e0152b113103598798599fecb8d735238e6dae110565d230d7ba93a076b98bd5bd5bb5f17fb");
        nDefaultPort = 18000;
        nMinerThreads = 0;
        consensus.nBlockDoubleAccumulated = -1;
        consensus.nBlockEnforceSerialRange = consensus.nNewProtocolStartHeight; //Enforce serial range starting this block
        consensus.nBlockRecalculateAccumulators = consensus.nNewProtocolStartHeight; //Trigger a recalculation of accumulators
        consensus.nBlockFirstFraudulent = -1; //First block that bad serials emerged
        consensus.nBlockLastGoodCheckpoint = consensus.nNewProtocolStartHeight; //Last valid accumulator checkpoint
        consensus.nRpicoinBadBlockTime = 0; // Skip nBit validation of Block 259201 per PR #915
        consensus.nRpicoinBadBlocknBits = 0; // Skip nBit validation of Block 259201 per PR #915
        consensus.nStakeMinAge = 4 * 60 * 60;
        consensus.nStakeMinAgeV2 = 60 * 60;   // RPICOIN: 1 hour

        // Note that of those with the service bits flag, most only support a subset of possible options
        vSeeds.push_back(CDNSSeedData("fuzzbawls.pw", "rpicoin.seed.fuzzbawls.pw", true));     // Primary DNS Seeder from Fuzzbawls
        vSeeds.push_back(CDNSSeedData("fuzzbawls.pw", "rpicoin.seed2.fuzzbawls.pw", true));    // Secondary DNS Seeder from Fuzzbawls
        // Public coin spend enforcement
        consensus.nPublicZCSpends = 650000;

        // Fake Serial Attack
        consensus.nFakeSerialBlockheightEnd = -1;
        consensus.nSupplyBeforeFakeSerial = 0;   // zerocoin supply at block nFakeSerialBlockheightEnd

        /**
         * Build the genesis block. Note that the output of the genesis coinbase cannot
         * be spent as it did not originally exist in the database.
         *
         * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
         *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
         *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
         *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
         *   vMerkleTree: e0028e
         */
        const char* pszTimestamp = "Buying Bitcoin Is Not Investing, Claims Warren Buffett";
        CMutableTransaction txNew;
        txNew.nVersion = 1;
        txNew.nTime = 1525283223;
        txNew.nLockTime = 0;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 0 << CScriptNum(42) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 113713337 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("0467b402a59fdb190a280fd7bc2234986dae22a28df82dabe19b58383c1c1f78b6d82f88fb90054efa6ff0025a8a38b802a2d04b5037f4fc56beb445f18d22d403") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime = 1525283223;
        genesis.nBits = consensus.powLimit.GetCompact();
        genesis.nNonce = 4004610;

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256("0x0000b712bda549469a4533c0827bd8263299cd2d13030b15e72d93a3e094e914"));
        assert(genesis.hashMerkleRoot == uint256("0x768512611033b4e7af714b9312d1a0e529b2fb4efd9b99d406403012df093073"));

        vSeeds.push_back(CDNSSeedData("seed1.rpicoin.com", "seed1.rpicoin.com"));
        vSeeds.push_back(CDNSSeedData("seed2.rpicoin.com", "seed2.rpicoin.com"));
        vSeeds.push_back(CDNSSeedData("seed3.rpicoin.com", "seed3.rpicoin.com"));
        vSeeds.push_back(CDNSSeedData("seed4.rpicoin.com", "seed4.rpicoin.com"));
        vSeeds.push_back(CDNSSeedData("seed5.rpicoin.com", "seed5.rpicoin.com"));
        vSeeds.push_back(CDNSSeedData("seed6.rpicoin.com", "seed6.rpicoin.com"));
        vSeeds.push_back(CDNSSeedData("seed7.rpicoin.com", "seed7.rpicoin.com"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 30);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 13);
        base58Prefixes[STAKING_ADDRESS] = std::vector<unsigned char>(1, 63);     // starting with 'S'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 212);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x02)(0x2D)(0x25)(0x33).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x02)(0x21)(0x31)(0x2B).convert_to_container<std::vector<unsigned char> >();
        // BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 60);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 122);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 145);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x77).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));
        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        consensus.fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fDefaultCheckMemPool = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        consensus.fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        fHeadersFirstSyncingActive = false;

        // Sapling
        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "ps";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "pviews";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "rpiks";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]         = "p-secret-spending-key-main";
        consensus.nPoolMaxTransactions = 3;
        consensus.nBudgetCycleBlocks = 43200; //!< Amount of blocks in a months period of time (using 1 minutes per) = (60*24*30)
        consensus.strSporkKey = "042ebd54696c8118a15522c1a755845ce3eab63ab3f655533bb16660539278788ae0221e0ea3fd96a5def1d3707672561a319d2b1a7b07b9139c1846aea406b338";
        consensus.strObfuscationPoolDummyAddress = "RJqgPMnzYPpwwctE1cXC691dC7EuqFAHZW ";
        consensus.nStartMasternodePayments = consensus.nNewProtocolStartTime; // July 2, 2018

        /** Zerocoin */
        consensus.zerocoinModulus = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784"
                          "4069182906412495150821892985591491761845028084891200728449926873928072877767359714183472702618963750149718246911"
                          "6507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363"
                          "7259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133"
                          "8441436038339044149526344321901146575444541784240209246165157233507787077498171257724679629263863563732899121548"
                          "31438167899885040445364023527381951378636564391212010397122822120720357";
        consensus.nMaxZerocoinSpendsPerTransaction = 7; // Assume about 20kb each
        consensus.nMaxZerocoinPublicSpendsPerTransaction = 637; // Assume about 220 bytes each input
        consensus.nMinZerocoinMintFee = 1 * CENT; //high fee required for zerocoin mints
        consensus.nMintRequiredConfirmations = 20; //the maximum amount of confirmations until accumulated in 19
        consensus.nRequiredAccumulation = 1;
        consensus.nDefaultSecurityLevel = 100; //full security level for accumulators
        consensus.nZerocoinHeaderVersion = 8; //Block headers must be this version once zerocoin is active
        consensus.nZerocoinRequiredStakeDepth = 200; //The required confirmations for a zrpi to be stakable

        consensus.nBudget_Fee_Confirmations = 6; // Number of confirmations for the finalization fee
        consensus.nProposalEstablishmentTime = 60 * 60 * 24; // Proposals must be at least a day old to make it into a budget
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }

};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";

        genesis = CreateGenesisBlock(1454124731, 2402015, 0x1e0ffff0, 1, 250 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0000041e482b9b9691d98eefb48473405c0b8ec31b76df3797c74a78680ef818"));
        assert(genesis.hashMerkleRoot == uint256S("0x1b2ef6e2f28be914103a277377ae7729dcd125dfeb8bf97bd5964ba72b6dc39b"));

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.powLimit   = ~UINT256_ZERO >> 20;   // RPICOIN starting difficulty is 1 / 2^12
        consensus.posLimitV1 = ~UINT256_ZERO >> 24;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nBudgetCycleBlocks = 144;         // approx 10 cycles per day
        consensus.nBudgetFeeConfirmations = 3;      // (only 8-blocks window for finalization on testnet)
        consensus.nCoinbaseMaturity = 15;
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;
        consensus.nMasternodeCountDrift = 4;        // num of MN we allow the see-saw payments to be off by
        consensus.nMaxMoneyOut = 43199500 * COIN;
        consensus.nPoolMaxTransactions = 2;
        consensus.nProposalEstablishmentTime = 60 * 5;  // at least 5 min old to make it into a budget
        consensus.nStakeMinAge = 60 * 60;
        consensus.nStakeMinDepth = 100;
        consensus.nTargetTimespan = 40 * 60;
        consensus.nTargetTimespanV2 = 30 * 60;
        consensus.nTargetSpacing = 1 * 60;
        consensus.nTimeSlotLength = 15;

        // spork keys
        consensus.strSporkPubKey = "04E88BB455E2A04E65FCC41D88CD367E9CCE1F5A409BE94D8C2B4B35D223DED9C8E2F4E061349BA3A38839282508066B6DC4DB72DD432AC4067991E6BF20176127";
        consensus.strSporkPubKeyOld = "04A8B319388C0F8588D238B9941DC26B26D3F9465266B368A051C5C100F79306A557780101FE2192FE170D7E6DEFDCBEE4C8D533396389C0DAFFDBC842B002243C";
        consensus.nTime_EnforceNewSporkKey = 1566860400;    //!> August 26, 2019 11:00:00 PM GMT
        consensus.nTime_RejectOldSporkKey = 1569538800;     //!> September 26, 2019 11:00:00 PM GMT

        // height based activations
        consensus.height_last_ZC_AccumCheckpoint = 1106090;
        consensus.height_last_ZC_WrappedSerials = -1;
        consensus.height_start_InvalidUTXOsCheck = 999999999;
        consensus.height_start_ZC_InvalidSerials = 999999999;
        consensus.height_start_ZC_SerialRangeCheck = 1;
        consensus.height_ZC_RecalcAccumulators = 999999999;

        // validation by-pass
        consensus.nRpicoinBadBlockTime = 1489001494; // Skip nBit validation of Block 201 per PR #915
        consensus.nRpicoinBadBlockBits = 0x1e0a20bd; // Skip nBit validation of Block 201 per PR #915

        // Zerocoin-related params
        consensus.ZC_Modulus = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784"
                "4069182906412495150821892985591491761845028084891200728449926873928072877767359714183472702618963750149718246911"
                "6507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363"
                "7259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133"
                "8441436038339044149526344321901146575444541784240209246165157233507787077498171257724679629263863563732899121548"
                "31438167899885040445364023527381951378636564391212010397122822120720357";
        consensus.ZC_MaxPublicSpendsPerTx = 637;    // Assume about 220 bytes each input
        consensus.ZC_MaxSpendsPerTx = 7;            // Assume about 20kb each input
        consensus.ZC_MinMintConfirmations = 20;
        consensus.ZC_MinMintFee = 1 * CENT;
        consensus.ZC_MinStakeDepth = 200;
        consensus.ZC_TimeStart = 1501776000;
        consensus.ZC_WrappedSerialsSupply = 0;   // WrappedSerials only on main net

        // Network upgrades
        consensus.vUpgrades[Consensus::BASE_NETWORK].nActivationHeight =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_POS].nActivationHeight           = 201;
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].nActivationHeight        = 51197;
        consensus.vUpgrades[Consensus::UPGRADE_ZC].nActivationHeight            = 201576;
        consensus.vUpgrades[Consensus::UPGRADE_ZC_V2].nActivationHeight         = 444020;
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].nActivationHeight         = 851019;
        consensus.vUpgrades[Consensus::UPGRADE_ZC_PUBLIC].nActivationHeight     = 1106100;
        consensus.vUpgrades[Consensus::UPGRADE_V3_4].nActivationHeight          = 1214000;
        consensus.vUpgrades[Consensus::UPGRADE_V4_0].nActivationHeight          = 1347000;
        consensus.vUpgrades[Consensus::UPGRADE_V5_DUMMY].nActivationHeight =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_ZC].hashActivationBlock =
                uint256S("0x258c489f42f03cb97db2255e47938da4083eee4e242853c2d48bae2b1d0110a6");
        consensus.vUpgrades[Consensus::UPGRADE_ZC_V2].hashActivationBlock =
                uint256S("0xfcc6a4c1da22e4db2ada87d257d6eef5e6922347ca1bb7879edfee27d24f64b5");
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].hashActivationBlock =
                uint256S("0xc54b3e7e8b710e4075da1806adf2d508ae722627d5bcc43f594cf64d5eef8b30");
        consensus.vUpgrades[Consensus::UPGRADE_V3_4].hashActivationBlock =
                uint256S("0x1822577176173752aea33d1f60607cefe9e0b1c54ebaa77eb40201a385506199");
        consensus.vUpgrades[Consensus::UPGRADE_V4_0].hashActivationBlock =
                uint256S("0x30c173ffc09a13f288bf6e828216107037ce5b79536b1cebd750a014f4939882");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */

        pchMessageStart[0] = 0x45;
        pchMessageStart[1] = 0x76;
        pchMessageStart[2] = 0x65;
        pchMessageStart[3] = 0xba;
        nDefaultPort = 51474;
        consensus.nSubsidyHalvingInterval = 0;
        consensus.nEnforceBlockUpgradeMajority = 51;
        consensus.nRejectBlockOutdatedMajority = 75;
        consensus.nToCheckBlockUpgradeMajority = 100;
        consensus.nMaxReorganizationDepth = 500;
        consensus.powLimit = ~uint256(0) >> 16; // RPICOIN starting difficulty is 1 / 2^12
        consensus.stakeLimit = ~uint256(0) >> 48;
        consensus.nTargetTimespanV1 =  16 * 60; // RPICOIN Old: 1 day
        consensus.nTargetTimespanV2 =  1 * 60; // RPICOIN New: 1 day
        consensus.nTargetSpacingV1 = 64;  // RPICOIN Old: 1 minute
        consensus.nTargetSpacingV2 = 1 * 60;  // RPICOIN New: 1 minute
        consensus.nLastPOWBlock = 100;
        consensus.nMaturity = 10;
        consensus.nMasternodeCountDrift = 4;
        consensus.nMaxMoneyOut = 5999991337 * COIN;
        consensus.nNewProtocolStartHeight = 750;
        consensus.nNewProtocolStartTime = 1537830552;
        consensus.nZerocoinStartHeight = consensus.nNewProtocolStartHeight;
        consensus.nZerocoinStartTime = consensus.nNewProtocolStartTime; // July 2, 2018
        consensus.nRpicoinBadBlockTime = 0; // Skip nBit validation of Block 259201 per PR #915
        consensus.nRpicoinBadBlocknBits = 0; // Skip nBit validation of Block 201 per PR #915

        pchMessageStart[0] = 0x44;
        pchMessageStart[1] = 0x18;
        pchMessageStart[2] = 0x61;
        pchMessageStart[3] = 0x33;
        vAlertPubKey=ParseHex("0467b402a59fdb190a280fd7bc2234986dae22a28df82dabe19b58383c1c1f78b6d82f88fb90054efa6ff0025a8a38b802a2d04b5037f4fc56beb445f18d22d403");
        nDefaultPort = 18002;
        nMinerThreads = 0;

        const char* pszTimestamp = "Buying Bitcoin Is Not Investing, Claims Warren Buffett";
        genesis.SetNull();
        CMutableTransaction txNew2;
        txNew2.nVersion = 1;
        txNew2.nTime = 1525283445;
        txNew2.nLockTime = 0;
        txNew2.vin.resize(1);
        txNew2.vout.resize(1);
        txNew2.vin[0].scriptSig = CScript() << 0 << CScriptNum(42) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew2.vout[0].SetEmpty();

        // Public coin spend enforcement
        consensus.nPublicZCSpends = 1106100;

        // Fake Serial Attack
        consensus.nFakeSerialBlockheightEnd = -1;
        consensus.nSupplyBeforeFakeSerial = 0;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.vtx.push_back(txNew2);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1525283445;
        genesis.nBits    = consensus.powLimit.GetCompact();
        genesis.nNonce   = 1759192;

        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256("0x0000d17194220e485dce46951ad042de557ceefdcdc96b1a4358847c103f9aae"));
        assert(genesis.hashMerkleRoot == uint256("0x25533f4208eab0dd0e880a32df9405daff31850bd23d2ec9dd7db8532992cb88"));


        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.push_back(CDNSSeedData("fuzzbawls.pw", "rpicoin-testnet.seed.fuzzbawls.pw", true));
        vSeeds.push_back(CDNSSeedData("fuzzbawls.pw", "rpicoin-testnet.seed2.fuzzbawls.pw", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 139); // Testnet rpicoin addresses start with 'x' or 'y'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 19);  // Testnet rpicoin script addresses start with '8' or '9'
        base58Prefixes[STAKING_ADDRESS] = std::vector<unsigned char>(1, 73);     // starting with 'W'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        // Testnet rpicoin BIP32 pubkeys start with 'DRKV'
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x3a)(0x80)(0x61)(0xa0).convert_to_container<std::vector<unsigned char> >();
        // Testnet rpicoin BIP32 prvkeys start with 'DRKP'
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x3a)(0x80)(0x58)(0x37).convert_to_container<std::vector<unsigned char> >();
        // Testnet rpicoin BIP44 coin type is '1' (All coin's testnet default)

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 110);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 8);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));
        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        consensus.fSkipProofOfWorkCheck = false;
        fMiningRequiresPeers = true;
        consensus.fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = false;
        fDefaultCheckMemPool = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        // Sapling
        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "ptestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "pviewtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "rpiktestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]         = "p-secret-spending-key-test";
        consensus.nPoolMaxTransactions = 2;
        consensus.nBudgetCycleBlocks = 144; //!< Ten cycles per day on testnet
        consensus.strSporkKey = "04e175173ea919f973cf4bf00d10e1c29c8ef75568c59056630d5a5cce8f6d8ac6edf0bb21baa2a24ecff17ce83b9863a88a54c54ca87c709c8a3f1dfef9d268e6";
        consensus.strObfuscationPoolDummyAddress = "mbTYaNZm7TaPt5Du65aPsL8FNTktufYydC";
        consensus.nStartMasternodePayments = consensus.nNewProtocolStartTime;
        consensus.nBudget_Fee_Confirmations = 3; // Number of confirmations for the finalization fee. We have to make this very short
        // here because we only have a 8 block finalization window on testnet
        consensus.nProposalEstablishmentTime = 60 * 5; // Proposals must be at least 5 mns old to make it into a test budget
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";

        genesis = CreateGenesisBlock(1454124731, 2402015, 0x1e0ffff0, 1, 250 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0000041e482b9b9691d98eefb48473405c0b8ec31b76df3797c74a78680ef818"));
        assert(genesis.hashMerkleRoot == uint256S("0x1b2ef6e2f28be914103a277377ae7729dcd125dfeb8bf97bd5964ba72b6dc39b"));

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.powLimit   = ~UINT256_ZERO >> 20;   // RPICOIN starting difficulty is 1 / 2^12
        consensus.posLimitV1 = ~UINT256_ZERO >> 24;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nBudgetCycleBlocks = 144;         // approx 10 cycles per day
        consensus.nBudgetFeeConfirmations = 3;      // (only 8-blocks window for finalization on regtest)
        consensus.nCoinbaseMaturity = 100;
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;
        consensus.nMasternodeCountDrift = 4;        // num of MN we allow the see-saw payments to be off by
        consensus.nMaxMoneyOut = 43199500 * COIN;
        consensus.nPoolMaxTransactions = 2;
        consensus.nProposalEstablishmentTime = 60 * 5;  // at least 5 min old to make it into a budget
        consensus.nStakeMinAge = 0;
        consensus.nStakeMinDepth = 2;
        consensus.nTargetTimespan = 40 * 60;
        consensus.nTargetTimespanV2 = 30 * 60;
        consensus.nTargetSpacing = 1 * 60;
        consensus.nTimeSlotLength = 15;

        /* Spork Key for RegTest:
        WIF private key: 932HEevBSujW2ud7RfB1YF91AFygbBRQj3de3LyaCRqNzKKgWXi
        private key hex: bd4960dcbd9e7f2223f24e7164ecb6f1fe96fc3a416f5d3a830ba5720c84b8ca
        Address: yCvUVd72w7xpimf981m114FSFbmAmne7j9
        */
        consensus.strSporkPubKey = "043969b1b0e6f327de37f297a015d37e2235eaaeeb3933deecd8162c075cee0207b13537618bde640879606001a8136091c62ec272dd0133424a178704e6e75bb7";
        consensus.strSporkPubKeyOld = "";
        consensus.nTime_EnforceNewSporkKey = 0;
        consensus.nTime_RejectOldSporkKey = 0;

        // height based activations
        consensus.height_last_ZC_AccumCheckpoint = 310;     // no checkpoints on regtest
        consensus.height_last_ZC_WrappedSerials = -1;
        consensus.height_start_InvalidUTXOsCheck = 999999999;
        consensus.height_start_ZC_InvalidSerials = 999999999;
        consensus.height_start_ZC_SerialRangeCheck = 300;
        consensus.height_ZC_RecalcAccumulators = 999999999;

        // Zerocoin-related params
        consensus.ZC_Modulus = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784"
                "4069182906412495150821892985591491761845028084891200728449926873928072877767359714183472702618963750149718246911"
                "6507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363"
                "7259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133"
                "8441436038339044149526344321901146575444541784240209246165157233507787077498171257724679629263863563732899121548"
                "31438167899885040445364023527381951378636564391212010397122822120720357";
        consensus.ZC_MaxPublicSpendsPerTx = 637;    // Assume about 220 bytes each input
        consensus.ZC_MaxSpendsPerTx = 7;            // Assume about 20kb each input
        consensus.ZC_MinMintConfirmations = 10;
        consensus.ZC_MinMintFee = 1 * CENT;
        consensus.ZC_MinStakeDepth = 10;
        consensus.ZC_TimeStart = 0;                 // not implemented on regtest
        consensus.ZC_WrappedSerialsSupply = 0;

        // Network upgrades
        consensus.vUpgrades[Consensus::BASE_NETWORK].nActivationHeight =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_POS].nActivationHeight           = 251;
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].nActivationHeight        = 251;
        consensus.vUpgrades[Consensus::UPGRADE_ZC].nActivationHeight            = 300;
        consensus.vUpgrades[Consensus::UPGRADE_ZC_V2].nActivationHeight         = 300;
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].nActivationHeight         =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_ZC_PUBLIC].nActivationHeight     = 400;
        consensus.vUpgrades[Consensus::UPGRADE_V3_4].nActivationHeight          = 251;
        consensus.vUpgrades[Consensus::UPGRADE_V4_0].nActivationHeight          =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_V5_DUMMY].nActivationHeight       = 300;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */

        pchMessageStart[0] = 0xa1;
        pchMessageStart[1] = 0xcf;
        pchMessageStart[2] = 0x7e;
        pchMessageStart[3] = 0xac;
        nDefaultPort = 51476;
        consensus.nSubsidyHalvingInterval = 0;
        consensus.nEnforceBlockUpgradeMajority = 750;
        consensus.nRejectBlockOutdatedMajority = 950;
        consensus.nToCheckBlockUpgradeMajority = 1000;
        consensus.nMaxReorganizationDepth = 500;
        consensus.powLimit = ~uint256(0) >> 1; // RPICOIN starting difficulty is 1 / 2^12
        consensus.stakeLimit = ~uint256(0) >> 48;
        consensus.nLastPOWBlock = 250;
        consensus.nTargetTimespanV1 = 16 * 60; // RPICOIN Old: 1 day
        consensus.nTargetTimespanV2 = 1 * 60; // RPICOIN New: 1 day
        consensus.nTargetSpacingV1 = 64;        // RPICOIN Old: 1 minutes
        consensus.nTargetSpacingV2 = 1 * 60;        // RPICOIN New: 1 minute
        consensus.nNewProtocolStartHeight = 300;
        consensus.nStakeMinAge = 0;
        consensus.nStakeMinAgeV2 = 0;

        consensus.nBlockEnforceSerialRange = 1; //Enforce serial range starting this block
        consensus.nBlockRecalculateAccumulators = 999999999; //Trigger a recalculation of accumulators
        consensus.nBlockFirstFraudulent = 999999999; //First block that bad serials emerged
        consensus.nBlockLastGoodCheckpoint = 999999999; //Last valid accumulator checkpoint

        // Public coin spend enforcement
        consensus.nPublicZCSpends = 350;

        // Fake Serial Attack
        consensus.nFakeSerialBlockheightEnd = -1;

        pchMessageStart[0] = 0xAD;
        pchMessageStart[1] = 0xBF;
        pchMessageStart[2] = 0xB1;
        pchMessageStart[3] = 0xDA;
        nMinerThreads = 1;
        genesis.nTime = 1411111111;
        genesis.nBits  = consensus.powLimit.GetCompact();
        genesis.nNonce = 2;

        consensus.hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 18004;
//        printf("Req net\n");
//        printf("genesis = %s\n", genesis.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256("6bc08d74ce7ed1003efdb1eb6a28b1a2e283f9486664be37fee7ea9d1ece6be1"));

        vFixedSeeds.clear(); //! Testnet mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Testnet mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        consensus.fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fDefaultCheckMemPool = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        consensus.fSkipProofOfWorkCheck = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        /* Spork Key for RegTest:
        WIF private key: 932HEevBSujW2ud7RfB1YF91AFygbBRQj3de3LyaCRqNzKKgWXi
        private key hex: bd4960dcbd9e7f2223f24e7164ecb6f1fe96fc3a416f5d3a830ba5720c84b8ca
        Address: yCvUVd72w7xpimf981m114FSFbmAmne7j9
        */
        consensus.strSporkKey = "02161ea61cdeacc91ac87728a98966b6e6ebda46c50644d954e03a6ba5426a78d5";
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE_NETWORK && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }
};
static CRegTestParams regTestParams;

static CChainParams* pCurrentParams = 0;

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}
