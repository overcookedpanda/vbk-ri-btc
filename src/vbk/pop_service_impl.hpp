#ifndef BITCOIN_SRC_VBK_POP_SERVICE_POP_SERVICE_IMPL_HPP
#define BITCOIN_SRC_VBK_POP_SERVICE_POP_SERVICE_IMPL_HPP

#include "chainparams.h"
#include "pop_service.hpp"

#include <memory>
#include <mutex>
#include <vector>

#include <util/system.h>
#include <veriblock/altintegration.hpp>
#include <veriblock/blockchain/alt_block_tree.hpp>
#include <veriblock/config.hpp>

namespace VeriBlock {

class PopServiceImpl : public PopService
{
private:
    std::mutex mutex;
    std::shared_ptr<altintegration::AltTree> altTree;

public:
    altintegration::AltTree& getAltTree() override
    {
        return *altTree;
    }

    PopServiceImpl(const altintegration::Config& config);

    ~PopServiceImpl() override = default;

    bool validatePopTxInput(const CTxIn& in, TxValidationState& state) override;

    bool validatePopTxOutput(const CTxOut& out, TxValidationState& state) override;
    PoPRewards getPopRewards(const CBlockIndex& pindexPrev, const Consensus::Params& consensusParams) override;
    void addPopPayoutsIntoCoinbaseTx(CMutableTransaction& coinbaseTx, const CBlockIndex& pindexPrev, const Consensus::Params& consensusParams) override;
    bool checkCoinbaseTxWithPopRewards(const CTransaction& tx, const CAmount& PoWBlockReward, const CBlockIndex& pindexPrev, const Consensus::Params& consensusParams, BlockValidationState& state) override;
    bool validatePopTx(const CTransaction& tx, TxValidationState& state) override;

    bool checkPopInputs(const CTransaction& tx, TxValidationState& state, unsigned int flags, bool cacheSigStore, PrecomputedTransactionData& txdata) override;

    std::vector<BlockBytes> getLastKnownVBKBlocks(size_t blocks) override;
    std::vector<BlockBytes> getLastKnownBTCBlocks(size_t blocks) override;

    void rewardsCalculateOutputs(const int& blockHeight, const CBlockIndex& endorsedBlock, const CBlockIndex& contaningBlocksTip, const CBlockIndex* difficulty_start_interval, const CBlockIndex* difficulty_end_interval, std::map<CScript, int64_t>& outputs) override;

    bool acceptBlock(const CBlockIndex& indexNew, BlockValidationState& state) override;
    bool addAllBlockPayloads(const CBlockIndex& indexNew, const CBlock& fullBlock, BlockValidationState& state) override;
    void invalidateBlockByHash(const uint256& block) override;
    bool setState(const uint256& block) override;

    bool evalScript(const CScript& script, std::vector<std::vector<unsigned char>>& stack, ScriptError* serror, altintegration::AltPayloads* pub, altintegration::ValidationState& state, bool with_checks) override;
    int compareForks(const CBlockIndex& left, const CBlockIndex& right) override;
};

bool parseTxPopPayloadsImpl(const CTransaction& tx, const Consensus::Params& params, TxValidationState& state, altintegration::AltPayloads& payloads);
bool parseBlockPopPayloadsImpl(const CBlock& block, const CBlockIndex& pindexThis, const Consensus::Params& params, BlockValidationState& state, std::vector<altintegration::AltPayloads>* payloads);
bool evalScriptImpl(const CScript& script, std::vector<std::vector<unsigned char>>& stack, ScriptError* serror, altintegration::AltPayloads* pub, altintegration::ValidationState& state, bool with_checks);
bool addAllPayloadsToBlockImpl(altintegration::AltTree& tree, const CBlockIndex& indexNew, const CBlock& block, BlockValidationState& state);

} // namespace VeriBlock
#endif //BITCOIN_SRC_VBK_POP_SERVICE_POP_SERVICE_IMPL_HPP