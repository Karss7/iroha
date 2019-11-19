/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CONSENSUS_GATE_OBJECT_HPP
#define CONSENSUS_GATE_OBJECT_HPP

#include <boost/variant.hpp>
#include "ametsuchi/ledger_state.hpp"
#include "consensus/round.hpp"
#include "cryptography/hash.hpp"
#include "cryptography/public_key.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  class Block;
}  // namespace shared_model

namespace iroha {
  namespace consensus {

    struct BaseGateObject {
      consensus::Round round;
      std::shared_ptr<const LedgerState> ledger_state;

      BaseGateObject(consensus::Round round,
                     std::shared_ptr<const LedgerState> ledger_state)
          : round(std::move(round)), ledger_state(std::move(ledger_state)) {}
    };

    /// Current pair is valid
    struct PairValid : public BaseGateObject {
      std::shared_ptr<shared_model::Block> block;

      PairValid(consensus::Round round,
                std::shared_ptr<const LedgerState> ledger_state,
                std::shared_ptr<shared_model::Block> block)
          : BaseGateObject(std::move(round), std::move(ledger_state)),
            block(std::move(block)) {}
    };

    struct Synchronizable : public BaseGateObject {
      shared_model::types::PublicKeyCollectionType public_keys;

      Synchronizable(consensus::Round round,
                     std::shared_ptr<const LedgerState> ledger_state,
                     shared_model::types::PublicKeyCollectionType public_keys)
          : BaseGateObject(std::move(round), std::move(ledger_state)),
            public_keys(std::move(public_keys)) {}
    };

    /// Network votes for another pair and round
    struct VoteOther : public Synchronizable {
      shared_model::types::HashType hash;

      VoteOther(consensus::Round round,
                std::shared_ptr<const LedgerState> ledger_state,
                shared_model::types::PublicKeyCollectionType public_keys,
                shared_model::types::HashType hash)
          : Synchronizable(std::move(round),
                           std::move(ledger_state),
                           std::move(public_keys)),
            hash(std::move(hash)) {}
    };

    /// Reject on proposal
    struct ProposalReject : public Synchronizable {
      using Synchronizable::Synchronizable;
    };

    /// Reject on block
    struct BlockReject : public Synchronizable {
      using Synchronizable::Synchronizable;
    };

    /// Agreement on <None, None>
    struct AgreementOnNone : public Synchronizable {
      using Synchronizable::Synchronizable;
    };

    /// round.block_round > ledger_state->top_block_info.height + 1
    struct Future : public Synchronizable {
      using Synchronizable::Synchronizable;
    };

    using GateObject = boost::variant<PairValid,
                                      VoteOther,
                                      ProposalReject,
                                      BlockReject,
                                      AgreementOnNone,
                                      Future>;

  }  // namespace consensus
}  // namespace iroha

extern template class boost::variant<iroha::consensus::PairValid,
                                     iroha::consensus::VoteOther,
                                     iroha::consensus::ProposalReject,
                                     iroha::consensus::BlockReject,
                                     iroha::consensus::AgreementOnNone,
                                     iroha::consensus::Future>;

#endif  // CONSENSUS_GATE_OBJECT_HPP
