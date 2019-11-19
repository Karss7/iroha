/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_TYPES_HPP
#define IROHA_MST_TYPES_HPP

#include <memory>

#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  class TransactionBatch;
  class TransactionResponse;
  class Peer;
}  // namespace shared_model

namespace iroha {

  using BatchPtr = std::shared_ptr<shared_model::TransactionBatch>;
  using ConstPeer = const shared_model::Peer;
  using TimeType = shared_model::types::TimestampType;
  using TxResponse = std::shared_ptr<shared_model::TransactionResponse>;

  template <typename T>
  using ConstRefT = const T &;

  using ConstRefBatch = ConstRefT<BatchPtr>;
  using ConstRefPeer = ConstRefT<shared_model::Peer>;
  using ConstRefTime = ConstRefT<TimeType>;

  class MstState;

  using ConstRefState = ConstRefT<MstState>;

  using DataType = BatchPtr;

  /**
   * Contains result of updating local state:
   *   - state with completed batches
   *   - state with updated (still not enough signatures) batches
   */
  struct StateUpdateResult {
    StateUpdateResult(std::shared_ptr<MstState> completed_state,
                      std::shared_ptr<MstState> updated_state)
        : completed_state_{std::move(completed_state)},
          updated_state_{std::move(updated_state)} {}
    std::shared_ptr<MstState> completed_state_;
    std::shared_ptr<MstState> updated_state_;
  };
}  // namespace iroha

#endif  // IROHA_MST_TYPES_HPP
