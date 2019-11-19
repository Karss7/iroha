/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_BLOCK_INDEX_HPP
#define IROHA_POSTGRES_BLOCK_INDEX_HPP

#include "ametsuchi/impl/block_index.hpp"

#include "ametsuchi/indexer.hpp"
#include "interfaces/transaction.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace ametsuchi {
    /**
     * Creates several indices for passed blocks. Namely:
     * transaction hash -> block, where this transaction is stored
     * transaction creator -> block where his transaction is located
     *
     * Additionally, for each Transfer Asset command:
     *   1. (account, asset) -> block for each:
     *     a. creator of the transaction
     *     b. source account
     *     c. destination account
     *   2. account -> block for source and destination accounts
     *   3. (account, height) -> list of txes
     */
    class PostgresBlockIndex : public BlockIndex {
     public:
      PostgresBlockIndex(std::unique_ptr<Indexer> indexer,
                         logger::LoggerPtr log);

      /// Index a block.
      void index(const shared_model::Block &block) override;

     private:
      /// Index a transaction.
      void makeAccountAssetIndex(
          const shared_model::types::AccountIdType &account_id,
          Indexer::TxPosition position,
          const shared_model::Transaction::CommandsType &commands);

      std::unique_ptr<Indexer> indexer_;
      logger::LoggerPtr log_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_BLOCK_INDEX_HPP
