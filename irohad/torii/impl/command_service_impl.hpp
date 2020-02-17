/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TORII_COMMAND_SERVICE_IMPL_HPP
#define TORII_COMMAND_SERVICE_IMPL_HPP

#include "torii/command_service.hpp"

#include "ametsuchi/storage.hpp"
#include "ametsuchi/tx_presence_cache.hpp"
#include "cache/cache.hpp"
#include "cryptography/hash.hpp"
#include "interfaces/iroha_internal/tx_status_factory.hpp"
#include "logger/logger_fwd.hpp"
#include "torii/processor/transaction_processor.hpp"
#include "torii/status_bus.hpp"

#include "obj_counter.hpp"

namespace iroha {
  namespace torii {
    /**
     * Actual implementation of sync CommandServiceImpl.
     */
    class CommandServiceImpl : public CommandService {
     public:
      // TODO: 2019-03-13 @muratovv fix with abstract cache type IR-397
      using CacheType = iroha::cache::Cache<
          shared_model::crypto::Hash,
          std::shared_ptr<shared_model::interface::TransactionResponse>,
          shared_model::crypto::Hash::Hasher>;

      /**
       * Creates a new instance of CommandService
       * @param tx_processor - processor of received transactions
       * @param storage - to query transactions outside the cache
       * @param status_bus is a common notifier for tx statuses
       * @param cache - non-persistent cache, an instance of type
       * CommandServiceImpl::CacheType
       * @param tx_presence_cache a cache over persistent storage
       * @param log to print progress
       */
      CommandServiceImpl(
          std::shared_ptr<iroha::torii::TransactionProcessor> tx_processor,
          std::shared_ptr<iroha::ametsuchi::Storage> storage,
          std::shared_ptr<iroha::torii::StatusBus> status_bus,
          std::shared_ptr<shared_model::interface::TxStatusFactory>
              status_factory,
          std::shared_ptr<iroha::torii::CommandServiceImpl::CacheType> cache,
          std::shared_ptr<iroha::ametsuchi::TxPresenceCache> tx_presence_cache,
          logger::LoggerPtr log);

      ~CommandServiceImpl() override;

      /**
       * Disable copying in any way to prevent potential issues with common
       * storage/tx_processor
       */
      CommandServiceImpl(const CommandServiceImpl &) = delete;
      CommandServiceImpl &operator=(const CommandServiceImpl &) = delete;

      void handleTransactionBatch(
          SharedPtrCounter<shared_model::interface::TransactionBatch> batch)
          override;

      std::shared_ptr<shared_model::interface::TransactionResponse> getStatus(
          const shared_model::crypto::Hash &request) override;
      rxcpp::observable<
          std::shared_ptr<shared_model::interface::TransactionResponse>>
      getStatusStream(const shared_model::crypto::Hash &hash) override;

     private:
      /**
       * Execute events scheduled in run loop until it is not empty and the
       * subscriber is active
       * @param subscription - tx status subscription
       * @param run_loop - gRPC thread run loop
       */
      inline void handleEvents(rxcpp::composite_subscription &subscription,
                               rxcpp::schedulers::run_loop &run_loop);

      /**
       * Share tx status and log it
       * @param who identifier for the logging
       * @param response to be shared
       */
      void pushStatus(
          const std::string &who,
          std::shared_ptr<shared_model::interface::TransactionResponse>
              response);

      /**
       * Forward batch to transaction processor and set statuses of all
       * transactions inside it
       * @param batch to be processed
       */
      void processBatch(
          SharedPtrCounter<shared_model::interface::TransactionBatch> batch);

      std::shared_ptr<iroha::torii::TransactionProcessor> tx_processor_;
      std::shared_ptr<iroha::ametsuchi::Storage> storage_;
      std::shared_ptr<iroha::torii::StatusBus> status_bus_;
      std::shared_ptr<CacheType> cache_;
      std::shared_ptr<shared_model::interface::TxStatusFactory> status_factory_;
      std::shared_ptr<iroha::ametsuchi::TxPresenceCache> tx_presence_cache_;

      rxcpp::composite_subscription status_subscription_;

      logger::LoggerPtr log_;
    };

  }  // namespace torii
}  // namespace iroha

#endif  // TORII_COMMAND_SERVICE_IMPL_HPP
