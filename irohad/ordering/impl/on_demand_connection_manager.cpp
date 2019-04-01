/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/on_demand_connection_manager.hpp"

#include <boost/range/combine.hpp>
#include "interfaces/iroha_internal/proposal.hpp"
#include "logger/logger.hpp"
#include "ordering/impl/on_demand_common.hpp"

using namespace iroha;
using namespace iroha::ordering;

OnDemandConnectionManager::OnDemandConnectionManager(
    std::shared_ptr<transport::OdOsNotificationFactory> factory,
    rxcpp::observable<CurrentPeers> peers,
    logger::LoggerPtr log)
    : log_(std::move(log)),
      factory_(std::move(factory)),
      subscription_(peers.subscribe([this](const auto &peers) {
        // exclusive lock
        std::lock_guard<std::shared_timed_mutex> lock(mutex_);

        this->initializeConnections(peers);
      })) {}

OnDemandConnectionManager::OnDemandConnectionManager(
    std::shared_ptr<transport::OdOsNotificationFactory> factory,
    rxcpp::observable<CurrentPeers> peers,
    CurrentPeers initial_peers,
    logger::LoggerPtr log)
    : OnDemandConnectionManager(std::move(factory), peers, std::move(log)) {
  // using start_with(initial_peers) results in deadlock
  initializeConnections(initial_peers);
}

OnDemandConnectionManager::~OnDemandConnectionManager() {
  subscription_.unsubscribe();
}

void OnDemandConnectionManager::onBatches(CollectionType batches) {
  std::shared_lock<std::shared_timed_mutex> lock(mutex_);
  connections_.peers[kConsumer]->onBatches(batches);
}

boost::optional<std::shared_ptr<const OnDemandConnectionManager::ProposalType>>
OnDemandConnectionManager::onRequestProposal(consensus::Round round) {
  std::shared_lock<std::shared_timed_mutex> lock(mutex_);

  log_->debug("onRequestProposal, {}", round);

  return connections_.peers[kIssuer]->onRequestProposal(round);
}

void OnDemandConnectionManager::initializeConnections(
    const CurrentPeers &peers) {
  auto create_assign = [this](auto &ptr, auto &peer) {
    ptr = factory_->create(*peer);
  };

  for (auto &&pair : boost::combine(connections_.peers, peers.peers)) {
    create_assign(boost::get<0>(pair), boost::get<1>(pair));
  }
}
