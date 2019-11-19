/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PEERS_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PEERS_RESPONSE_HPP

#include "interfaces/base/model_primitive.hpp"

#include "interfaces/common_objects/peer.hpp"
#include "qry_responses.pb.h"

#include <boost/range/any_range.hpp>
#include "interfaces/common_objects/types.hpp"

namespace shared_model {

  using PeersForwardCollectionType =
      boost::any_range<Peer, boost::forward_traversal_tag, const Peer &>;

  /**
   * Provide response with peers in the network
   */
  class PeersResponse : public ModelPrimitive<PeersResponse> {
   public:
    explicit PeersResponse(iroha::protocol::QueryResponse &query_response);

    /**
     * @return a list of peers
     */
    PeersForwardCollectionType peers() const;

    std::string toString() const override;

    bool operator==(const ModelType &rhs) const override;

   private:
    const iroha::protocol::PeersResponse &peers_response_;

    std::vector<Peer> peers_;
  };
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_PEERS_RESPONSE_HPP
