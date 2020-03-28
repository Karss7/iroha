/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "util/proto_status_tools.hpp"

#include <boost/assign.hpp>
#include <boost/bimap/bimap.hpp>
#include <boost/bimap/set_of.hpp>
#include "common/bind.hpp"
#include "util/status.hpp"

using iroha::operator|;

namespace iroha {
  namespace utility_service {

    using ProtoStatusBimap =
        boost::bimaps::bimap<boost::bimaps::set_of<Status>,
                             boost::bimaps::set_of<proto::Status::StatusEnum>>;

    static const ProtoStatusBimap &getProtoStatusBimap() {
      // clang-format off
      static const ProtoStatusBimap map =
          boost::assign::list_of<ProtoStatusBimap::relation>
            (Status::kUnknown,        proto::Status_StatusEnum_unknown)
            (Status::kInitialization, proto::Status_StatusEnum_initialization)
            (Status::kRunning,        proto::Status_StatusEnum_running)
            (Status::kTermination,    proto::Status_StatusEnum_termination)
            (Status::kStopped,        proto::Status_StatusEnum_stopped)
            (Status::kFailed,         proto::Status_StatusEnum_failed);
      // clang-format on
      return map;
    }

    boost::optional<std::unique_ptr<proto::Status>> makeProtoStatus(
        Status status) {
      auto status_it = getProtoStatusBimap().left.find(status);
      if (status_it == getProtoStatusBimap().left.end()) {
        assert(status_it != getProtoStatusBimap().left.end());
        return boost::none;
      }
      auto proto_status = std::make_unique<proto::Status>();
      proto_status->set_status(status_it->second);
      return proto_status;
    }

    boost::optional<Status> makeStatus(const proto::Status &status) {
      auto status_it = getProtoStatusBimap().right.find(status.status());
      if (status_it == getProtoStatusBimap().right.end()) {
        assert(status_it != getProtoStatusBimap().right.end());
        return boost::none;
      }
      return status_it->second;
    }

  }  // namespace utility_service
}  // namespace iroha

IROHA_DEFINE_PROTO_ENUM_TO_STRING(
    ::iroha::utility_service::proto::Status::StatusEnum);
IROHA_DEFINE_IFACE_ENUM_TO_PROTO_STRING(
    ::iroha::utility_service::Status,
    ::iroha::utility_service::getProtoStatusBimap().left);
