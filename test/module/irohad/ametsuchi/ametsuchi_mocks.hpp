/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_MOCKS_HPP
#define IROHA_AMETSUCHI_MOCKS_HPP

#include <gmock/gmock.h>
#include <boost/optional.hpp>
#include "ametsuchi/temporary_wsv.hpp"
#include "ametsuchi/wsv_command.hpp"
#include "common/result.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "module/irohad/ametsuchi/mock_block_query.hpp"
#include "module/irohad/ametsuchi/mock_block_query_factory.hpp"
#include "module/irohad/ametsuchi/mock_mutable_factory.hpp"
#include "module/irohad/ametsuchi/mock_mutable_storage.hpp"
#include "module/irohad/ametsuchi/mock_peer_query.hpp"
#include "module/irohad/ametsuchi/mock_peer_query_factory.hpp"
#include "module/irohad/ametsuchi/mock_query_executor.hpp"
#include "module/irohad/ametsuchi/mock_storage.hpp"
#include "module/irohad/ametsuchi/mock_temporary_factory.hpp"
#include "module/irohad/ametsuchi/mock_tx_presence_cache.hpp"
#include "module/irohad/ametsuchi/mock_wsv_query.hpp"

namespace iroha {
  namespace ametsuchi {

    class MockWsvCommand : public WsvCommand {
     public:
      MOCK_METHOD1(insertRole, WsvCommandResult(const std::string &role_name));
      MOCK_METHOD2(insertAccountRole,
                   WsvCommandResult(const std::string &account_id,
                                    const std::string &role_name));
      MOCK_METHOD2(deleteAccountRole,
                   WsvCommandResult(const std::string &account_id,
                                    const std::string &role_name));
      MOCK_METHOD2(
          insertRolePermissions,
          WsvCommandResult(const std::string &role_id,
                           const shared_model::RolePermissionSet &permissions));

      MOCK_METHOD3(
          insertAccountGrantablePermission,
          WsvCommandResult(const std::string &permittee_account_id,
                           const std::string &account_id,
                           shared_model::permissions::Grantable permission));

      MOCK_METHOD3(
          deleteAccountGrantablePermission,
          WsvCommandResult(const std::string &permittee_account_id,
                           const std::string &account_id,
                           shared_model::permissions::Grantable permission));
      MOCK_METHOD1(insertAccount,
                   WsvCommandResult(const shared_model::Account &));
      MOCK_METHOD1(updateAccount,
                   WsvCommandResult(const shared_model::Account &));
      MOCK_METHOD1(insertAsset, WsvCommandResult(const shared_model::Asset &));
      MOCK_METHOD1(upsertAccountAsset,
                   WsvCommandResult(const shared_model::AccountAsset &));
      MOCK_METHOD1(insertSignatory,
                   WsvCommandResult(const shared_model::types::PubkeyType &));
      MOCK_METHOD1(deleteSignatory,
                   WsvCommandResult(const shared_model::types::PubkeyType &));

      MOCK_METHOD2(insertAccountSignatory,
                   WsvCommandResult(const std::string &,
                                    const shared_model::types::PubkeyType &));

      MOCK_METHOD2(deleteAccountSignatory,
                   WsvCommandResult(const std::string &,
                                    const shared_model::types::PubkeyType &));

      MOCK_METHOD1(insertPeer, WsvCommandResult(const shared_model::Peer &));

      MOCK_METHOD1(deletePeer, WsvCommandResult(const shared_model::Peer &));

      MOCK_METHOD1(insertDomain,
                   WsvCommandResult(const shared_model::Domain &));
      MOCK_METHOD4(setAccountKV,
                   WsvCommandResult(const std::string &,
                                    const std::string &,
                                    const std::string &,
                                    const std::string &));
    };

    class MockTemporaryWsv : public TemporaryWsv {
     public:
      MOCK_METHOD1(apply,
                   expected::Result<void, validation::CommandError>(
                       const shared_model::Transaction &));
      MOCK_METHOD1(
          createSavepoint,
          std::unique_ptr<TemporaryWsv::SavepointWrapper>(const std::string &));
    };

    class MockTemporaryWsvSavepointWrapper
        : public TemporaryWsv::SavepointWrapper {
      MOCK_METHOD0(release, void(void));
    };

    namespace tx_cache_status_responses {
      std::ostream &operator<<(std::ostream &os, const Committed &resp) {
        return os << resp.hash.toString();
      }
      std::ostream &operator<<(std::ostream &os, const Rejected &resp) {
        return os << resp.hash.toString();
      }
      std::ostream &operator<<(std::ostream &os, const Missing &resp) {
        return os << resp.hash.toString();
      }
    }  // namespace tx_cache_status_responses

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_AMETSUCHI_MOCKS_HPP
