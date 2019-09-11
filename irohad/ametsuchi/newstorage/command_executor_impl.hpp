/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMAND_EXECUTOR_IMPL_HPP
#define IROHA_COMMAND_EXECUTOR_IMPL_HPP

#include "ametsuchi/command_executor.hpp"

namespace shared_model {
  namespace interface {
    class AddAssetQuantity;
    class AddPeer;
    class AddSignatory;
    class AppendRole;
    class CompareAndSetAccountDetail;
    class CreateAccount;
    class CreateAsset;
    class CreateDomain;
    class CreateRole;
    class DetachRole;
    class GrantPermission;
    class PermissionToString;
    class RemovePeer;
    class RemoveSignatory;
    class RevokePermission;
    class SetAccountDetail;
    class SetQuorum;
    class SubtractAssetQuantity;
    class TransferAsset;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace newstorage {

    class CommandExecutorImpl final : public CommandExecutor {
     public:
      CommandExecutorImpl(
          std::unique_ptr<soci::session> sql,
          std::shared_ptr<shared_model::interface::PermissionToString>
              perm_converter);

      ~CommandExecutorImpl();

      CommandResult execute(const shared_model::interface::Command &cmd,
                            const shared_model::interface::types::AccountIdType
                                &creator_account_id,
                            bool do_validation) override;

      soci::session &getSession();

      CommandResult operator()(
          const shared_model::interface::AddAssetQuantity &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::AddPeer &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::AddSignatory &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::AppendRole &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::CompareAndSetAccountDetail &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::CreateAccount &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::CreateAsset &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::CreateDomain &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::CreateRole &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::DetachRole &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::GrantPermission &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::RemovePeer &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::RemoveSignatory &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::RevokePermission &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::SetAccountDetail &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::SetQuorum &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::SubtractAssetQuantity &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::TransferAsset &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          bool do_validation);

     private:
      class CommandStatements;
      class StatementExecutor;

      void initStatements();

      std::unique_ptr<CommandStatements> makeCommandStatements(
          const std::unique_ptr<soci::session> &session,
          const std::string &base_statement,
          const std::vector<std::string> &permission_checks);

      std::unique_ptr<soci::session> sql_;

      std::shared_ptr<shared_model::interface::PermissionToString>
          perm_converter_;

      std::unique_ptr<CommandStatements> add_asset_quantity_statements_;
      std::unique_ptr<CommandStatements> add_peer_statements_;
      std::unique_ptr<CommandStatements> add_signatory_statements_;
      std::unique_ptr<CommandStatements> append_role_statements_;
      std::unique_ptr<CommandStatements>
          compare_and_set_account_detail_statements_;
      std::unique_ptr<CommandStatements> create_account_statements_;
      std::unique_ptr<CommandStatements> create_asset_statements_;
      std::unique_ptr<CommandStatements> create_domain_statements_;
      std::unique_ptr<CommandStatements> create_role_statements_;
      std::unique_ptr<CommandStatements> detach_role_statements_;
      std::unique_ptr<CommandStatements> grant_permission_statements_;
      std::unique_ptr<CommandStatements> remove_peer_statements_;
      std::unique_ptr<CommandStatements> remove_signatory_statements_;
      std::unique_ptr<CommandStatements> revoke_permission_statements_;
      std::unique_ptr<CommandStatements> set_account_detail_statements_;
      std::unique_ptr<CommandStatements> set_quorum_statements_;
      std::unique_ptr<CommandStatements> subtract_asset_quantity_statements_;
      std::unique_ptr<CommandStatements> transfer_asset_statements_;
    };
  }  // namespace newstorage
}  // namespace iroha

#endif  // IROHA_COMMAND_EXECUTOR_IMPL_HPP