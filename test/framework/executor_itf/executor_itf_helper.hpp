/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_FRAMEWORK_EXECUTOR_ITF_HELPER_HPP
#define IROHA_TEST_FRAMEWORK_EXECUTOR_ITF_HELPER_HPP

#include <memory>

#include <boost/mpl/at.hpp>
#include <boost/mpl/contains.hpp>
#include <boost/mpl/map.hpp>
#include "common/result.hpp"
#include "interfaces/commands/command.hpp"
#include "interfaces/queries/query.hpp"

#include "interfaces/query_responses/account_asset_response.hpp"
#include "interfaces/query_responses/account_detail_response.hpp"
#include "interfaces/query_responses/account_response.hpp"
#include "interfaces/query_responses/asset_response.hpp"
#include "interfaces/query_responses/block_error_response.hpp"
#include "interfaces/query_responses/block_query_response.hpp"
#include "interfaces/query_responses/block_response.hpp"
#include "interfaces/query_responses/error_query_response.hpp"
#include "interfaces/query_responses/pending_transactions_page_response.hpp"
#include "interfaces/query_responses/query_response.hpp"
#include "interfaces/query_responses/role_permissions_response.hpp"
#include "interfaces/query_responses/roles_response.hpp"
#include "interfaces/query_responses/signatories_response.hpp"
#include "interfaces/query_responses/transactions_page_response.hpp"
#include "interfaces/query_responses/transactions_response.hpp"

namespace iroha {
  namespace integration_framework {
    namespace detail {

      /**
       * A type map from specific query to the corresponding response.
       *
       * Is used only to get a default expected response type for some query.
       * The queries may also return different responses, and if you expect a
       * different response type, you should either use the interface of
       * conversion functions to specify it, or extract it from the response
       * variant manually.
       */
      typedef boost::mpl::map<
          boost::mpl::pair<shared_model::GetAccount,
                           shared_model::AccountResponse>,
          boost::mpl::pair<shared_model::GetSignatories,
                           shared_model::SignatoriesResponse>,
          boost::mpl::pair<shared_model::GetAccountTransactions,
                           shared_model::TransactionsResponse>,
          boost::mpl::pair<shared_model::GetAccountAssetTransactions,
                           shared_model::TransactionsResponse>,
          boost::mpl::pair<shared_model::GetTransactions,
                           shared_model::TransactionsResponse>,
          boost::mpl::pair<shared_model::GetAccountAssets,
                           shared_model::AccountAssetResponse>,
          boost::mpl::pair<shared_model::GetAccountDetail,
                           shared_model::AccountDetailResponse>,
          boost::mpl::pair<shared_model::GetRoles, shared_model::RolesResponse>,
          boost::mpl::pair<shared_model::GetRolePermissions,
                           shared_model::RolePermissionsResponse>,
          boost::mpl::pair<shared_model::GetAssetInfo,
                           shared_model::AssetResponse>,
          boost::mpl::pair<shared_model::GetPendingTransactions,
                           shared_model::PendingTransactionsPageResponse>,
          boost::mpl::pair<shared_model::GetBlock, shared_model::BlockResponse>>
          SpecificQueryResponses;

      /// true for specific commands
      template <typename T>
      constexpr bool isSpecificCommand =
          boost::mpl::contains<shared_model::Command::CommandVariantType::types,
                               const std::decay_t<T> &>::type::value;

      /// true for specific queries
      template <typename T>
      constexpr bool isSpecificQuery =
          boost::mpl::contains<shared_model::Query::QueryVariantType::types,
                               const std::decay_t<T> &>::type::value;

      template <typename T>
      std::enable_if_t<isSpecificQuery<T>, const T &> getInterfaceQueryRef(
          const T &query) {
        return query;
      }

      template <typename T, typename SpecificQuery = typename T::ModelType>
      std::enable_if_t<isSpecificQuery<SpecificQuery>, const SpecificQuery &>
      getInterfaceQueryRef(const T &query) {
        return static_cast<const SpecificQuery &>(query);
      }

      template <typename T>
      using InterfaceQuery = decltype(getInterfaceQueryRef(std::declval<T>()));

      /// response for specific query
      template <typename SpecificQuery,
                typename = std::enable_if_t<isSpecificQuery<SpecificQuery>>>
      using GetSpecificQueryResponse =
          typename boost::mpl::at<SpecificQueryResponses,
                                  std::decay_t<SpecificQuery>>::type;

      /**
       * Try to extract the given specific response from a general query
       * response.
       * @tparam SpecificQueryResponse The specific response type to extract.
       * @param query_result The general query response.
       * @return The specific response if the general one has it, the general
       * response if not.
       */
      template <typename SpecificQueryResponse>
      iroha::expected::Result<const SpecificQueryResponse &,
                              iroha::ametsuchi::QueryExecutorResult &>
      convertToSpecificQueryResponse(
          iroha::ametsuchi::QueryExecutorResult &query_result) {
        if (auto specific_query_response =
                boost::strict_get<const SpecificQueryResponse &>(
                    &query_result->get())) {
          return iroha::expected::makeValue<const SpecificQueryResponse &>(
              *specific_query_response);
        }
        return iroha::expected::makeError<
            iroha::ametsuchi::QueryExecutorResult &>(query_result);
      }
    }  // namespace detail
  }    // namespace integration_framework
}  // namespace iroha

#endif  // IROHA_TEST_FRAMEWORK_EXECUTOR_ITF_HELPER_HPP
