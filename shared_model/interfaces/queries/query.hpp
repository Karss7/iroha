/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_QUERY_HPP
#define IROHA_SHARED_MODEL_QUERY_HPP

#include <boost/variant/variant_fwd.hpp>

#include "interfaces/base/signable.hpp"
#include "interfaces/common_objects/types.hpp"

namespace iroha {
  namespace protocol {
    class Query;
  }
}  // namespace iroha

namespace shared_model {

  class GetAccount;
  class GetBlock;
  class GetSignatories;
  class GetAccountTransactions;
  class GetAccountAssetTransactions;
  class GetTransactions;
  class GetAccountAssets;
  class GetAccountDetail;
  class GetRoles;
  class GetRolePermissions;
  class GetAssetInfo;
  class GetPendingTransactions;
  class GetPeers;

  /**
   * Class Query provides container with one of concrete query available in
   * system.
   * General note: this class is container for queries but not a base class.
   */
  class Query : public Signable<Query> {
   private:
    /// Shortcut type for const reference
    template <typename... Value>
    using wrap = boost::variant<const Value &...>;

   public:
    using TransportType = iroha::protocol::Query;

    Query(const Query &o);
    Query(Query &&o) noexcept;

    explicit Query(const TransportType &ref);
    explicit Query(TransportType &&ref);

    /// Type of variant, that handle concrete query
    using QueryVariantType = wrap<GetAccount,
                                  GetSignatories,
                                  GetAccountTransactions,
                                  GetAccountAssetTransactions,
                                  GetTransactions,
                                  GetAccountAssets,
                                  GetAccountDetail,
                                  GetRoles,
                                  GetRolePermissions,
                                  GetAssetInfo,
                                  GetPendingTransactions,
                                  GetBlock,
                                  GetPeers>;

    /**
     * @return reference to const variant with concrete command
     */
    const QueryVariantType &get() const;

    /**
     * @return id of query creator
     */
    const types::AccountIdType &creatorAccountId() const;

    /**
     * Query counter - incremental variable reflect for number of sent to
     * system queries plus 1. Required for preventing replay attacks.
     * @return attached query counter
     */
    types::CounterType queryCounter() const;

    // ------------------------| Primitive override |-------------------------

    std::string toString() const override;

    bool operator==(const ModelType &rhs) const override;

   private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
  };
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_QUERY_HPP
