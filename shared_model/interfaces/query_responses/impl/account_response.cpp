/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/account_response.hpp"
#include "utils/string_builder.hpp"

using namespace shared_model;

std::string AccountResponse::toString() const {
  return detail::PrettyStringBuilder()
      .init("AccountResponse")
      .append(account().toString())
      .append("roles")
      .appendAll(roles(), [](auto s) { return s; })
      .finalize();
}

bool AccountResponse::operator==(const ModelType &rhs) const {
  return account() == rhs.account() and roles() == rhs.roles();
}
