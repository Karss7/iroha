/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/commands/create_domain.hpp"

using namespace shared_model;

std::string CreateDomain::toString() const {
  return detail::PrettyStringBuilder()
      .init("CreateDomain")
      .append("domain_id", domainId())
      .append("user_default_role", userDefaultRole())
      .finalize();
}

bool CreateDomain::operator==(const ModelType &rhs) const {
  return domainId() == rhs.domainId()
      and userDefaultRole() == rhs.userDefaultRole();
}
