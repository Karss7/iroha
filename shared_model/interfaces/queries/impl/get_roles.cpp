/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/get_roles.hpp"

using namespace shared_model;

std::string GetRoles::toString() const {
  return detail::PrettyStringBuilder().init("GetRoles").finalize();
}

bool GetRoles::operator==(const ModelType &rhs) const {
  return true;
}
