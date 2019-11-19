/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/get_transactions.hpp"

#include "cryptography/hash.hpp"
#include "utils/string_builder.hpp"

using namespace shared_model;

std::string GetTransactions::toString() const {
  return detail::PrettyStringBuilder()
      .init("GetTransactions")
      .appendAll(transactionHashes(),
                 [](const auto &s) { return s.toString(); })
      .finalize();
}

bool GetTransactions::operator==(const ModelType &rhs) const {
  return transactionHashes() == rhs.transactionHashes();
}
