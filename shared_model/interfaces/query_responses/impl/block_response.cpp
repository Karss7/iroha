/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/block_response.hpp"

#include "interfaces/block.hpp"
#include "utils/string_builder.hpp"

using namespace shared_model;

std::string BlockResponse::toString() const {
  return detail::PrettyStringBuilder()
      .init("BlockResponse")
      .append(block().toString())
      .finalize();
}

bool BlockResponse::operator==(const ModelType &rhs) const {
  return block() == rhs.block();
}
