/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string>

#include <benchmark/benchmark.h>
#include <boost/variant.hpp>
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "backend/protobuf/transaction.hpp"
#include "benchmark/bm_utils.hpp"
#include "module/shared_model/builders/protobuf/test_query_builder.hpp"
#include "utils/query_error_response_visitor.hpp"

using namespace benchmark::utils;
using namespace common_constants;

/**
 * This benchmark executes get account query in order to measure query execution
 * performance
 */
static void BM_QueryAccount(benchmark::State &state) {
  integration_framework::IntegrationTestFramework itf(1);
  itf.setInitialState(kAdminSigner);
  itf.sendTx(createUserWithPerms(
                 kUser,
                 kUserSigner->publicKey(),
                 kRole,
                 {shared_model::interface::permissions::Role::kGetAllAccounts})
                 .build()
                 .signAndAddSignature(*kAdminSigner)
                 .finish());

  itf.skipBlock().skipProposal();

  auto make_query = []() {
    return TestUnsignedQueryBuilder()
        .createdTime(iroha::time::now())
        .creatorAccountId(kUserId)
        .queryCounter(1)
        .getAccount(kUserId)
        .build()
        .signAndAddSignature(*kUserSigner)
        .finish();
  };

  auto check = [](auto &status) {
    boost::get<const shared_model::interface::AccountResponse &>(status.get());
  };

  itf.sendQuery(make_query(), check);

  while (state.KeepRunning()) {
    itf.sendQuery(make_query());
  }
  itf.done();
}
BENCHMARK(BM_QueryAccount)->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN();
