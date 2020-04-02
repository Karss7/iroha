/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <boost/variant.hpp>
#include "builders/protobuf/transaction.hpp"
#include "framework/batch_helper.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "interfaces/iroha_internal/transaction_sequence.hpp"
#include "interfaces/iroha_internal/transaction_sequence_factory.hpp"
#include "interfaces/permissions.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/irohad/multi_sig_transactions/mst_test_helpers.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "module/shared_model/cryptography/make_default_crypto_signer.hpp"

using namespace shared_model;
using namespace common_constants;
using interface::permissions::Role;
using ::testing::ElementsAre;
using ::testing::get;
using ::testing::IsEmpty;
using ::testing::Pointwise;
using ::testing::Truly;
using ::testing::Values;
using ::testing::WithParamInterface;

class BatchPipelineTest
    : public AcceptanceFixture,
      public WithParamInterface<interface::types::BatchType> {
 public:
  /**
   * Create transaction to create first user
   * @return transaction to create first user
   */
  auto createFirstUser() {
    return AcceptanceFixture::createUser(kFirstUser,
                                         kFirstUserSigner->publicKey())
        .build()
        .signAndAddSignature(*kAdminSigner)
        .finish();
  }

  /**
   * Create transaction to add one more signatory and set account quorum equal 2
   */
  auto raiseFirstUserQuorum() {
    return AcceptanceFixture::complete(
        AcceptanceFixture::baseTx(kFirstUserId)
            .addSignatory(kFirstUserId, kFirstUserSecondSigner->publicKey())
            .setAccountQuorum(kFirstUserId, 2),
        *kFirstUserSigner);
  }

  /**
   * @return transaction to create second user
   */
  auto createSecondUser() {
    return AcceptanceFixture::createUser(kSecondUser,
                                         kSecondUserSigner->publicKey())
        .build()
        .signAndAddSignature(*kAdminSigner)
        .finish();
  }

  /**
   * @return transaction to create the role for the two users
   */
  auto createRole() {
    return AcceptanceFixture::baseTx(kAdminId)
        .createRole(kRole,
                    {Role::kReceive,
                     Role::kTransfer,
                     Role::kAddAssetQty,
                     Role::kSubtractAssetQty,
                     Role::kCreateAsset,
                     Role::kAddSignatory,
                     Role::kSetQuorum})
        .build()
        .signAndAddSignature(*kAdminSigner)
        .finish();
  }

  /**
   * @return transaction to add the role to the two users
   */
  auto addRoleToUsers() {
    return AcceptanceFixture::baseTx(kAdminId)
        .appendRole(kFirstUserId, kRole)
        .appendRole(kSecondUserId, kRole)
        .build()
        .signAndAddSignature(*kAdminSigner)
        .finish();
  }

  /**
   * Create transaction to create asset and add its given amount to given user
   * @param account_id account for which amount of asset is added
   * @param asset_name name of the asset to be created and added to the account
   * @param amount amount of the asset to be added to the account
   * @param signer is used to sign transaction
   * @return transaction with create asset and add asset quantity commands
   */
  auto createAndAddAssets(const interface::types::AccountIdType &account_id,
                          const interface::types::AssetNameType &asset_name,
                          const std::string &amount,
                          const crypto::CryptoSigner &signer) {
    return proto::TransactionBuilder()
        .creatorAccountId(account_id)
        .quorum(1)
        .createdTime(iroha::time::now())
        .createAsset(asset_name, kDomain, 2)
        .addAssetQuantity(asset_name + "#" + kDomain, amount)
        .build()
        .signAndAddSignature(signer)
        .finish();
  }

  /**
   * Create builder for transaction to do transfer between given users with
   * given amount of given asset
   * @param src_account_id source accound id
   * @param dest_account_id destination account id
   * @param asset_name name of the asset (without domain) to be transferred
   * @param amount amount of asset to be transferred
   * @param quorum for the transaction
   * @return transaction builder with transfer asset command
   */
  auto prepareTransferAssetBuilder(
      const interface::types::AccountIdType &src_account_id,
      const interface::types::AccountIdType &dest_account_id,
      const interface::types::AssetNameType &asset_name,
      const std::string &amount,
      const interface::types::QuorumType &quorum = 1) {
    return TestTransactionBuilder()
        .creatorAccountId(src_account_id)
        .quorum(quorum)
        .createdTime(iroha::time::now())
        .transferAsset(src_account_id,
                       dest_account_id,
                       asset_name + "#" + kDomain,
                       "",
                       amount);
  }

  /**
   * Take transaction and sign it with provided signature
   * @param tx to be signed
   * @param signer to sign with
   * @return signed transaction
   */
  auto signedTx(std::shared_ptr<interface::Transaction> tx,
                const crypto::CryptoSigner &signer) {
    auto signature_hex = signer.sign(tx->payload());
    auto clone_tx = clone(tx.get());
    clone_tx->addSignature(
        shared_model::interface::types::SignedHexStringView{signature_hex},
        signer.publicKey());
    return std::shared_ptr<interface::Transaction>(std::move(clone_tx));
  }

  auto createTransactionSequence(
      const interface::types::SharedTxsCollectionType &txs) {
    auto transaction_sequence_result =
        interface::TransactionSequenceFactory::createTransactionSequence(
            txs,
            validation::DefaultUnsignedTransactionsValidator(
                iroha::test::kTestsValidatorsConfig),
            validation::FieldValidator(iroha::test::kTestsValidatorsConfig));

    auto transaction_sequence_value =
        framework::expected::val(transaction_sequence_result);
    EXPECT_TRUE(transaction_sequence_value)
        << framework::expected::err(transaction_sequence_result).value().error;

    return transaction_sequence_value.value().value;
  }

  auto batchToSequence(
      const std::shared_ptr<interface::TransactionBatch> &batch) {
    return interface::TransactionSequence(
        std::vector<std::shared_ptr<shared_model::interface::TransactionBatch>>{
            batch});
  };

  integration_framework::IntegrationTestFramework &prepareState(
      integration_framework::IntegrationTestFramework &itf,
      const std::string &amount1,
      const std::string &amount2) {
    return itf.setInitialState(kAdminSigner)
        .sendTxAwait(createFirstUser(), CHECK_TXS_QUANTITY(1))
        .sendTxAwait(createSecondUser(), CHECK_TXS_QUANTITY(1))
        .sendTxAwait(createRole(), CHECK_TXS_QUANTITY(1))
        .sendTxAwait(addRoleToUsers(), CHECK_TXS_QUANTITY(1))
        .sendTxAwait(createAndAddAssets(
                         kFirstUserId, kAssetA, amount1, *kFirstUserSigner),
                     CHECK_TXS_QUANTITY(1))
        .sendTxAwait(createAndAddAssets(
                         kSecondUserId, kAssetB, amount2, *kSecondUserSigner),
                     CHECK_TXS_QUANTITY(1));
  }

 protected:
  const std::string kAdmin = "admin";
  const std::string kFirstUser = "first";
  const std::string kSecondUser = "second";

  const std::string kFirstUserId = kFirstUser + "@" + kDomain;
  const std::string kSecondUserId = kSecondUser + "@" + kDomain;

  const std::shared_ptr<crypto::CryptoSigner> kFirstUserSigner =
      shared_model::crypto::makeDefaultSigner();
  const std::shared_ptr<crypto::CryptoSigner> kFirstUserSecondSigner =
      shared_model::crypto::makeDefaultSigner();
  const std::shared_ptr<crypto::CryptoSigner> kSecondUserSigner =
      shared_model::crypto::makeDefaultSigner();

  const std::string kAssetA = "usd";
  const std::string kAssetB = "euro";
};

/**
 * Matchers to compare references against pointers
 */

MATCHER(RefAndPointerEq, "") {
  return get<0>(arg) == *get<1>(arg);
}

MATCHER_P(RefAndPointerEq, arg1, "") {
  return arg == *arg1;
}

/**
 * @given any type of batch (ordered or atomic) with two transactions
 * @when transactions are sent to iroha
 * @then both transactions are committed
 */
TEST_P(BatchPipelineTest, ValidBatch) {
  auto batch_transactions = framework::batch::makeTestBatchTransactions(
      GetParam(),
      prepareTransferAssetBuilder(kFirstUserId, kSecondUserId, kAssetA, "1.0"),
      prepareTransferAssetBuilder(kSecondUserId, kFirstUserId, kAssetB, "1.0"));

  SCOPED_TRACE("From valid batch test");
  auto transaction_sequence = createTransactionSequence(
      {signedTx(batch_transactions[0], *kFirstUserSigner),
       signedTx(batch_transactions[1], *kSecondUserSigner)});
  integration_framework::IntegrationTestFramework itf(2);
  prepareState(itf, "1.0", "1.0")
      .sendTxSequenceAwait(
          transaction_sequence, [&transaction_sequence](const auto &block) {
            // check that transactions from block are the same as transactions
            // from transaction sequence
            ASSERT_THAT(block->transactions(),
                        Pointwise(RefAndPointerEq(),
                                  transaction_sequence.transactions()));
          });
}

/**
 * @given atomic batch of two transactions, with one transaction being stateful
 * invalid
 * @when batch is sent to iroha
 * @then no transaction is committed
 */
TEST_F(BatchPipelineTest, InvalidAtomicBatch) {
  auto batch_transactions = framework::batch::makeTestBatchTransactions(
      interface::types::BatchType::ATOMIC,
      prepareTransferAssetBuilder(kFirstUserId, kSecondUserId, kAssetA, "1.0"),
      prepareTransferAssetBuilder(kSecondUserId,
                                  kFirstUserId,
                                  kAssetB,
                                  "2.0")  // invalid tx due to too big transfer
  );

  SCOPED_TRACE("From invalid atomic batch test");
  auto transaction_sequence = createTransactionSequence(
      {signedTx(batch_transactions[0], *kFirstUserSigner),
       signedTx(batch_transactions[1], *kSecondUserSigner)});

  integration_framework::IntegrationTestFramework itf(2);
  prepareState(itf, "1.0", "1.0")
      .sendTxSequence(
          transaction_sequence,
          [](const auto &statuses) {
            for (const auto &status : statuses) {
              EXPECT_NO_THROW(
                  boost::get<const shared_model::interface::
                                 StatelessValidTxResponse &>(status.get()));
            }
          })
      .checkStatus(batch_transactions[0]->hash(), CHECK_STATELESS_VALID)
      .checkStatus(batch_transactions[0]->hash(), CHECK_ENOUGH_SIGNATURES)
      .checkStatus(batch_transactions[1]->hash(), CHECK_STATELESS_VALID)
      .checkStatus(batch_transactions[1]->hash(), CHECK_ENOUGH_SIGNATURES)
      .checkStatus(batch_transactions[1]->hash(), CHECK_STATEFUL_INVALID)
      .checkProposal([&transaction_sequence](const auto proposal) {
        ASSERT_THAT(
            proposal->transactions(),
            Pointwise(RefAndPointerEq(), transaction_sequence.transactions()));
      })
      .checkVerifiedProposal([](const auto verified_proposal) {
        ASSERT_THAT(verified_proposal->transactions(), IsEmpty());
      })
      .checkBlock([](const auto block) {
        ASSERT_THAT(block->transactions(), IsEmpty());
      });
}

/**
 * @given ordered batch of three transactions, with one transaction being
 * stateful invalid
 * @when batch is sent to iroha
 * @then all transactions except stateful invalid one are committed
 */
TEST_F(BatchPipelineTest, InvalidOrderedBatch) {
  auto batch_transactions = framework::batch::makeTestBatchTransactions(
      interface::types::BatchType::ORDERED,
      prepareTransferAssetBuilder(kFirstUserId, kSecondUserId, kAssetA, "0.3"),
      prepareTransferAssetBuilder(
          kSecondUserId,
          kFirstUserId,
          kAssetB,
          "2.0"),  // stateful invalid tx due to too big transfer
      prepareTransferAssetBuilder(kFirstUserId, kSecondUserId, kAssetA, "0.7"));

  SCOPED_TRACE("From InvalidOrderedBatch");
  auto transaction_sequence = createTransactionSequence(
      {signedTx(batch_transactions[0], *kFirstUserSigner),
       signedTx(batch_transactions[1], *kSecondUserSigner),
       signedTx(batch_transactions[2], *kFirstUserSigner)});

  integration_framework::IntegrationTestFramework itf(3);
  prepareState(itf, "1.0", "1.0")
      .sendTxSequenceAwait(transaction_sequence, [&](const auto block) {
        ASSERT_THAT(
            block->transactions(),
            ElementsAre(
                RefAndPointerEq(transaction_sequence.transactions()[0]),
                RefAndPointerEq(transaction_sequence.transactions()[2])));
      });
}

INSTANTIATE_TEST_SUITE_P(BatchPipelineParameterizedTest,
                         BatchPipelineTest,
                         // note additional comma is needed to make it compile
                         // https://github.com/google/googletest/issues/1419
                         Values(interface::types::BatchType::ATOMIC,
                                interface::types::BatchType::ORDERED));

/**
 * Test that a batch would not be passed to stateful validation when one
 * transaction is fully signed and another is not signed at all.
 * @given
 *   two users - the first user has quorum two
 *   an atomic batch with two transactions
 *   the first transaction is signed with only one valid signature
 *   the second transaciton is not signed
 *   the batch is sent to Iroha and in a pending state
 * @when
 *   the first transaction acquires the second valid signature
 *   and the batch is sent again to Iroha
 * @then
 *   the batch is sill in a pending state
 *   because the second transaction has no signatures
 */
TEST_F(BatchPipelineTest, SemisignedAtomicBatch) {
  auto batch = framework::batch::makeTestBatch(
      prepareTransferAssetBuilder(
          kFirstUserId, kSecondUserId, kAssetA, "1.0", 2),
      prepareTransferAssetBuilder(kSecondUserId, kFirstUserId, kAssetB, "1.0"));

  batch = addSignaturesFromKeyPairs(batch, 0, *kFirstUserSigner);
  auto firstTxHash = batch->transactions()[0]->hash();

  integration_framework::IntegrationTestFramework itf(2);
  prepareState(itf, "10.0", "20.0")
      .sendTxAwait(raiseFirstUserQuorum(), CHECK_TXS_QUANTITY(1))
      .sendTxSequence(batchToSequence(batch))
      .checkStatus(firstTxHash, CHECK_STATELESS_VALID)
      .checkStatus(firstTxHash, CHECK_MST_PENDING);

  batch = addSignaturesFromKeyPairs(batch, 0, *kFirstUserSecondSigner);
  itf.sendTxSequence(batchToSequence(batch))
      .checkStatus(firstTxHash, CHECK_STATELESS_VALID)
      .checkStatus(firstTxHash, CHECK_MST_PENDING);
}

/**
 * Test that the batch goes to the stateful validation only when all the
 * signatures are collected. Signatures are added sequentially by one.
 * @given
 *   two users - the first user has quorum two
 *   an atomic batch with two transactions
 *   the first transaction is signed with only one valid signature
 *   the second transaciton is not signed
 *   the batch is sent to Iroha and in a pending state
 * @when
 *   signatures are added sequentially
 * @then
 *   batch remains pending till all signatures are collected
 */
TEST_F(BatchPipelineTest, CommitAtomicBatchStepByStepSigning) {
  auto batch = framework::batch::makeTestBatch(
      prepareTransferAssetBuilder(
          kFirstUserId, kSecondUserId, kAssetA, "1.0", 2),
      prepareTransferAssetBuilder(kSecondUserId, kFirstUserId, kAssetB, "1.0"));

  auto batch1 = addSignaturesFromKeyPairs(batch, 0, *kFirstUserSigner);
  auto firstTxHash = batch->transactions()[0]->hash();

  integration_framework::IntegrationTestFramework itf(2);
  prepareState(itf, "10.0", "20.0")
      .sendTxAwait(raiseFirstUserQuorum(), CHECK_TXS_QUANTITY(1))
      .sendTxSequence(batchToSequence(batch1))
      .checkStatus(firstTxHash, CHECK_STATELESS_VALID)
      .checkStatus(firstTxHash, CHECK_MST_PENDING);

  auto batch2 = addSignaturesFromKeyPairs(batch, 0, *kFirstUserSecondSigner);
  itf.sendTxSequence(batchToSequence(batch2))
      .checkStatus(firstTxHash, CHECK_STATELESS_VALID)
      .checkStatus(firstTxHash, CHECK_MST_PENDING);

  auto batch3 = addSignaturesFromKeyPairs(batch, 1, *kSecondUserSigner);
  itf.sendTxSequence(batchToSequence(batch3))
      .checkStatus(firstTxHash, CHECK_STATELESS_VALID)
      .checkStatus(firstTxHash, CHECK_ENOUGH_SIGNATURES)
      .checkStatus(firstTxHash, CHECK_STATEFUL_VALID)
      .checkStatus(firstTxHash, CHECK_COMMITTED);
}
