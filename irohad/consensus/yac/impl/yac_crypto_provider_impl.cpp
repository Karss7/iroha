/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/impl/yac_crypto_provider_impl.hpp"

#include "backend/plain/signature.hpp"
#include "common/result.hpp"
#include "consensus/yac/transport/yac_pb_converters.hpp"
#include "cryptography/crypto_provider/crypto_signer.hpp"
#include "cryptography/crypto_provider/crypto_verifier.hpp"
#include "logger/logger.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {
      CryptoProviderImpl::CryptoProviderImpl(
          const shared_model::crypto::Keypair &keypair, logger::LoggerPtr log)
          : keypair_(keypair), log_(std::move(log)) {}

      bool CryptoProviderImpl::verify(const std::vector<VoteMessage> &msg) {
        return std::all_of(
            std::begin(msg), std::end(msg), [this](const auto &vote) {
              auto serialized =
                  PbConverters::serializeVote(vote).hash().SerializeAsString();
              auto blob = shared_model::crypto::Blob(serialized);

              using namespace shared_model::interface::types;
              return shared_model::crypto::CryptoVerifier::verify(
                         makeStrongView<SignedHexStringView>(
                             vote.signature->signedData()),
                         blob,
                         makeStrongView<PublicKeyHexStringView>(
                             vote.signature->publicKey()))
                  .match([](const auto &) { return true; },
                         [this](const auto &error) {
                           log_->debug("Vote signature verification failed: {}",
                                       error.error);
                           return false;
                         });
            });
      }

      VoteMessage CryptoProviderImpl::getVote(YacHash hash) {
        VoteMessage vote;
        vote.hash = hash;
        auto serialized =
            PbConverters::serializeVotePayload(vote).hash().SerializeAsString();
        auto blob = shared_model::crypto::Blob(serialized);
        const auto &pubkey = keypair_.publicKey();
        const auto &privkey = keypair_.privateKey();
        auto signature = shared_model::crypto::CryptoSigner<>::sign(
            blob, shared_model::crypto::Keypair(pubkey, privkey));

        // TODO 30.08.2018 andrei: IR-1670 Remove optional from YAC
        // CryptoProviderImpl::getVote
        using namespace shared_model::interface::types;
        vote.signature = std::make_shared<shared_model::plain::Signature>(
            makeStrongView<SignedHexStringView>(signature), pubkey);

        return vote;
      }

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
