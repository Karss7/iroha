#include "cryptography/gost3410_impl/internal/gost_impl.hpp"

#include <botan/auto_rng.h>
#include <botan/gost_3410.h>
#include <botan/pubkey.h>
#include <botan/pkcs8.h>
#include <botan/x509_key.h>
#include <botan/rng.h>
#include <botan/data_src.h>
<<<<<<< HEAD
=======

using shared_model::interface::types::PublicKeyByteRangeView;
using shared_model::interface::types::SignatureByteRangeView;
>>>>>>> base64 encoding removed

static const auto ECGName = std::string("gost_256A");
static const auto EMSA = std::string("EMSA1(SHA-512)");

namespace iroha {

  bool verify(const uint8_t *msg,
              size_t msgsize,
              const uint8_t* pub_key,
              size_t pub_key_size,
              const uint8_t* signature,
              size_t signature_size) {

    auto ds = Botan::DataSource_Memory(pub_key, pub_key_size);
    auto key = Botan::X509::load_key(ds);

    Botan::PK_Verifier verifier(*key, EMSA);
    verifier.update(msg, msgsize);
<<<<<<< HEAD

    auto res = verifier.check_signature(
      signature, signature_size
=======
    auto sigt = std::string(reinterpret_cast<const char*>(signature.t.data()), signature.t.size());
    
    auto res = verifier.check_signature(
      reinterpret_cast<const uint8_t*>(sig.data()), sig.size()
>>>>>>> base64 encoding removed
      );
    delete key;
    return res;
  }

  bool verify(std::string_view msg,
              const std::vector<uint8_t>& public_key,
              const std::vector<uint8_t>& signature) {
    return verify(reinterpret_cast<const uint8_t *>(msg.data()),
                  msg.size(),
                  public_key.data(), public_key.size(),
                  signature.data(), signature.size()
                  );
  }

  std::pair<std::string, std::vector<uint8_t>> create_keypair() {
    Botan::AutoSeeded_RNG rng;
    auto key = Botan::GOST_3410_PrivateKey(rng, Botan::EC_Group(ECGName));

    auto pvkey = Botan::PKCS8::BER_encode(key);
    auto pbkey = Botan::X509::PEM_encode(key);

    auto pair = std::make_pair(std::move(pbkey), std::vector<uint8_t>(pvkey.begin(), pvkey.end()));
    
    return pair;
  }
  
  std::vector<uint8_t> sign(const uint8_t *msg,
                  size_t msgsize,
                  const uint8_t* priv, size_t privLen){
<<<<<<< HEAD
=======
    
    auto ds = Botan::DataSource_Memory(priv, privLen);
    auto key = Botan::PKCS8::load_key(ds);

    Botan::AutoSeeded_RNG rng;
    Botan::PK_Signer signer(*key.get(), rng, EMSA);
    signer.update(msg, msgsize);
    std::vector<uint8_t> signature = signer.signature(rng);
    
    //assert(signature.size() == iroha::sig_t::size());
    //std::copy_n(sig.begin(), signature.size(), signature.begin());
    return signature;
  }

  std::string sign(const std::string& msg, const uint8_t* priv, size_t privLen){
    auto sig = sign(reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                      priv, privLen);
    return std::string(reinterpret_cast<const char*>(sig.data()), sig.size());
    //return Botan::base64_encode(sig.data(), sig.size());
  }
}

// class keypair{
// public:
//     std::vector<uint8_t> pubKey;
//     std::vector<uint8_t> privKey;
// };
 
// keypair makeKeypair(){
//     AutoSeeded_RNG rng;
//     auto key = GOST_3410_PrivateKey(rng, EC_Group(ECGName));

//     // auto aig = AlgorithmIdentifier(ECGName);
//     // std:: cout << 

//     std::cout << "Key length: " << key.key_length() << std::endl;

//     auto prvbits = PKCS8::BER_encode(key); //key.private_key_bits();
//     auto pbkbits = X509::BER_encode(key);//key.public_key_bits();

//     std::cout << "pvkSize: " << prvbits.size() << std::endl;
//     std::cout << "pbkSize: " << pbkbits.size() << std::endl;

//     keypair kpair;

//     kpair.privKey = std::vector<uint8_t>(prvbits.begin(), prvbits.end());
//     kpair.pubKey = std::vector<uint8_t>(pbkbits.begin(), pbkbits.end());

//     std::cout << "kpair.priv size: " << kpair.privKey.size() << std::endl;
//     std::cout << "kpair.pub size: " << kpair.pubKey.size() << std::endl;

//     return kpair;
// }

// // template<size_t size_>
// // class blob_t : public std::array<uint8_t, size_> {

// // };


// std::vector<uint8_t> sign(const uint8_t *msg,
//             size_t msgsize,
//             const pubkey_t &pub,
//             const privkey_t &priv) {
>>>>>>> base64 encoding removed
    
    auto ds = Botan::DataSource_Memory(priv, privLen);
    auto key = Botan::PKCS8::load_key(ds);

    Botan::AutoSeeded_RNG rng;
    Botan::PK_Signer signer(*key.get(), rng, EMSA);
    signer.update(msg, msgsize);
    std::vector<uint8_t> signature = signer.signature(rng);
    
    return signature;
  }

  std::string sign(const std::string& msg, const uint8_t* priv, size_t privLen){
    auto sig = sign(reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                      priv, privLen);
    return std::string(reinterpret_cast<const char*>(sig.data()), sig.size());
  }
}
