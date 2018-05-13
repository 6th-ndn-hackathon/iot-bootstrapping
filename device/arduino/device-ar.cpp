#include "device-ar.hpp"
#include <ndn-cpp/util/blob-lite.hpp>
#include <ndn-cpp/data.hpp>
#include <ndn-cpp/lite/util/crypto-lite.hpp>
#include <ndn-cpp/security/safe-bag.hpp>

#include <iostream>
using namespace ndn;

DeviceAr::DeviceAr(const NameLite& BKName)
  : m_bkName(BKName)
{
  std::cout << "Ar is being constructed" << std::endl;
}

void
DeviceAr::importBootstrappingKey(const char* path)
{
  // TODO: zhiyi, edward
  
}

NameLite::Component
DeviceAr::makeBootstrappingKeyDigest()
{
  // TODO: zhiyi, edward
  const Bloblite& publicKeyBits = m_cert.getPublicKey(); 
  ndn::CryptoLite digest;
  digest.digestSha256(publicKeyBits.data(), *(publicKeyBits.size()));
  std::string digestStr = digest.toString();
  NameLite tmpName(digestStr.substr(0, 25));
  return m_bkName.at(0);
}

NameLite::Component
DeviceAr::makeCommunicationKeyPair()
{
  // TODO: zhiyi, edward
  return NameLite::Component("CKpub");
}

NameLite::Component
DeviceAr::makeTokenSignature(const uint64_t& token)
{
  // TODO: zhiyi, edward
  return name::Component("CKpri(token)");
}
