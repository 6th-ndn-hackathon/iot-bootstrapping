#include "device-pi.hpp"
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/util/sha256.hpp>
#include <ndn-cxx/security/transform/signer-filter.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include <iostream>

using namespace ndn;

DevicePi::DevicePi(const Name& BKName)
  : m_bkName(BKName)
{
  std::cout << "Pi is being constructed" << std::endl;
}

void
DevicePi::importBootstrappingKey(const char* path)
{
  std::string importPassword = "1234";
  shared_ptr<security::SafeBag> safeBag;
  try {
    safeBag = io::load<security::SafeBag>(path);
  }
  catch (const std::runtime_error& e) {
    std::cerr << "ERROR: cannot import safe bag " << e.what() << std::endl;
  }

  Data certData = safeBag->getCertificate();
  m_cert = ndn::security::v2::Certificate(std::move(certData));
  Name identity = m_cert.getIdentity();
  Name keyName = m_cert.getKeyName();

  // load public key
  const Buffer publicKeyBits = m_cert.getPublicKey();
  m_pub.loadPkcs8(publicKeyBits.data(), publicKeyBits.size());

  // load private key
  m_prv.loadPkcs8(safeBag->getEncryptedKeyBag().data(), safeBag->getEncryptedKeyBag().size(),
                  importPassword.c_str(), importPassword.size());
}

name::Component
DevicePi::makeBootstrappingKeyDigest()
{
  const Buffer publicKeyBits = m_cert.getPublicKey();
  ndn::util::Sha256 digest;
  digest.update(publicKeyBits.data(), publicKeyBits.size());
  digest.computeDigest();
  std::string digestStr = digest.toString();
  Name tmpName(digestStr.substr(0, 25));
  return tmpName.at(0);
}

name::Component
DevicePi::makeCommunicationKeyPair()
{
  // TODO: zhiyi
  return name::Component("CKpub");
}

name::Component
DevicePi::makeTokenSignature(const uint64_t& token)
{
  using namespace ndn::security::transform;

  OBufferStream sigOs;
  bufferSource(std::to_string(token)) >> signerFilter(DigestAlgorithm::SHA256, m_prv) >> streamSink(sigOs);
  Block sigValue(tlv::SignatureValue, sigOs.buf());

  return name::Component(sigValue);
}
