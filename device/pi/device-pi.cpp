#include "device-pi.hpp"
#include <logger.hpp>
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/util/sha256.hpp>
#include <ndn-cxx/security/transform/signer-filter.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include <ndn-cxx/encoding/block-helpers.hpp>
#include <iostream>
#include <stdlib.h>
using namespace ndn;

DevicePi::DevicePi(const char* BKfile, const std::string& host)
{
  LOG_WELCOME("device", host);
  importBootstrappingKey(BKfile);
  m_host = Name::Component(host);
}

DevicePi::DevicePi()
{
  LOG_INFO("A Test PI Is Being Constructed");
  m_anchor = m_keyChain.getPib()
    .getIdentity(Name("/iot")).getDefaultKey().getDefaultCertificate();
  m_deviceCert = m_keyChain.getPib()
    .getIdentity(Name("/iot/pi")).getDefaultKey().getDefaultCertificate();

  startServices();
  m_face.processEvents();
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
  m_bootstrappingCert = ndn::security::v2::Certificate(std::move(certData));
  Name identity =  m_bootstrappingCert.getIdentity();
  Name keyName =  m_bootstrappingCert.getKeyName();

  std::cout << "key name from safebag: " << keyName << std::endl;
  // load public key
  const Buffer publicKeyBits = m_bootstrappingCert.getPublicKey();
  m_pub.loadPkcs8(publicKeyBits.data(), publicKeyBits.size());

  // load private key
  m_prv.loadPkcs8(safeBag->getEncryptedKeyBag().data(), safeBag->getEncryptedKeyBag().size(),
                  importPassword.c_str(), importPassword.size());

  // add safebag to the keychain
  try {
    m_keyChain.importSafeBag(*safeBag, importPassword.c_str(), importPassword.size());
  }
  catch (const std::exception& e) {
    return;
  }
}

name::Component
DevicePi::makeBootstrappingKeyDigest()
{
  const Buffer publicKeyBits = m_bootstrappingCert.getPublicKey();
  ndn::util::Sha256 digest;
  digest.update(publicKeyBits.data(), publicKeyBits.size());
  digest.computeDigest();
  Name tmpName(digest.toString());
  return tmpName.at(0);
}

name::Component
DevicePi::makeCommunicationKeyPair(const Name& prefix)
{
  EcKeyParams params;
  Name identityName = prefix;
  //identityName.append(makeBootstrappingKeyDigest());
  identityName.append(m_host);
  auto identity = m_keyChain.createIdentity(identityName, params);
  auto cert = identity.getDefaultKey().getDefaultCertificate();
  return name::Component(8, cert.wireEncode().getBuffer());
}

name::Component
DevicePi::makeTokenSignature(const uint64_t& token)
{
  using namespace ndn::security::transform;

  OBufferStream sigOs;
  bufferSource(std::to_string(token)) >> signerFilter(DigestAlgorithm::SHA256, m_prv) >> streamSink(sigOs);
  Block sigValue(tlv::SignatureValue, sigOs.buf());

  return name::Component(8, sigValue.getBuffer());
}

bool
DevicePi::verifyHash(const std::string& hash)
{
  auto pubKey = m_bootstrappingCert.getPublicKey();
  auto pubKey2 = m_bootstrappingCert.getPublicKey();
  pubKey.insert(pubKey.end(), pubKey2.begin(), pubKey2.end());
  ndn::util::Sha256 digest;
  digest.update(pubKey.data(), pubKey.size());
  digest.computeDigest();
  if (hash == digest.toString())
    return true;

  return false;
}


void
DevicePi::signRequest(ndn::Interest& request)
{
  m_keyChain.sign(request, signingByCertificate(m_bootstrappingCert));
}

void
DevicePi::startServices()
{
  LOG_INFO("start services on the device");
  startLEDService();
  startCertificateService();
}

void
DevicePi::startLEDService()
{
  // /[home_prefix]/led
  Name serviceName = Name(m_anchor.getIdentity()).append("led");
  m_face.setInterestFilter(serviceName,
                           bind(&DevicePi::onLEDCommand, this, _2),
                           bind(&DevicePi::onRegisterFailure, this, _1, _2));
}

void
DevicePi::startCertificateService()
{
  m_face.setInterestFilter(m_deviceCert.getName(),
                           bind(&DevicePi::onCertificateRequest, this, _2),
                           bind(&DevicePi::onRegisterFailure, this, _1, _2));
}

void
DevicePi::onLEDCommand(const Interest& command)
{
  LOG_INTEREST_IN(command);

  afterVerificationCallback cbAfterVerification = [this, command] {
    system("python pi/control.py");
    makeCommandResponse(command, "OK");
  };
  
  verify(command, cbAfterVerification,
	 bind(&DevicePi::makeCommandResponse, this, command, _1));
}

void
DevicePi::onCertificateRequest(const ndn::Interest& request)
{
  LOG_INTEREST_IN(request);
  m_face.put(m_deviceCert);
}

void
DevicePi::makeCommandResponse(const Interest& command, const std::string& reason)
{
  Data data(Name(command.getName()).appendVersion());
  data.setContent(makeStringBlock(tlv::Content, reason));
  m_keyChain.sign(data);
  m_face.put(data);
}
