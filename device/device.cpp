#include "device.hpp"
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/security/v2/certificate.hpp>
#include <ndn-cxx/encoding/tlv.hpp>
#include <iostream>
using namespace ndn;

int
Device::run()
{
  std::cout << "start the device site!" << std::endl;
  
  expressBootstrappingRequest();

  m_face.processEvents();
  return 0;
}

void
Device::expressBootstrappingRequest()
{
  auto onNack = [] (const Interest& interest, const lp::Nack& nack) {
    std::cout << "received Nack with reason " << nack.getReason() << std::endl;    
  };
  
  auto token = random::generateWord64();
  m_face.expressInterest(makeBootstrappingRequest(token),
			 bind(&Device::onBootstrappingResponse, this, _2, token),
			 onNack,
			 bind(&Device::expressBootstrappingRequest, this));
}

ndn::Interest
Device::makeBootstrappingRequest(const uint64_t& token)
{
  // /ndn/sign-on/Hash(BKpub)/token1/{ECDSA signature by BKpri}
  auto name = Name("/ndn/sign-on");
  name.append(makeBootstrappingKeyDigest())
      .append(name::Component::fromNumber(token));

  auto request = Interest(name, 2_s);
  request.setMustBeFresh(true);
  signRequest(request);

  return request;
}

void
Device::onBootstrappingResponse(const ndn::Data& data, const uint64_t& token)
{
  // data: {controller's public key, token1, token2}
  std::cout << " >> D: " << data << std::endl;

  auto content = data.getContent();
  try {
    content.parse();
  }
  catch (const tlv::Error& e) {
    std::cout << "bootstrapping request, Can not parse the response" << std::endl;
    return;
  }

  // TODO-1: zhiyi, please add decryption here.
  security::v2::Certificate anchorCert(content.get(tlv::Data));
  auto token1 = readNonNegativeInteger(content.get(129));
  auto token2 = readNonNegativeInteger(content.get(130));
  std::cout << anchorCert << std::endl;
  std::cout << "token1 = " << token1 << "; token2 = " << token2 << std::endl;

  if (token1 == token) {
    expressCertificateRequest(anchorCert.getIdentity(), token2);
  }
}

void
Device::expressCertificateRequest(const ndn::Name& prefix, const uint64_t& token)
{
  auto onNack = [] (const Interest& interest, const lp::Nack& nack) {
    std::cout << "received Nack with reason " << nack.getReason() << std::endl;    
  };
  
  m_face.expressInterest(makeCertificateRequest(prefix, token),
			 bind(&Device::onCertificateResponse, this, _2),
			 onNack,
			 bind(&Device::expressCertificateRequest, this, prefix, token));  
}

ndn::Interest
Device::makeCertificateRequest(const Name& prefix, const uint64_t& token)
{
  // /[home-prefix]/cert/Hash(BKpub)/{CKpub}/{signature of token2}/{signature by BKpri}
  auto name = prefix;
  name.append("cert")
      .append(makeBootstrappingKeyDigest())
      .append(makeCommunicationKeyPair())
      .append(makeTokenSignature(token));

  auto request = Interest(name);
  request.setMustBeFresh(true);
  signRequest(request);

  return request;
}

void
Device::onCertificateResponse(const ndn::Data& data)
{
  std::cout << " >> D: " << data << std::endl;
  // TODO-2: zhiyi, please verify the data, the certificate and install the certificate here.
}

void
Device::signRequest(ndn::Interest& request)
{
  // implement different versions in different subclasses
  m_keyChain.sign(request);
}

bool
Device::verifyData(const ndn::Data& data, const Block& certificate)
{
  // implement different versions in different subclasses
  return true;
}
