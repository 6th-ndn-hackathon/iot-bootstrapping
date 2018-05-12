#include "device.hpp"
#include <logger.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/security/v2/certificate.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/encoding/tlv.hpp>
#include <iostream>
using namespace ndn;

int
Device::run()
{
  LOG_INFO("device site starts");

  expressBootstrappingRequest();

  m_face.processEvents();
  return 0;
}

void
Device::expressBootstrappingRequest()
{
  auto onNack = [] (const Interest& interest, const lp::Nack& nack) {
    LOG_FAILURE("received Nack with reason ", nack.getReason());
  };

  auto request = makeBootstrappingRequest();
  m_face.expressInterest(request,
			 bind(&Device::onBootstrappingResponse, this, _2),
			 onNack,
			 bind(&Device::expressBootstrappingRequest, this));

  LOG_INTEREST_OUT(request);
}

ndn::Interest
Device::makeBootstrappingRequest()
{
  // /ndn/sign-on/{digest of BKpub}/{ECDSA signature by BKpri}
  auto name = Name("/ndn/sign-on").append(makeBootstrappingKeyDigest());

  std::cerr << "first interest name: " << name << std::endl;;

  auto request = Interest(name, 2_s);
  request.setMustBeFresh(true);
  signRequest(request);

  return request;
}

void
Device::onBootstrappingResponse(const ndn::Data& data)
{
  // data: {controller's public key, token}
  LOG_DATA_IN(data);

  auto content = data.getContent();
  try {
    content.parse();
  }
  catch (const tlv::Error& e) {
    LOG_FAILURE("sign-on", "bootstrapping request, Can not parse the response");
    return;
  }

  m_anchor = security::v2::Certificate(content.get(tlv::Data));
  auto token = readNonNegativeInteger(content.get(129));
  auto hash = readString(content.get(130));

  if (!verifyHash(hash)) {
    std::cout << "can not verify the hash value of the sign-on response" << std::endl;
    return;
  }

  std::cout << "token = " << token << std::endl;
  std::cout << "hash = " << hash << std::endl;

  if (verifyData(data, m_anchor)) {
    expressCertificateRequest(m_anchor.getIdentity(), token);
  }
  else {
    LOG_FAILURE("sign-on", "can not verify the signature of the sign-on response");
  }
}

void
Device::expressCertificateRequest(const ndn::Name& prefix, const uint64_t& token)
{
  auto onNack = [] (const Interest& interest, const lp::Nack& nack) {
    LOG_FAILURE("certificate", "received Nack with reason " << nack.getReason());
  };

  auto request = makeCertificateRequest(prefix, token);
  m_face.expressInterest(request,
                         bind(&Device::onCertificateResponse, this, _2),
                         onNack,
                         bind(&Device::expressCertificateRequest, this, prefix, token));

  LOG_INTEREST_OUT(request);
}

ndn::Interest
Device::makeCertificateRequest(const Name& prefix, const uint64_t& token)
{
  // /[home-prefix]/cert/{digest of BKpub}/{CKpub}/{signature of token}/{signature by BKpri}
  auto name = prefix;
  name.append("cert")
      .append(makeBootstrappingKeyDigest())
      .append(makeCommunicationKeyPair(prefix))
      .append(makeTokenSignature(token));

  auto request = Interest(name);
  request.setMustBeFresh(true);
  signRequest(request);

  return request;
}

void
Device::onCertificateResponse(const ndn::Data& data)
{
  LOG_DATA_IN(data);

  verifyData(data, m_anchor);

  // verify signature
  if (verifyData(data, m_anchor)) {
    // install cert
    ndn::security::v2::Certificate cert(data.getContent().blockFromValue());
    auto& pib = m_keyChain.getPib();
    ndn::security::Identity id = pib.getIdentity(cert.getIdentity());
    ndn::security::Key key = id.getKey(cert.getKeyName());
    m_keyChain.addCertificate(key, cert);
  }
  else {
    std::cout << "can not verify the signature of the cert-request response" << std::endl;
  }
}

void
Device::signRequest(ndn::Interest& request)
{
  // implement different versions in different subclasses
  m_keyChain.sign(request);
}

bool
Device::verifyData(const ndn::Data& data, const security::v2::Certificate& certificate)
{
  return ndn::security::verifySignature(data, certificate);
}

bool
Device::verifyHash(const std::string& hash) {
  return true;
}
