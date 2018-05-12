#include "device.hpp"
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/security/v2/certificate.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
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

  m_face.expressInterest(makeBootstrappingRequest(),
                         bind(&Device::onBootstrappingResponse, this, _2),
                         onNack,
                         bind(&Device::expressBootstrappingRequest, this));
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
  m_anchor = security::v2::Certificate(content.get(tlv::Data));
  auto token = readNonNegativeInteger(content.get(129));
  std::cout << m_anchor << std::endl;
  std::cout << "token = " << token << std::endl;

  if (verifyData(data, m_anchor)) {
    expressCertificateRequest(m_anchor.getIdentity(), token);
  }
  else {
    std::cout << "can not verify the signature of the sign-on response" << std::endl;
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
  std::cout << " >> D: " << data << std::endl;
  // TODO-2: zhiyi, please verify the data, the certificate and install the certificate here.

  verifyData(data, m_anchor);

  ndn::security::v2::Certificate cert(data.getContent().blockFromValue());
  auto& pib = m_keyChain.getPib();
  ndn::security::Identity id = pib.getIdentity(cert.getIdentity());
  ndn::security::Key key = id.getKey(cert.getKeyName());
  m_keyChain.addCertificate(key, cert);
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
