#include "device.hpp"
#include <logger.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/security/v2/certificate.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/encoding/tlv.hpp>
#include <iostream>
using namespace ndn;

int
Device::run(bool needStartService)
{
  LOG_INFO("device starts");

  m_needStartService = needStartService;
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
  std::cout << data << std::endl;
  try {
    content.parse();
  }
  catch (const tlv::Error& e) {
    LOG_FAILURE("sign-on", "bootstrapping request, Can not parse the response " << e.what());
    return;
  }

  auto token = readNonNegativeInteger(content.get(129));
  auto hash = readString(content.get(130));

  if (!verifyHash(hash)) {
    std::cout << "can not verify the hash value of the sign-on response" << std::endl;
    return;
  }

  std::cout << "token = " << token << std::endl;
  std::cout << "hash = " << hash << std::endl;

  m_anchor = security::v2::Certificate(content.get(tlv::Data));

  if (ndn::security::verifySignature(data, m_anchor)) {
    expressCertificateRequest(m_anchor.getIdentity(), token);
  }
  else {
    LOG_FAILURE("sign-on:", "can not verify the signature of the sign-on response");
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

  // verify signature
  if (ndn::security::verifySignature(data, m_anchor)) {
    // install cert
    ndn::security::v2::Certificate cert(data.getContent().blockFromValue());
    auto& pib = m_keyChain.getPib();
    ndn::security::Identity id = pib.getIdentity(cert.getIdentity());
    ndn::security::Key key = id.getKey(cert.getKeyName());
    m_keyChain.addCertificate(key, cert);
    m_deviceCert = cert;
    
    if (m_needStartService) {
      startServices();
    }
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

void
Device::verify(const ndn::Interest& interest,
	       const afterVerificationCallback& cbAfterVerification,
	       const failVerificationCallback& cbFailVerification)
{
  Name klName;
  if (!getKeyLocatorName(interest, klName)) {
    cbFailVerification(klName.toUri());
    return;
  }

  if (klName.equals(m_anchor.getName())) {
    if (ndn::security::verifySignature(interest, m_anchor)) {
      cbAfterVerification();
    }
    else {
      cbFailVerification("can not be verified by the trust anchor");
    }
    return;
  }

  auto certRequest = Interest(klName);
  certRequest.setMustBeFresh(true);
  LOG_INTEREST_OUT(certRequest);
  
  m_face.expressInterest(certRequest,
			 bind(&Device::onCertificate, this,
			      _2, interest, cbAfterVerification, cbFailVerification),
			 bind(cbFailVerification, "NACK: can not get certificate"),
			 bind(cbFailVerification, "TIMEOUT: can not get certificate"));
}

void
Device::verify(const ndn::Data& data,
	       const afterVerificationCallback& cbAfterVerification,
	       const failVerificationCallback& cbFailVerification)
{
  Name klName;
  if (!getKeyLocatorName(data, klName)) {
    cbFailVerification(klName.toUri());
    return;
  }

  std::cout << "klName: " << klName << "\n"
	    << "anchor: " << m_anchor.getKeyName() << std::endl;
  
  if (klName.equals(m_anchor.getKeyName())) {
    if (ndn::security::verifySignature(data, m_anchor)) {
      cbAfterVerification();
    }
    else {
      cbFailVerification("can not be verified by the trust anchor");
    }
    return;
  }

  

  // TODO: fetch this data's cert for further verification; do not need for hackathon
}

void
Device::onCertificate(const ndn::Data& certificate,  const ndn::Interest& interest,
		      const afterVerificationCallback& cbAfterVerification,
		      const failVerificationCallback& cbFailVerification)
{
  security::v2::Certificate cert(certificate);
  if (ndn::security::verifySignature(interest, cert)) {
    verify(certificate, cbAfterVerification, cbFailVerification);
  }
  else {
    cbFailVerification("can not verify signature");
  }
}

bool
Device::getKeyLocatorName(const SignatureInfo& si, Name& name)
{
  if (!si.hasKeyLocator()) {
    name = Name("missing key locator");
    return false;
  }

  const KeyLocator& kl = si.getKeyLocator();
  if (kl.getType() != KeyLocator::KeyLocator_Name) {
    name = Name("not a name");
    return false;
  }

  name = kl.getName();
  return true;
}

bool
Device::getKeyLocatorName(const Data& data, Name& name)
{
  return getKeyLocatorName(data.getSignature().getSignatureInfo(), name);
}

bool
Device::getKeyLocatorName(const Interest& interest, Name& name)
{
  Name interestName = interest.getName();
  if (interestName.size() < signed_interest::MIN_SIZE) {
    name = Name("interest name is too short");
    return false;
  }

  SignatureInfo si;
  try {
    si.wireDecode(interestName.at(signed_interest::POS_SIG_INFO).blockFromValue());
  }
  catch (const tlv::Error& e) {
    name = Name(e.what());
    return false;
  }

  return getKeyLocatorName(si, name);
}
