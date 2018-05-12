#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/security/pib/identity.hpp>
#include <map>
#include <iostream>
#include <logger.hpp>
using namespace ndn;

namespace std
{
  template<> struct less<Name::Component>
    {
      bool operator() (const Name::Component& lhs, const Name::Component& rhs) const
       {
	 return lhs.compare(rhs) < 0;
       }
    };
}

class Controller
{
public:
  Controller(const Name& prefix);

public:
  int run();
  void onRegisterFailure(const Name& prefix, const std::string& reason);
  void onBootstrappingRequest(const Interest& request);
  void onCertificateRequest(const Interest& request);

protected:
  security::v2::Certificate getDefaultCertificate();

private:
  Name m_homePrefix;
  Face m_face;
  KeyChain m_keyChain;
  security::Identity m_identity;

  struct DeviceInfo {
    int BKpub; // TODO-1: Edward, this should be loaded from the QR code; zhiyi, please specify the correct formate here
    uint64_t token;
  };
  typedef std::map<Name::Component, struct DeviceInfo> DeviceList;
  typedef DeviceList::iterator DeviceIt;

  DeviceList devices;
};

Controller::Controller(const Name& prefix)
  : m_homePrefix(prefix)
  , m_identity(m_keyChain.createIdentity(m_homePrefix))
{
}

void
Controller::onRegisterFailure(const Name& prefix, const std::string& reason)
{
  std::cout << "fail to register " << prefix << " due to: " << reason << std::endl;
}

security::v2::Certificate
Controller::getDefaultCertificate()
{
  return m_identity.getDefaultKey().getDefaultCertificate();
}

void
Controller::onBootstrappingRequest(const Interest& request)
{
  LOG_INTEREST_IN(request);

  // TODO-2: zhiyi, please verify the signature here

  // /ndn/sign-on/{digest of BKpub}/{ECDSA signature by BKpri}

  auto name = request.getName();
  auto BKpubHash = name.at(2);

  // TODO-0: currently, we do not have the QR code scanned yet
  DeviceInfo devInfo;
  devices.insert(DeviceList::value_type(BKpubHash, devInfo));

  DeviceIt devIt = devices.find(BKpubHash);
  if (devIt == devices.end()) {
    std::cout << "hasn't scanned the QR code yet" << std::endl;
    return;
  }

  auto BKpub = devIt->second.BKpub;
  // TODO-3: zhiyi, please verify the hash of BKpub here

  auto anchorCert = getDefaultCertificate();// controller's public key
  auto token = random::generateWord64();
  devIt->second.token = token;

  // TODO-4: zhiyi, please encrypt controller's public key, token1, token2 by BKpub, and then add the encryption to the data content
  auto content = makeEmptyBlock(tlv::Content);
  content.push_back(anchorCert.wireEncode());
  content.push_back(makeNonNegativeIntegerBlock(129, token));
  std::cout << "token = " << token << std::endl;

  Data data(Name(name).appendVersion());
  data.setContent(content);
  m_keyChain.sign(data); // sign by controller's private key
  m_face.put(data);

  LOG_DATA_OUT(data);
}

void
Controller::onCertificateRequest(const Interest& request)
{
  LOG_INTEREST_IN(request);

  // /[home-prefix]/cert/{digest of BKpub}/{CKpub}/{signature of token}/{signature by BKpri}
  auto name = request.getName();
  auto signatureOfToken = name.at(-3);
  auto CKpub = name.at(-4);
  auto BKpubHash = name.at(-5);

  DeviceIt devIt = devices.find(BKpubHash);
  if (devIt == devices.end()) {
    std::cout << "can not recognize the device" << std::endl;
    return;
  }

  auto token = devIt->second.token;
  // TODO-5: zhiyi, please verify the signature of token2 here

  Name deviceName(m_homePrefix);
  deviceName.append(BKpubHash);

  security::v2::Certificate certRequest(CKpub);
  security::v2::Certificate newCert;

  newCert.setName(certRequest.getKeyName().append("NDNCERT-IOT").appendVersion());
  newCert.setContent(certRequest.getContent());
  SignatureInfo signatureInfo;
  security::ValidityPeriod period(time::system_clock::now(),
                                  time::system_clock::now() + time::days(10));
  signatureInfo.setValidityPeriod(period);
  security::SigningInfo signingInfo(security::SigningInfo::SIGNER_TYPE_ID,
                                    m_homePrefix, signatureInfo);
  m_keyChain.sign(newCert);

  Data data(Name(name).appendVersion());
  data.setContent(newCert.wireEncode());
  m_keyChain.sign(data); // sign by controller's private key
  m_face.put(data);

  LOG_DATA_OUT(data);
}

int
Controller::run()
{
  auto bootstrapPrefix = Name("/ndn/sign-on");
  auto certPrefix = Name(m_homePrefix).append("cert");

  m_face.setInterestFilter(bootstrapPrefix,
			   bind(&Controller::onBootstrappingRequest, this, _2),
			   bind(&Controller::onRegisterFailure, this, _1, _2));

  m_face.setInterestFilter(certPrefix,
			   bind(&Controller::onCertificateRequest, this, _2),
			   bind(&Controller::onRegisterFailure, this, _1, _2));

  m_face.processEvents();
  return 0;
}

int main(int argc, char** argv)
{
  Controller controller("/ucla/eiv396");
  return controller.run();
}
