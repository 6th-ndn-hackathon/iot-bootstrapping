#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/security/pib/identity.hpp>
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/util/sha256.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
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
  Controller(const Name& prefix, const std::string& filename);

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

  security::v2::Certificate m_deviceCert;
  security::v2::Certificate m_anchorCert;

  struct DeviceInfo {
    int BKpub; // TODO-1: Edward, this should be loaded from the QR code; zhiyi, please specify the correct formate here
    uint64_t token;
  };
  typedef std::map<Name::Component, struct DeviceInfo> DeviceList;
  typedef DeviceList::iterator DeviceIt;

  DeviceList devices;
};

Controller::Controller(const Name& prefix, const std::string& filename)
  : m_homePrefix(prefix)
{

  try {
    m_identity = m_keyChain.createIdentity(m_homePrefix);
  }
  catch (const std::exception& e) {
    const auto& pib = m_keyChain.getPib();
    m_identity = pib.getIdentity(m_homePrefix);
  }

  std::cout << "before load" << std::endl;

  m_deviceCert = *(io::load<ndn::security::v2::Certificate>(filename));
  std::cout << m_deviceCert.getName() << std::endl;

  m_anchorCert = getDefaultCertificate();// controller's public key
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

  // /ndn/sign-on/{digest of BKpub}/{ECDSA signature by BKpri}

  if (!ndn::security::verifySignature(request, m_deviceCert)) {
    std::cerr << "cannot verify the first Interest's signature, return" << std::endl;
    return;
  }

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

  auto token = random::generateWord64();
  devIt->second.token = token;

  auto content = makeEmptyBlock(tlv::Content);

  auto pubKey = m_deviceCert.getPublicKey();
  auto pubKey2 = m_deviceCert.getPublicKey();
  pubKey.insert(pubKey.end(), pubKey2.begin(), pubKey2.end());

  content.push_back(makeNonNegativeIntegerBlock(129, token));

  ndn::util::Sha256 digest;
  digest.update(pubKey.data(), pubKey.size());
  digest.computeDigest();
  std::cout << "hash = " << digest.toString() << std::endl;

  content.push_back(makeStringBlock(130, digest.toString()));
  std::cout << "token = " << token << std::endl;

  content.push_back(m_anchorCert.wireEncode());
  content.parse();
  std::cout << "content length" << content.value_size() << std::endl;
  std::cout << "content packet length" << content.get(6).value_size() << std::endl;
  std::cout << "content hash length" << content.get(130).value_size() << std::endl;
  std::cout << "content token length" << content.get(129).value_size() << std::endl;

  Data data(Name(name).appendVersion());
  data.setContent(content);
  m_keyChain.sign(data, signingByCertificate(m_anchorCert)); // sign by controller's private key
  m_face.put(data);

  LOG_DATA_OUT(data);
}

void
Controller::onCertificateRequest(const Interest& request)
{
  LOG_INTEREST_IN(request);

  if (!ndn::security::verifySignature(request, m_deviceCert)) {
    std::cerr << "cannot very signon signature, return" << std::endl;
    return;
  }

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
  m_keyChain.sign(newCert, signingByCertificate(m_anchorCert));

  Data data(Name(name).appendVersion());
  data.setContent(newCert.wireEncode());
  m_keyChain.sign(data, signingByCertificate(m_anchorCert)); // sign by controller's private key
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
  std::cout << "test" << std::endl;
  Controller controller("/ucla/eiv396", "/Users/ZhangZhiyi/Develop/iot-bootstrapping/controller/linux/pi-pub.key");
  return controller.run();
}
