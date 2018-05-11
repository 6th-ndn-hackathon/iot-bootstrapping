#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/security/pib/identity.hpp>
#include <map>
#include <iostream>
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
    uint64_t token2;
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
  std::cout << " << I: " << request << std::endl;

  // TODO-2: zhiyi, please verify the signature here
  
  // /ndn/sign-on/Hash(BKpub)/token1/{ECDSA signature by BKpri}
  auto name = request.getName();
  auto BKpubHash = name.at(2);
  auto token1 = name.at(3).toNumber();

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
  auto token2 = random::generateWord64();
  devIt->second.token2 = token2;

  // TODO-4: zhiyi, please encrypt controller's public key, token1, token2 by BKpub, and then add the encryption to the data content
  auto content = makeEmptyBlock(tlv::Content);
  content.push_back(anchorCert.wireEncode());
  content.push_back(makeNonNegativeIntegerBlock(129, token1));
  content.push_back(makeNonNegativeIntegerBlock(130, token2));
  std::cout << "token1 = " << token1 << "; token2 = " << token2 << std::endl;

  Data data(Name(name).appendVersion());
  data.setContent(content);
  m_keyChain.sign(data); // sign by controller's private key
  m_face.put(data);
}

void
Controller::onCertificateRequest(const Interest& request)
{
  std::cout << " << I: " << request << std::endl;

  // /[home-prefix]/cert/Hash(BKpub)/{CKpub}/{signature of token2}/{signature by BKpri}
  auto name = request.getName();
  auto signatureOfToken2 = name.at(-3);
  auto CKpub = name.at(-4);
  auto BKpubHash = name.at(-5);

  DeviceIt devIt = devices.find(BKpubHash);
  if (devIt == devices.end()) {
    std::cout << "can not recognize the device" << std::endl;
    return;
  }

  auto token2 = devIt->second.token2;
  // TODO-5: zhiyi, please verify the signature of token2 here

  Name deviceName(m_homePrefix);
  deviceName.append(BKpubHash);

  // TODO-6: zhiyi, please generate the device certificate here
  security::v2::Certificate newCert;

  Data data(Name(name).appendVersion());
  auto content = makeEmptyBlock(tlv::Content);
  data.setContent(content);
  m_keyChain.sign(data); // sign by controller's private key
  m_face.put(data);
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
