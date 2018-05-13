#include <device.hpp>
#include <ndn-cxx/security/transform/private-key.hpp>
#include <ndn-cxx/security/transform/public-key.hpp>

class DevicePi : public Device
{
public:
  DevicePi(const char* BKfile, const ndn::Name& BKName = "iot-pi");

public:
  virtual void
  importBootstrappingKey(const char* path);

  virtual ndn::name::Component
  makeBootstrappingKeyDigest();

  virtual ndn::name::Component
  makeCommunicationKeyPair(const ndn::Name& prefix);

  virtual ndn::name::Component
  makeTokenSignature(const uint64_t& token);

  virtual bool
  verifyHash(const std::string& hash);

  virtual void
  signRequest(ndn::Interest& request);

  virtual void
  startServices();

public:
  void
  onRegisterFailure(const ndn::Name& prefix, const std::string& reason)
  {
    std::cout << "fail to register " << prefix << " due to: " << reason << std::endl;
  }
  
  void
  startLEDService();

  void
  onLEDCommand(const ndn::Interest& command);

  void
  startCertificateService();

  void
  onCertificateRequest(const ndn::Interest& request);

private:
  ndn::Name m_bkName;
  ndn::security::v2::Certificate m_bootstrappingCert;
  ndn::security::transform::PrivateKey m_prv;
  ndn::security::transform::PublicKey m_pub;
};
