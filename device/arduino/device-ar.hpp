#include "../device.hpp"
#include <ndn-cpp/lite/name-lite.hpp>
#include <ndn-cpp/lite/data-lite.hpp>
#include <ndn-cpp/security/v2/certificate-v2.hpp>

class DeviceAr : public Device
{
public:
  DeviceAr(const ndn::NameLite& BKName = "iot-ar");

public:
  virtual void
  importBootstrappingKey(const char* path);

  virtual ndn::NameLite::Component
  makeBootstrappingKeyDigest();

  virtual ndn::NameLite::Component
  makeCommunicationKeyPair();

  virtual ndn::NameLite::Component
  makeTokenSignature(const uint64_t& token);

private:
  ndn::NameLite m_bkName;
  ndn::CertificateV2 m_cert; // This certificate is not under lite.
};
