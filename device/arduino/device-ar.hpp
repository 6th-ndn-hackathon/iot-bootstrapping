#include "../device.hpp"

class DeviceAr : public Device
{
public:
  DeviceAr(const ndn::Name& BKName = "iot-ar");

public:
  virtual void
  importBootstrappingKey(const char* path);

  virtual ndn::name::Component
  makeBootstrappingKeyDigest();

  virtual ndn::name::Component
  makeCommunicationKeyPair();

  virtual ndn::name::Component
  makeTokenSignature(const uint64_t& token);

private:
  ndn::Name m_bkName;
};
