#include <device.hpp>

class DevicePi : public Device
{
public:
  DevicePi(const ndn::Name& BKName = "iot-pi");

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
