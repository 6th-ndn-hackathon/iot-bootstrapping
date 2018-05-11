#include "device-pi.hpp"
#include <iostream>
using namespace ndn;

DevicePi::DevicePi(const Name& BKName)
  : m_bkName(BKName)
{
  std::cout << "Pi is being constructed" << std::endl;
}

void
DevicePi::importBootstrappingKey(const char* path)
{
  // TODO: zhiyi
}

name::Component
DevicePi::makeBootstrappingKeyDigest()
{
  // TODO: zhiyi
  return m_bkName.at(0);
}

name::Component
DevicePi::makeCommunicationKeyPair()
{
  // TODO: zhiyi
  return name::Component("CKpub");
}

name::Component
DevicePi::makeTokenSignature(const uint64_t& token)
{
  // TODO: zhiyi
  return name::Component("CKpri(token)");
}


