#include "device-ar.hpp"
#include <iostream>
using namespace ndn;

DeviceAr::DeviceAr(const Name& BKName)
  : m_bkName(BKName)
{
  std::cout << "Ar is being constructed" << std::endl;
}

void
DeviceAr::importBootstrappingKey(const char* path)
{
  // TODO: zhiyi, edward
}

name::Component
DeviceAr::makeBootstrappingKeyDigest()
{
  // TODO: zhiyi, edward
  return m_bkName.at(0);
}

name::Component
DeviceAr::makeCommunicationKeyPair()
{
  // TODO: zhiyi, edward
  return name::Component("CKpub");
}

name::Component
DeviceAr::makeTokenSignature(const uint64_t& token)
{
  // TODO: zhiyi, edward
  return name::Component("CKpri(token)");
}


