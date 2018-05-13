#include "device.hpp"
#include <iostream>
#include <boost/ref.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

void
onData(const ndn::Interest& interest, const ndn::Data& data, ndn::Face& face)
{
  std::cout << "Interest: " << interest.toUri() << std::endl;
  std::cout << "Data: " << data.getName().toUri() << std::endl;
}

void
onTimeout(const ndn::Interest& interest,
          ndn::Face& face)
{
  std::cout << "Timeout" << std::endl;
}


int main(int argc, char** argv)
{
  try {
    ndn::Interest i(ndn::Name("/ucla/eiv396/control/1"));
    i.setMustBeFresh(true);

    ndn::KeyChain keyChain;
    ndn::Name cert("/ucla/eiv396/6C05A21A2940029D372883C39BFFF0046BE38D7571319356A310D03F04C2E20B");
    keyChain.sign(i, signingByCertificate(cert));

    ndn::Face face;
    face.expressInterest(i,
                         bind(onData,  _1, _2, boost::ref(face)),
                         nullptr,
                         bind(onTimeout,  _1, boost::ref(face)));

    // processEvents will block until the requested data received or timeout occurs
    face.processEvents();
  }
  catch(std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
  return 0;
}