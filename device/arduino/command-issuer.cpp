#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <logger.hpp>
using namespace ndn;

class CommandIssuer
{
public:
  CommandIssuer();

  void issueCommand(const Name& commandName);
  void sendCertificate(const security::v2::Certificate& certificate);
  
private:
  Face m_face;
  KeyChain m_keyChain;
  security::v2::Certificate m_defaultCert;
};

CommandIssuer::CommandIssuer()
{
  m_defaultCert = m_keyChain.getPib().getDefaultIdentity().getDefaultKey().getDefaultCertificate();
  m_face.setInterestFilter(m_defaultCert.getKeyName(),
			   bind(&CommandIssuer::sendCertificate, this, m_defaultCert),
			   [] (const Name& prefix, const std::string& reason) {
			     std::cout << "fail to register " << prefix << std::endl;
			   });
}

void
CommandIssuer::sendCertificate(const security::v2::Certificate& certificate)
{
  m_face.put(certificate);
}

void
CommandIssuer::issueCommand(const Name& commandName)
{
  Interest command(commandName);
  command.setMustBeFresh(true);
  // use the default certificate to sign
  m_keyChain.sign(command, signingByCertificate(m_defaultCert)); 
  m_face.expressInterest(command,
			 [] (const Interest& interest, const Data& data) {
			   LOG_DATA_IN(data);
			   std::cout << readString(data.getContent()) << std::endl;
			 },
			 [] (const Interest& interest, const lp::Nack& nack) {
			   LOG_FAILURE("received Nack with reason ", nack.getReason());
			 },
			 [] (const Interest& interest) {
			   LOG_FAILURE("interest timeout: ", interest.getName());
			 });

  m_face.processEvents();
}


int main(int argc, char** argv)
{
  if (argc < 2) {
    LOG_FAILURE("too less arguments", "please specify the command prefix");
    return 0;
  }

  CommandIssuer issuer;
  issuer.issueCommand(argv[1]);
  
  return 0;
}
