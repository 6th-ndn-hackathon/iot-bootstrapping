#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <string>
#include <iostream>

class Device
{
public:
  /**
   * @brief import the Bootstrapping Key from a file
   *
   * @param path the path to the file
   */
  virtual void
  importBootstrappingKey(const char* path) = 0;

  /**
   * @brief make a name component for the digest of the bootstrapping key
   *
   * @return return a name component encapsulating the digest
   */
  virtual ndn::name::Component
  makeBootstrappingKeyDigest() = 0;

  /**
   * @brief make a pair for securing communication
   *
   * stores the key pair for later use
   * the public key will be sent to the controller to sign
   * @param identity prefix
   *
   * @return return a name component encapsulating the public key bits
   */
  virtual ndn::name::Component
  makeCommunicationKeyPair(const ndn::Name& prefix) = 0;

  /**
   * @brief make a name component for the signature of the token
   *
   * @params token
   *
   * this is to prove the presence of CKpri
   */
  virtual ndn::name::Component
  makeTokenSignature(const uint64_t& token) = 0;

  virtual void
  startServices() = 0;

  virtual bool
  verifyHash(const std::string& hash);

public:
  /**
   * @brief run the device site of the sign-on protocol
   *
   */
  int
  run(bool needStartService = false);

  /**
   * @brief make the bootstrapping request
   *
   * name: /ndn/sign-on/{digest of BKpub}/{ECDSA signature by BKpri}
   *
   */
  ndn::Interest
  makeBootstrappingRequest();

  /**
   * @brief express the bootstrapping request
   *
   */
  void
  expressBootstrappingRequest();

  void
  onBootstrappingResponse(const ndn::Data& data);

  /**
   * @brief make the certificate request
   *
   * @params prefix the home prefix received from the bootstrap response
   * @params token received from the bootstrap response
   *
   * name: /[home-prefix]/cert/Hash(BKpub)/{CKpub}/{signature of token2}/{signature by BKpri}
   */
  ndn::Interest
  makeCertificateRequest(const ndn::Name& prefix, const uint64_t& token);

  /**
   * @brief express the certificate request
   *
   */
  void
  expressCertificateRequest(const ndn::Name& prefix, const uint64_t& token);

  void
  onCertificateResponse(const ndn::Data& data);

protected:
  virtual void
  signRequest(ndn::Interest& request);

  virtual bool
  verifyData(const ndn::Data& data, const ndn::security::v2::Certificate& certificate);

  virtual bool
  getKeyLocatorName(const ndn::SignatureInfo& si, ndn::Name& name);
  
  virtual bool
  getKeyLocatorName(const ndn::Interest& interest, ndn::Name& name);

  virtual bool
  getKeyLocatorName(const ndn::Data& data, ndn::Name& name);
  
  typedef ndn::function<void(void)> afterVerificationCallback;
  typedef ndn::function<void(const std::string& reason)> failVerificationCallback;
  
  virtual void
  verify(const ndn::Data& data,
	 const afterVerificationCallback& cbAfterVerification,
	 const failVerificationCallback& cbFailVerification = [] (const std::string& reason) {
	   std::cout << reason << std::endl;
	 });

  virtual void
  verify(const ndn::Interest& interest,
	 const afterVerificationCallback& cbAfterVerification,
	 const failVerificationCallback& cbFailVerification = [] (const std::string& reason) {
	   std::cout << reason << std::endl;
	 });

  virtual void
  onCertificate(const ndn::Data& certificate, const ndn::Interest& interest,
		const afterVerificationCallback& cbAfterVerification,
		const failVerificationCallback& cbFailVerification);

  ndn::security::v2::Certificate m_anchor;
  ndn::security::v2::Certificate m_deviceCert;
  ndn::KeyChain m_keyChain;
  ndn::Face m_face;
  bool m_needStartService;
};
