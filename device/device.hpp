#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>

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
   *
   * @return return a name component encapsulating the public key bits  
   */
  virtual ndn::name::Component
  makeCommunicationKeyPair() = 0;
  
  /**
   * @brief make a name component for the signature of the token
   *
   * @params token
   *
   * this is to prove the presence of CKpri
   */
  virtual ndn::name::Component
  makeTokenSignature(const uint64_t& token) = 0;

public:
  /**
   * @brief run the device site of the sign-on protocol
   *
   */
  int
  run();
  
  /**
   * @brief make the bootstrapping request
   *
   * name: /ndn/sign-on/Hash(BKpub)/token1/{ECDSA signature by BKpri}
   *
   * @param token token1
   */
  ndn::Interest
  makeBootstrappingRequest(const uint64_t& token);

  /**
   * @brief express the bootstrapping request
   *
   */
  void
  expressBootstrappingRequest();

  void
  onBootstrappingResponse(const ndn::Data& data, const uint64_t& token);

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
  verifyData(const ndn::Data& data, const ndn::Block& certificate);
  
  ndn::KeyChain m_keyChain;
  ndn::Face m_face;
};

