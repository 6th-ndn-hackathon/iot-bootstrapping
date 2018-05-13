#include "logger.hpp"
#include <ndn-cxx/util/time.hpp>
#include <cinttypes>
#include <stdio.h>
#include <type_traits>
#include <ndn-cxx/encoding/tlv.hpp>
#include <ndn-cxx/signature-info.hpp>
#include <ndn-cxx/lp/tags.hpp>

bool globalDebugFlag = false;

static std::string
getKey(const SignatureInfo& info)
{
  std::string type = "";
  std::string key = "";
  switch(info.getSignatureType()) {
  case 129: key = "HMAC"; break;
  case 0: type = "DigestSha256"; break;
  case 1: type = "SignatureSha256WithRsa"; break;
  case 3: type = "SignatureSha256WithEcdsa"; break;
  default: type = "NOT DEFIEND"; break;
  }

  if (info.getSignatureType() != 129) {
    if (info.hasKeyLocator()) {
      const auto& kl = info.getKeyLocator();
      if (kl.getType() == KeyLocator::KeyLocator_Name) {
	key = kl.getName().toUri();
      }
    }
  }

  return key;
}

void
printInfoFromInterest(const std::string& msg, const Interest& interest)
{
  shared_ptr<lp::IncomingFaceIdTag> tag = interest.getTag<lp::IncomingFaceIdTag>();
  if (tag) {
    std::cout << "FROM ID = " << tag->get() << std::endl;
  }
  else {
    std::cout << "CAN NOT FIND IN ID" << std::endl;
  }
    
  // std::cerr << "[" << LoggerTimestamp{} << "] " << msg << ":\n"
  // cout << "\033[1;31mbold red text\033[0m\n";
  Name name = interest.getName();
  if (name[0] == name::Component("localhost")) return;

  bool hasSignature = false;
  try {
    auto block = name.get(-2).blockFromValue();
    if (block.type() == tlv::SignatureInfo) {
      hasSignature = true;
    }
  }
  catch (const tlv::Error&) {
  }
  
  if (hasSignature) {
    SignatureInfo info(name.get(-2).blockFromValue());
    auto key = getKey(info);
    
      std::cerr << "[" << LoggerTimestamp{} << "][" << msg << "]:\n"
		<< "\033[1mNAME: \033[1;31m" << name.getPrefix(-4)
		<< "\033[0m[\n      SIGNED BY \033[1m " << key << "\033[0m" << std::endl;
  }
  else {
    std::cerr << "[" << LoggerTimestamp{} << "][" << msg << "]:\n"
	      << "\033[1mNAME: \033[1;31m" << name << "\033[0m" << std::endl;
  }
  LOG_DOT_LINE("");
}

void printInfoFromData(const std::string& msg, const Data& data)
{
  Name name = data.getName();
  if (name[0] == name::Component("localhost")) return;
  
  bool hasSignature = false;
  try {
    auto block = name.get(-3).blockFromValue();
    if (block.type() == tlv::SignatureInfo) {
      hasSignature = true;
    }
  }
  catch (const tlv::Error&) {
  }

  SignatureInfo dataSigInfo = data.getSignature().getSignatureInfo();
  auto dataKey = getKey(dataSigInfo);

  if (!hasSignature) {  
    std::cerr << "[" << LoggerTimestamp{} << "][" << msg << "]:\n"
	      << "\033[1m     NAME: \033[1;32m" << name.getPrefix(-1) << "\033[0m"
	      << "[\n                 VER=" << name.get(-1).toVersion() << "]\n"
	      << "\033[1mSIGNATURE: \033[0mSIGNED BY \033[1m " << dataKey << "\033[0m"
	      << std::endl;
    LOG_DOT_LINE("");
    return;
  }

  SignatureInfo info(name.get(-3).blockFromValue());
  auto key = getKey(info);
    
    std::cerr << "[" << LoggerTimestamp{} << "][" << msg << "]:\n"
	      << "\033[1mNAME: \033[1;32m" << name.getPrefix(-5) << "\033[0m"
	      << "[\n          SIG=" << key << "]"
	      << "[\n          VER=" << name.get(-1).toVersion() << "]\n"
	      << "\033[1mSIGNATURE: \033[0mSIGNED BY \033[1m " << dataKey << "\033[0m"
	      << std::endl;
  LOG_DOT_LINE("");
}

std::ostream&
operator<<(std::ostream& os, const LoggerTimestamp&)
{
  using namespace ndn::time;

  static const microseconds::rep ONE_SECOND = 1000000;
  microseconds::rep microsecondsSinceEpoch = duration_cast<microseconds>(
    system_clock::now().time_since_epoch()).count();

  // 10 (whole seconds) + '.' + 6 (fraction) + '\0'
  char buffer[10 + 1 + 6 + 1];
  BOOST_ASSERT_MSG(microsecondsSinceEpoch / ONE_SECOND <= 9999999999L,
                   "whole seconds cannot fit in 10 characters");

  static_assert(std::is_same<microseconds::rep, int_least64_t>::value,
                "PRIdLEAST64 is incompatible with microseconds::rep");
  // - std::snprintf not found in some environments
  //   http://redmine.named-data.net/issues/2299 for more information
  snprintf(buffer, sizeof(buffer), "%" PRIdLEAST64 ".%06" PRIdLEAST64,
           microsecondsSinceEpoch / ONE_SECOND,
           microsecondsSinceEpoch % ONE_SECOND);

  return os << buffer;
}
