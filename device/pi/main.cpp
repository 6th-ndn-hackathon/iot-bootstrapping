#include "device-pi.hpp"
#include <string.h>

#define DEFAULT_BKPATH "/Users/ZhangZhiyi/Develop/ndn-iot-device-signon/device/pi/safebag.key"
int main(int argc, char** argv)
{
  char BKfilePath[128] = DEFAULT_BKPATH;
  if (argc > 1) {
    strcpy(BKfilePath, argv[1]);
  }
  
  DevicePi device(BKfilePath, "iot-pi");
  return device.run();
}
