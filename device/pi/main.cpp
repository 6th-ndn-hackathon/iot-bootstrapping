#include "device-pi.hpp"

int main(int argc, char** argv)
{
  DevicePi device("iot-pi");
  device.importBootstrappingKey("/Users/ZhangZhiyi/Develop/ndn-iot-device-signon/device/pi/safebag.key");
  return device.run();
}
