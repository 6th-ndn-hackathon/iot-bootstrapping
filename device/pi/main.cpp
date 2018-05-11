#include "device-pi.hpp"

int main(int argc, char** argv)
{
  DevicePi device("iot-pi");
  return device.run();
}
