#include "device-ar.hpp"

int ar_main(int argc, char** argv)
{
  DeviceAr device("iot-ar");
  return device.run();
}
