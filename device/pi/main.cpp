#include "device-pi.hpp"
#include <string.h>
#include <unistd.h>

#define DEFAULT_BKPATH "/Users/ZhangZhiyi/Develop/iot-bootstrapping/device/pi/safebag.key"
#define HOST_NAME "pi"

int usage()
{
  fprintf(stderr, "Usage:\n"
	  "-t\t this is for test purpose!\n"
	  "-s\t start service after bootstrapping\n"
	  "-k [key_path]\t load the key from the file\n"
	  "-n [host_name]\t make host name a component of the identity\n");
}

int main(int argc, char** argv)
{
  char BKfilePath[128] = DEFAULT_BKPATH;
  char HostName[128] = HOST_NAME;
  bool isForTest = false;
  bool needStartService = false;
  
  int c;
  while ((c = getopt (argc, argv, "tsk:")) != -1) {
    switch (c) {
    case 't': isForTest = true; break;
    case 's': needStartService = true; break;
    case 'k': strcpy(BKfilePath, optarg); break;
    case 'n': strcpy(HostName, optarg); break;
    default: return usage();
    }
  }

  if (isForTest) {
    DevicePi testDevice;
    return 0;
  }

  DevicePi device(BKfilePath, HostName);
  return device.run(needStartService);
}
