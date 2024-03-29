# inject_aarch64

Simply clone the directory and run `make` which will create `inject_arm64` and `inject_arm64e` respectively.

__NOTE:__ AMFI needs to be turned off for arm64e if you are targeting Apple binaries until the ES method is implemented.

Below is a simple usage on the Books application.

First step is creating the library.

```bash
$ cat lib.c
#include <stdio.h>

__attribute__((constructor))
static void ctor(void)
{
    printf("hello from ReverseApple\n");
}
$ gcc lib.c -dynamiclib -o lib.dylib -arch arm64e
$ # create ~/Library/Logs/AirTraffic directory because it can be read from sandbox
$ mkdir ~/Library/Logs/AirTraffic
$ # copy to previous location to respect the sandbox
$ cp lib.dylib ~/Library/Logs/AirTraffic/airtraffic.log
$ sudo ./inject_arm64e 42448 ~/Library/Logs/AirTraffic/airtraffic.log
```

![Running against Books](running.png)
