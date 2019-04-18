#include "device.h"
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <iostream>


int main(void)
{
	class DeviceList* pdevice_list = new DeviceList();
	delete pdevice_list;

	pid_t fork_pid = fork();
	if (fork_pid != 0) {
        int status = 0;
        int err = waitpid(fork_pid, &status, 0);
		if(err < 0)
		    std::cout << " waitpid error happen" << std::endl;
		else
			std::cout << " child exit now " << std::endl;
	}
trick:
	{
	    class DeviceList* pdevice_list = new DeviceList();
	    delete pdevice_list;
	}
	return 0;
}
