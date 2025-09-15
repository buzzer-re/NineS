#include <stdio.h>
#include <unistd.h>
#include <ps5/klog.h>


int main() 
{
  klog_printf("Hello from pid %d\n", getpid());
  return 0;
}

