#ifdef _TARGET_WINDOWS
#include <windows.h>
#endif


volatile void func()
{
    __asm__ (
        "xor %eax, %eax; \r\n"
        "inc %eax; \r\n"
        "int3; \r\n"
        "call *%eax\r\n"
        "movl 1, %ebx\r\n"
        "ret; \r\n"
    );
}


int main()
{
    func();
    return 0;
}