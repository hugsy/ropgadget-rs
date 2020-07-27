#ifdef _TARGET_WINDOWS
#include <windows.h>
#endif


volatile void func()
{
    __asm__ (
        "xor %rax, %rax; \r\n"
        "inc %rax; \r\n"
        "int3; \r\n"
        "call *%rax\r\n"
        "mov 1, %rbx\r\n"
        "ret; \r\n"
    );
}


int main()
{
    func();
    return 0;
}