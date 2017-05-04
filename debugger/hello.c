#include <stdio.h>

int main()
{
    int a = 3;
    int b = a + 42;
    printf("%lld\n", (size_t)&a);
    printf("%p\n", &a);
    for (int i = 0; i < 3; i++) {
        int c = a + b - i;
    }
    //     write(1, "Hello, world!\n", 14);
    return 239;
}
