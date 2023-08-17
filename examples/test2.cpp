#include <iostream>
// clang-format off

void a() {
    std::cout << "hello a" << "\n"; 
}

void b() {
    std::cout << "hello b" << "\n"; 
    a();
}

void c() {
    std::cout << "hello c" << "\n"; 
    b();
}

void d() {
    std::cout << "hello d" << "\n";
    c();
}

void e() {
    std::cout << "hello e" << "\n"; 
    d();
}

void f() {
    std::cout << "hello f" << "\n"; 
    e();
}

int main() {
    f();
}

// clang-format on