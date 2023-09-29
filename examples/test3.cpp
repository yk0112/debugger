#include <iostream>

// clang-format off

int twice(int num) {
  return num + num;
}

int main() {
  long a = 1;
  long b = 2;
  long c = 1 + 2;
  long d = twice(c);
  std::cout << d << std::endl; 
}

// clang-format on
