#include <fcntl.h>
#include <linux/types.h>

#include <string>
#include <unordered_map>
#include <utility>

#include "dwarf/dwarf++.hh"
#include "elf/elf++.hh"
class debugger {
 public:
  debugger(std::string prog_name, pid_t pid)
      : m_prog_name{std::move(prog_name)}, m_pid{pid} {
    auto fd = open(m_prog_name.c_str(), O_RDONLY);

    m_elf = elf::elf{elf::create_mmap_loader(fd)};             // ELF file生成
    m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};  // dwarf file生成
  }

  void run();

 private:
  void handle_command(const std::string& line);
  void continue_execution();
  void set_breakpoint_at_address(std::intptr_t addr);
  void dump_registers();
  void set_pc(uint64_t pc);
  uint64_t get_pc();
  void step_over_breakpoint();
  void wait_for_signal();
  void print_all_breakpoint();
  auto get_function_from_pc(uint64_t pc) -> dwarf::die;
  auto get_line_entry_from_pc(uint64_t pc) -> dwarf::line_table::iterator;
  void initialise_load_address();
  uint64_t offset_load_address(uint64_t addr);
  void handle_sigtrap(siginfo_t info);
  void print_source(const std::string& file_name, unsigned line,
                    unsigned n_lines_context = 2);
  void single_step_instruction();
  void single_step_instruction_with_breakpoint_check();
  siginfo_t get_signal_info();
  void set_breakpoint_at_source_line(const std::string& file, unsigned line);
  uint64_t offset_dwarf_address(uint64_t addr);

  std::string m_prog_name;
  pid_t m_pid;
  std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;
  dwarf::dwarf m_dwarf;
  elf::elf m_elf;
  uint64_t m_load_address = 0;
};