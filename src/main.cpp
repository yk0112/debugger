#include <fcntl.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

#include "../include/breakpoint.hpp"
#include "../include/debugger.hpp"
#include "../include/register.hpp"
#include "../modules/linenoise/linenoise.h"

std::vector<std::string> split(const std::string &s, char delimiter) {
  std::vector<std::string> out{};
  std::stringstream ss{s};
  std::string item;
  while (std::getline(ss, item, delimiter)) {
    out.push_back(item);
  }
  return out;
}

bool is_prefix(const std::string &s, const std::string &of) {
  if (s.size() > of.size())
    return false;
  return std::equal(s.begin(), s.end(), of.begin());
}

bool is_suffix(const std::string &s, const std::string &of) {
  if (s.size() > of.size())
    return false;
  auto diff = of.size() - s.size();
  return std::equal(s.begin(), s.end(), of.begin() + diff);
}

std::string to_string(symbol_type st) {
  switch (st) {
  case symbol_type::notype:
    return "NOTYPE";
  case symbol_type::file:
    return "FILE";
  case symbol_type::object:
    return "OBJECT";
  case symbol_type::section:
    return "SECTION";
  case symbol_type::func:
    return "FUNCTION";
  default:
    return "Not found type";
  }
}

symbol_type to_symbol_type(elf::stt sym) {
  switch (sym) {
  case elf::stt::notype:
    return symbol_type::notype;
  case elf::stt::object:
    return symbol_type::object;
  case elf::stt::func:
    return symbol_type::func;
  case elf::stt::section:
    return symbol_type::section;
  case elf::stt::file:
    return symbol_type::file;
  default:
    return symbol_type::notype;
  }
};

std::vector<symbol> debugger::lookup_symbol(
    const std::string &name) { // 検索するtype(obj,func,file...)毎に区別すべき?
  std::vector<symbol> syms;

  for (auto &sec : m_elf.sections()) {
    if (sec.get_hdr().type != elf::sht::symtab &&
        sec.get_hdr().type != elf::sht::dynsym)
      continue;

    for (auto sym : sec.as_symtab()) {
      if (sym.get_name() == name) {
        auto &d = sym.get_data();
        syms.push_back(
            symbol{to_symbol_type(d.type()), sym.get_name(), d.value});
      }
    }
  }

  return syms;
}

void debugger::continue_execution() {
  step_over_breakpoint();
  ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
  wait_for_signal();
}

uint64_t debugger::get_pc() { return get_register_value(m_pid, reg::rip); }

void debugger::set_pc(uint64_t pc) { set_register_value(m_pid, reg::rip, pc); }

void debugger::remove_breakpoint(std::intptr_t addr) {
  if (m_breakpoints.at(addr).is_enable()) {
    m_breakpoints.at(addr).disable();
  }
  m_breakpoints.erase(addr);
}

uint64_t debugger::read_memory(uint64_t address) {
  return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

uint64_t debugger::get_offset_pc() { return offset_load_address(get_pc()); }

void debugger::step_over_breakpoint() {
  if (m_breakpoints.count(get_pc())) {
    auto &bp = m_breakpoints.at(get_pc());
    if (bp.is_enable()) {
      bp.disable();
      ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
      wait_for_signal();
      bp.enable();
    }
  }
}

void debugger::step_out() {
  auto frame_pointer = get_register_value(m_pid, reg::rbp);
  auto return_address = read_memory(frame_pointer + 8);

  bool should_remove_breakpoint = false;
  if (!m_breakpoints.count(return_address)) {
    set_breakpoint_at_address(return_address, false);
    should_remove_breakpoint = true;
  }
  continue_execution();

  if (should_remove_breakpoint) {
    remove_breakpoint(return_address);
  }
}

void debugger::step_in() {
  auto line = get_line_entry_from_pc(get_offset_pc())->line;
  auto before_pc = get_offset_pc();
  unsigned int now = line;
  while (now == line) {
    try {
      single_step_instruction_with_breakpoint_check();
      now = get_line_entry_from_pc(get_offset_pc())->line;
    } catch (const std::exception &e) {
      step_over(before_pc);
      return;
    }
  }
  auto line_entry = get_line_entry_from_pc(get_offset_pc());
  print_source(line_entry->file->path, line_entry->line);
}

void debugger::step_over(uint64_t addr) {
  auto func = get_function_from_pc(addr);
  auto func_entry = at_low_pc(func);
  auto func_end = at_high_pc(func); // return uint64_t

  auto line = get_line_entry_from_pc(func_entry); // function start line
  auto start_line = get_line_entry_from_pc(addr); // now line

  std::vector<std::intptr_t> to_delete{};

  while (line->address < func_end) {
    auto load_address = offset_dwarf_address(line->address);
    if (line->address != start_line->address &&
        !m_breakpoints.count(load_address)) {
      set_breakpoint_at_address(load_address, false);
      to_delete.push_back(load_address);
    }
    ++line;
  }

  auto frame_pointer = get_register_value(m_pid, reg::rbp);
  auto return_address = read_memory(frame_pointer + 8);
  if (!m_breakpoints.count(return_address)) {
    set_breakpoint_at_address(return_address, false);
    to_delete.push_back(return_address);
  }

  continue_execution();

  for (auto addr : to_delete) {
    remove_breakpoint(addr);
  }
}

void debugger::single_step_instruction() {
  ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
  wait_for_signal();
}

void debugger::single_step_instruction_with_breakpoint_check() {
  if (m_breakpoints.count(get_pc())) {
    step_over_breakpoint();
  } else {
    single_step_instruction();
  }
}

void debugger::wait_for_signal() {
  int wait_status;
  auto options = 0;
  waitpid(m_pid, &wait_status, options);

  auto siginfo = get_signal_info(); // type: siginfo_t

  switch (siginfo.si_signo) {
  case SIGTRAP:
    handle_sigtrap(siginfo);
    break;
  case SIGSEGV:
    std::cout << "Yay, segfault. Reason: " << siginfo.si_code << std::endl;
    break;
  default:
    std::cout << "Got signal " << strsignal(siginfo.si_signo) << std::endl;
  }
}

void debugger::print_all_breakpoint() {
  for (auto &&point : m_breakpoints) {
    std::cout << point.first << "\n";
  }
}

dwarf::die debugger::get_function_from_pc(uint64_t pc) {
  for (auto &cu : m_dwarf.compilation_units()) {
    if (die_pc_range(cu.root()).contains(pc)) {
      for (const auto &die : cu.root()) {
        if (die.tag == dwarf::DW_TAG::subprogram) {
          // die_pc_rangeが原因, DIE does not have attribute DW_AT_low_pc
          if (die.has(dwarf::DW_AT::low_pc) && die_pc_range(die).contains(pc)) {
            return die;
          }
        }
      }
    }
  }
  throw std::out_of_range{"Cannot find function"};
}

dwarf::line_table::iterator debugger::get_line_entry_from_pc(uint64_t pc) {
  for (auto &cu : m_dwarf.compilation_units()) {
    if (die_pc_range(cu.root()).contains(pc)) {
      auto &lt = cu.get_line_table();
      auto it = lt.find_address(pc);
      if (it == lt.end()) {
        throw std::out_of_range{"Cannot find line entry"};
      } else {
        return it;
      }
    }
  }
  throw std::out_of_range{"Cannot find line entry"};
}

void debugger::initialise_load_address() {
  if (m_elf.get_hdr().type == elf::et::dyn) {
    std::ifstream map("/proc/" + std::to_string(m_pid) + "/maps");
    std::string addr;
    std::getline(map, addr, '-');
    std::cout << addr << "\n";
    m_load_address = std::stol(addr, nullptr, 16);
  }
}

uint64_t debugger::offset_load_address(uint64_t addr) {
  return addr - m_load_address;
}

uint64_t debugger::offset_dwarf_address(uint64_t addr) {
  return addr + m_load_address;
}

void debugger::handle_sigtrap(siginfo_t info) {
  switch (info.si_code) {
  case SI_KERNEL:
  case TRAP_BRKPT: {
    set_pc(get_pc() - 1);

    if (m_breakpoints.at(get_pc()).is_users_breakpoint) {
      std::cout << "Hit breakpoint at address 0x" << std::hex << get_pc()
                << std::endl;
    }
    auto offset_pc = offset_load_address(get_pc());
    auto line_entry = get_line_entry_from_pc(offset_pc);
    print_source(line_entry->file->path, line_entry->line);
    return;
  }
  case TRAP_TRACE:
    return;
  default:
    std::cout << "Unknown SIGTRAP code " << info.si_code << std::endl;
    return;
  }
}

void debugger::print_source(
    const std::string &filename, unsigned line,
    unsigned n_lines_context) { // n_lines_context == 周辺を何行表示するか
  std::ifstream file{filename};
  auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
  auto end_line = line + n_lines_context +
                  (line < n_lines_context ? n_lines_context - line : 0) + 1;

  char c{};
  auto current_line = 1u;

  while (current_line != start_line && file.get(c)) {
    if (c == '\n') {
      ++current_line;
    }
  }
  std::cout << (current_line == line ? "> " : "  ");

  while (current_line <= end_line && file.get(c)) {
    std::cout << c;
    if (c == '\n') {
      ++current_line;
      std::cout << (current_line == line ? "> " : "  ");
    }
  }
  std::cout << std::endl;
}

siginfo_t debugger::get_signal_info() {
  siginfo_t info;
  ptrace(PTRACE_GETSIGINFO, m_pid, nullptr,
         &info); // get last signal prosess recived
  return info;
}

void debugger::set_breakpoint_at_address(std::intptr_t addr, bool is_print) {
  if (is_print) {
    std::cout << "set break point at address " << std::hex << addr << "\n";
  }
  breakpoint bp{m_pid, addr, is_print};
  bp.enable();
  m_breakpoints.emplace(addr, bp);
}

void debugger::set_breakpoint_at_function(const std::string &name) {
  for (const auto &cu : m_dwarf.compilation_units()) {
    for (const auto &die : cu.root()) {
      if (die.has(dwarf::DW_AT::name) && at_name(die) == name) {
        auto low_pc = at_low_pc(die);
        auto entry = get_line_entry_from_pc(low_pc);
        ++entry;
        set_breakpoint_at_address(offset_dwarf_address(entry->address), true);
      }
    }
  }
}

void debugger::set_breakpoint_at_source_line(const std::string &file,
                                             unsigned line) {
  for (const auto &cu : m_dwarf.compilation_units()) {
    if (is_suffix(file, at_name(cu.root()))) {
      const auto &lt = cu.get_line_table();

      for (const auto &entry : lt) {
        if (entry.is_stmt && entry.line == line) {
          set_breakpoint_at_address(offset_dwarf_address(entry.address), true);
          return;
        }
      }
    }
  }
}

void debugger::handle_command(const std::string &line) {
  auto args = split(line, ' ');
  auto command = args[0];

  if (is_prefix(command, "cont")) {
    continue_execution();
  } else if (is_prefix(command, "break")) {
    if (args[1][0] == '0' && args[1][1] == 'x') {
      std::string addr{args[1], 2};
      set_breakpoint_at_address(std::stol(addr, 0, 16), true);
    } else if (args[1].find(':') != std::string::npos) {
      auto file_and_line = split(args[1], ':');
      set_breakpoint_at_source_line(file_and_line[1],
                                    std::stoi(file_and_line[0]));
    } else {
      set_breakpoint_at_function(args[1]);
    }
  } else if (is_prefix(command, "step")) {
    step_in();
  } else if (is_prefix(command, "next")) {
    step_over(get_offset_pc());
  } else if (is_prefix(command, "finish")) {
    step_out();
  } else if (is_prefix(command, "stepi")) {
    single_step_instruction_with_breakpoint_check();
    auto line_entry = get_line_entry_from_pc(get_pc());
    print_source(line_entry->file->path, line_entry->line);
  } else if (is_prefix(command, "register")) {
    if (is_prefix(args[1], "dump")) {
      dump_registers();
    } else if (is_prefix(args[1], "read")) {
      std::cout << "0x" << std::setfill('0') << std::setw(16) << std::hex
                << get_register_value(m_pid, get_register_from_name(args[2]))
                << std::endl;
    } else if (is_prefix(args[1], "write")) {
      std::string val{args[3], 2};
      set_register_value(m_pid, get_register_from_name(args[2]),
                         std::stol(val, nullptr, 16));
    }
  } else if (is_prefix(command, "all")) {
    print_all_breakpoint();
  } else if (is_prefix(command, "symbol")) {
    auto syms = lookup_symbol(args[1]);
    if (syms.empty()) {
      std::cout << "Not found symbol \n";
    } else {
      for (auto &&s : syms) {
        std::cout << s.name << ' ' << to_string(s.type) << " 0x" << std::hex
                  << s.addr << std::endl; // 相対アドレス
      }
    }
  } else {
    std::cerr << "unknown command \n";
  }
}

void debugger::dump_registers() {
  for (const auto &rd : g_register_descriptors) {
    std::cout << rd.name << " 0x" << std::setfill('0') << std::setw(16)
              << std::hex << get_register_value(m_pid, rd.r) << "\n";
  }
}

void debugger::run() {
  wait_for_signal();
  initialise_load_address();

  char *line = nullptr;
  while ((line = linenoise("minidbg> ")) != nullptr) {
    handle_command(line);
    linenoiseHistoryAdd(line);
    linenoiseFree(line);
  }
}

void execute_debugee(const std::string prog_name) {
  if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
    std::cerr << "Error in ptrace \n";
    return;
  }
  // tracemeによりこれ以降、子プロセスでexecが実行されるとSIGTRAPが送信される
  execl(prog_name.c_str(), prog_name.c_str(), nullptr);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cerr << "Pleae specify the program" << '\n';
    return -1;
  }
  auto prog = argv[1];
  auto pid = fork();

  if (pid == 0) {
    personality(ADDR_NO_RANDOMIZE);
    execute_debugee(prog);
  } else if (pid >= 1) {
    std::cout << "start debug process: " << pid << '\n';
    debugger dbg{prog, pid};
    dbg.run();
  }
}