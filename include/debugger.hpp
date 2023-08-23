#include <fcntl.h>
#include <linux/types.h>

#include <string>
#include <unordered_map>
#include <utility>

#include "dwarf/dwarf++.hh"
#include "elf/elf++.hh"

enum class symbol_type {
  notype,  //ファイル内に実体を持たないオブジェクト
  object,  // 変数,定数など
  func,    // 関数
  section, // 再配置のために存在するエントリ
  file     //生成元のソースファイル名
};

struct symbol {
  symbol_type type;
  std::string name;
  std::uintptr_t addr;
};

class debugger {
public:
  debugger(std::string prog_name, pid_t pid)
      : m_prog_name{std::move(prog_name)}, m_pid{pid} {
    auto fd = open(m_prog_name.c_str(), O_RDONLY);

    m_elf = elf::elf{elf::create_mmap_loader(fd)};            // ELF file生成
    m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)}; // dwarf file生成
  }

  void run();

private:
  void handle_command(const std::string &line);
  void continue_execution();
  void set_breakpoint_at_address(std::intptr_t addr, bool is_print);
  void dump_registers();
  void set_pc(uint64_t pc);
  uint64_t get_pc();
  void step_over_breakpoint();
  void wait_for_signal();
  void print_all_breakpoint();

  // 与えられたpcにおける命令が含まれている関数のdieを返す
  auto get_function_from_pc(uint64_t pc) -> dwarf::die;

  // 与えられたpcにおける命令のlina tabelのentryのイテレータを返す
  auto get_line_entry_from_pc(uint64_t pc) -> dwarf::line_table::iterator;

  void initialise_load_address();

  //ロードアドレスからの相対アドレスを返す
  uint64_t offset_load_address(uint64_t addr);

  void handle_sigtrap(siginfo_t info);
  void print_source(const std::string &file_name, unsigned line,
                    unsigned n_lines_context = 2);
  void single_step_instruction();
  void single_step_instruction_with_breakpoint_check();
  siginfo_t get_signal_info();

  //ファイル名と行番号からブレークポイントを設定
  void set_breakpoint_at_source_line(const std::string &file, unsigned line);

  //関数名からブレークポイントを設定
  void set_breakpoint_at_function(const std::string &name);

  void step_out();
  void remove_breakpoint(std::intptr_t addr);
  uint64_t read_memory(uint64_t address);
  void step_in();

  //現在のアドレスの相対アドレスを返す
  uint64_t get_offset_pc();

  //ロードアドレスを返す
  uint64_t offset_dwarf_address(uint64_t addr);

  // step over
  void step_over(uint64_t addr);

  // シンボルテーブルを参照し,指定した名前のエントリを返す
  std::vector<symbol> lookup_symbol(const std::string &name);

  // バックトレースを表示する
  void print_backtrace();

  std::string m_prog_name;
  pid_t m_pid;
  std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;
  dwarf::dwarf m_dwarf;
  elf::elf m_elf;
  uint64_t m_load_address = 0;
};