#ifndef UNTHEMIDATOR_HOOKS_HPP
#define UNTHEMIDATOR_HOOKS_HPP

#include "c_emulator_ctx.hpp"

namespace hooks {

    void get_module_handle(const c_emulator_ctx *ctx);
    void get_proc_address(const c_emulator_ctx *ctx);
    void create_file_a(c_emulator_ctx *ctx);
    void create_file_w(c_emulator_ctx *ctx);
    void create_file_mapping(c_emulator_ctx *ctx);
    void read_file(c_emulator_ctx *ctx);
    void rtl_allocate_heap(c_emulator_ctx *ctx);
    void rtl_reallocate_heap(c_emulator_ctx *ctx);
    void rtl_free_heap(c_emulator_ctx *ctx);
    void local_alloc(c_emulator_ctx *ctx);
    void get_current_dir(const c_emulator_ctx *ctx);
    void get_adapters_info(c_emulator_ctx *ctx);
    void sh_get_special_folder_path_w(const c_emulator_ctx *ctx);
    void get_volume_information_a(c_emulator_ctx *ctx);
    void get_local_time(c_emulator_ctx *ctx);
    void system_time_to_file_time(c_emulator_ctx *ctx);
    void get_module_filename(const c_emulator_ctx *ctx);
    void get_command_line_a(c_emulator_ctx *ctx);
    void get_command_line_w(c_emulator_ctx *ctx);
    void add_veh(c_emulator_ctx *ctx);
    void remove_veh(c_emulator_ctx *ctx);
    void raise_exception(c_emulator_ctx *ctx);
    void get_version(const c_emulator_ctx *ctx);
    void virtual_alloc(c_emulator_ctx *ctx);
    void virtual_free(c_emulator_ctx *ctx);
    void virtual_protect(const c_emulator_ctx *ctx);
    void map_view_of_file(c_emulator_ctx *ctx);
    void get_file_size(c_emulator_ctx *ctx);
    void get_token_information(c_emulator_ctx *ctx);
    void get_thread_context(c_emulator_ctx *ctx);
    void create_thread(const c_emulator_ctx *ctx);

    void message_box_ex_w(const c_emulator_ctx *ctx);
    void message_box_ex_a(const c_emulator_ctx *ctx);

    void nt_query_information_process(c_emulator_ctx *ctx);
    void nt_query_system_information(const c_emulator_ctx *ctx);
    void nt_protect_virtual_memory(const c_emulator_ctx *ctx);
    void nt_query_object(c_emulator_ctx *ctx);
    void check_remote_debugger(c_emulator_ctx *ctx);
    void is_wow64_process(c_emulator_ctx *ctx);
    void is_wow64_process2(c_emulator_ctx *ctx);
    void get_current_process_id(const c_emulator_ctx *ctx);
    void get_current_thread_id(const c_emulator_ctx *ctx);
    void get_last_error(const c_emulator_ctx *ctx);
    void set_last_error(c_emulator_ctx *ctx);
    void create_toolhelp_snapshot(c_emulator_ctx *ctx);
    void close_handle(c_emulator_ctx *ctx);
    void process_next_w(c_emulator_ctx *ctx);
    void process_first(c_emulator_ctx *ctx);
    void process_first_w(c_emulator_ctx *ctx);
    void process_next(c_emulator_ctx *ctx);

    void dummy_function(const c_emulator_ctx *ctx);
    void dummy_true_function(const c_emulator_ctx *ctx);

    void vm_enter(const c_emulator_ctx *ctx);

}

#endif //UNTHEMIDATOR_HOOKS_HPP
