#include "hooks.hpp"

#include <iostream>
#include <codecvt>
#include <locale>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>
#include <algorithm>

#include "../unpacker/c_themida_unpacker.hpp"

namespace {
    template<typename T>
    bool read_conversion_input(c_emulator_ctx *ctx, uint64_t address, const int count, std::vector<T> &input) {
        if (count != -1) {
            input.resize(static_cast<size_t>(count));
            return uc_mem_read(ctx->get_uc(), address, input.data(), input.size() * sizeof(T)) == UC_ERR_OK;
        }

        while (true) {
            const auto value = ctx->read<T>(address);

            if (!value) {
                return false;
            }

            input.push_back(*value);

            if (!*value) {
                return true;
            }

            address += sizeof(T);
        }
    }

    constexpr uint32_t k_protection_marker = 0x676767;
    constexpr uint64_t k_created_thread_handle = 0x1337;

    uint64_t teb_field(const c_emulator_ctx *ctx, const uint32_t offset32, const uint32_t offset64) {
        return ctx->get_memory()->get_address_by_tag("TEB").value() +
               (ctx->get_arch() == e_architecture::k_x86 ? offset32 : offset64);
    }

    void write_last_error(c_emulator_ctx *ctx, const uint32_t error) {
        if (!ctx->write<uint32_t>(teb_field(ctx, 0x34, 0x68), error)) {
            throw std::runtime_error("failed to write last error");
        }
    }

    struct s_file_view {
        uint64_t base = 0;
        uint32_t size = 0;
        uint32_t status = 0;
    };

    s_file_view map_file_view(c_emulator_ctx *ctx, const std::vector<uint8_t> &file, const uint64_t file_size,
        const uint64_t offset, uint64_t bytes) {
        //
        if (offset >= file_size || file_size > file.size()) {
            return {.status = 0xC000000D}; // STATUS_INVALID_PARAMETER
        }

        const auto remaining = file_size - offset;

        if (!bytes) {
            bytes = remaining;
        }

        if (bytes > remaining || bytes > UINT32_MAX - 0xFFF) {
            return {.status = 0xC000001F}; // STATUS_INVALID_VIEW_SIZE
        }

        const auto size = static_cast<uint32_t>(page_up(bytes, 0x1000));
        const auto base = ctx->allocate_storage(size, "local_file");

        if (const auto copy_size = std::min<uint64_t>(size, remaining);
            uc_mem_write(ctx->get_uc(), base, file.data() + offset, copy_size) != UC_ERR_OK) {
            //
            ctx->free_storage(base);

            return {.status = 0xC0000005}; // STATUS_ACCESS_VIOLATION
        }

        return {
            .base = base,
            .size = size,
            .status = 0,
        };
    }

    template<typename T, typename C>
    void write_process_entry(c_emulator_ctx *ctx, const bool first) {
        struct s_process_entry {
            uint32_t size, usage, process_id;
            T default_heap_id;
            uint32_t module_id, threads, parent_process_id;
            int32_t base_priority;
            uint32_t flags;
            C exe_file[260];
        };

        static_assert(sizeof(s_process_entry) == (sizeof(T) == 4 ? (sizeof(C) == 1 ? 296 : 556) : sizeof(C) == 1 ? 304 : 568));

        const auto address = ctx->get_arg(1);
        const auto snapshot = ctx->get_process_snapshot(ctx->get_arg(0));

        if (const auto size = ctx->read<uint32_t>(address); !snapshot || !size || *size < sizeof(s_process_entry)) {
            write_last_error(ctx, !snapshot ? 6 : (!size ? 998 : 87));
            ctx->set_result(0);
            return;
        }

        struct s_process {
            uint32_t process_id, parent_process_id, threads;
            int32_t base_priority;
            const char *name;
        };

        const s_process processes[] = {
            {4, 0, 80, 8, "System"},
            {256, 4, 2, 11, "smss.exe"},
            {384, 256, 8, 13, "csrss.exe"},
            {448, 256, 1, 13, "wininit.exe"},
            {512, 448, 6, 9, "services.exe"},
            {576, 448, 8, 9, "lsass.exe"},
            {768, 512, 10, 8, "svchost.exe"},
            {snapshot->m_process_id, 0, 1, 8, "bebra.exe"},
        };
        const auto index = first ? 0 : snapshot->m_index;

        if (!(snapshot->m_flags & 2) || index >= std::size(processes)) {
            write_last_error(ctx, 18);
            ctx->set_result(0);
            return;
        }

        const auto &process = processes[index];
        s_process_entry entry{};
        entry.size = sizeof(entry);
        entry.process_id = process.process_id;
        entry.parent_process_id = process.parent_process_id;
        entry.threads = process.threads;
        entry.base_priority = process.base_priority;

        for (size_t i = 0; process.name[i]; ++i) {
            entry.exe_file[i] = process.name[i];
        }

        const auto success = ctx->write(address, entry);

        if (!success) {
            write_last_error(ctx, 998);
        } else {
            snapshot->m_index = index + 1;
        }

        ctx->set_result(success ? 1 : 0);
    }

    void handle_virtual_protection(const c_emulator_ctx *ctx, const uint64_t address, const uint32_t size,
        const uint32_t new_prot, const uint64_t old_prot_ptr) {
        //
        const auto memory = ctx->get_memory();
        const auto image_base = memory->get_image_base();
        const auto image_size = memory->get_image_size();
        const auto headers_size = memory->get_pe_image()->get_size_of_headers();

        if (address < image_base || address - image_base >= image_size) {
            return;
        }

        if (address - image_base < headers_size) {
            return;
        }

        if (new_prot != k_protection_marker) {
            if (uc_mem_write(ctx->get_uc(), old_prot_ptr,
                             &k_protection_marker, sizeof(k_protection_marker)) != UC_ERR_OK) {
                //
                throw std::runtime_error("failed to write old memory protection");
            }

            ctx->get_themida_unpacker()->on_region_made_writable(address, size);
            return;
        }

        ctx->get_themida_unpacker()->on_region_save(address, size);
    }
}

void hooks::get_module_handle(const c_emulator_ctx *ctx) {
    const auto name_ptr = ctx->get_arg(0);

    if (!name_ptr) {
        throw std::runtime_error("hooks: get local module handle is not implemented");
    }

    char buffer[64]{};
    uc_mem_read(ctx->get_uc(), name_ptr, buffer, sizeof(buffer));

    const auto module_name = std::string(buffer);

    if (module_name.find("dateinj01") != std::string::npos || module_name.find("cmdvrt32") != std::string::npos ||
        module_name.find("SbieDll") != std::string::npos || module_name.find("frida-agent") != std::string::npos) {
        //

        ctx->set_result(0);
        return;
    }

    const auto module_handle = ctx->get_imports()->load_module(module_name);

    ctx->set_result(module_handle);

    std::cout << "[unthemidator][runtime] loaded module: " << module_name << " (forwarded to unthemidator.dummy) - 0x" <<
            std::hex << module_handle << std::dec << std::endl;
}

void hooks::get_proc_address(const c_emulator_ctx *ctx) {
    const auto module_handle = ctx->get_arg(0);
    const auto name_ptr = ctx->get_arg(1);

    if (!module_handle) {
        throw std::runtime_error("hooks: get proc address from local module is not implemented");
    }

    std::string function_name;
    uint64_t address = 0;

    if (name_ptr <= UINT16_MAX) {
        const auto ordinal = static_cast<uint16_t>(name_ptr);

        function_name = "#" + std::to_string(ordinal) + " (ordinal)";
        address = ctx->get_imports()->resolve_import(module_handle, ordinal);
    } else {
        char buffer[64]{};

        if (uc_mem_read(ctx->get_uc(), name_ptr, buffer, sizeof(buffer) - 1) == UC_ERR_OK) {
            function_name = buffer;
            address = ctx->get_imports()->resolve_import(module_handle, function_name);
        }
    }

    std::cout << "[unthemidator][runtime] loaded function " << function_name << std::hex << " (0x" <<
            address << ") from mod 0x" << module_handle << std::dec << std::endl;

    ctx->set_result(address);
}

void hooks::create_file_a(c_emulator_ctx *ctx) {
    std::vector<char> path;
    const auto readable = read_conversion_input(ctx, ctx->get_arg(0), -1, path);

    printf("[unthemidator][runtime] CreateFileA: %s\n", readable ? path.data() : "<unreadable path>");

    const auto handle = readable ? ctx->open_file(path.data()) : 0;

    if (!handle) {
        write_last_error(ctx, readable ? 2 : 998);
    }

    ctx->set_result(handle ? handle : UINT64_MAX);
}

void hooks::create_file_w(c_emulator_ctx *ctx) {
    std::vector<char16_t> path;
    std::string text = "<unreadable path>";

    uint64_t handle = 0;
    uint32_t error = 998;

    if (read_conversion_input(ctx, ctx->get_arg(0), -1, path)) {
        try {
            std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
            text = converter.to_bytes(path.data());
            handle = ctx->open_file(text);
            error = 2;
        } catch (const std::range_error &) {
            text = "<invalid UTF-16 path>";
            error = 1113;
        }
    }

    printf("[unthemidator][runtime] CreateFileW: %s\n", text.c_str());

    if (!handle) {
        write_last_error(ctx, error);
    }

    ctx->set_result(handle ? handle : UINT64_MAX);
}

void hooks::create_file_mapping(c_emulator_ctx *ctx) {
    const auto file = ctx->get_file_handle(ctx->get_arg(0), false);
    const auto protection = static_cast<uint32_t>(ctx->get_arg(2));
    const auto size = (static_cast<uint64_t>(static_cast<uint32_t>(ctx->get_arg(3))) << 32) |
                      static_cast<uint32_t>(ctx->get_arg(4));
    const auto file_size = file ? file->m_size : ctx->get_original_file_mapping().size();
    uint32_t error = 0;
    if (!ctx->get_arg(0)) {
        error = 6;
    } else if (!file_size) {
        error = 1006;
    } else if (size > file_size || (protection != 2 && protection != 4 && protection != 8 &&
                                    protection != 0x20 && protection != 0x40 && protection != 0x80)) {
        error = 87;
    }

    if (error) {
        write_last_error(ctx, error);
        ctx->set_result(0);
        return;
    }

    ctx->set_result(ctx->create_file_mapping(ctx->get_arg(0), size, protection));
}

void hooks::rtl_allocate_heap(c_emulator_ctx *ctx) {
    ctx->set_result(ctx->allocate_heap(ctx->get_arg(2)));
}

void hooks::rtl_reallocate_heap(c_emulator_ctx *ctx) {
    ctx->set_result(ctx->reallocate_heap(ctx->get_arg(2), ctx->get_arg(3),
        static_cast<uint32_t>(ctx->get_arg(1))));
}

void hooks::rtl_free_heap(c_emulator_ctx *ctx) {
    ctx->set_result(ctx->free_heap(ctx->get_arg(2)));
}

void hooks::local_alloc(c_emulator_ctx *ctx) {
    const auto size = static_cast<uint32_t>(ctx->get_arg(1));
    const auto base = ctx->allocate_storage(size, "local_alloc");

    ctx->set_result(base);
}

namespace {
    // The emulated process runs from a fictional drive root, so every path API has
    // to agree with the others about where "the executable" lives.
    std::string emulated_command_line(const c_emulator_ctx *ctx) {
        const auto input = ctx->get_input_path();
        const auto separator = input.find_last_of("\\/");
        const std::string file = separator == std::string::npos ? input : input.substr(separator + 1);
        return "\"C:\\" + file + "\"";
    }
}

void hooks::get_command_line_a(c_emulator_ctx *ctx) {
    const auto str_location = ctx->allocate_storage(0x100);

    const auto command_line = emulated_command_line(ctx);
    uc_mem_write(ctx->get_uc(), str_location, command_line.data(), command_line.length() + 1);

    ctx->set_result(str_location);
}

void hooks::get_command_line_w(c_emulator_ctx *ctx) {
    const auto str_location = ctx->allocate_storage(0x100);

    const auto command_line = emulated_command_line(ctx);
    std::u16string wide_command_line(command_line.begin(), command_line.end());
    wide_command_line.push_back(u'\0');
    uc_mem_write(ctx->get_uc(), str_location, wide_command_line.data(), wide_command_line.size() * sizeof(char16_t));

    ctx->set_result(str_location);
}

void hooks::add_veh(c_emulator_ctx *ctx) {
    const auto first = ctx->get_arg(0);
    const auto handler_address = ctx->get_arg(1);

    std::cout << "[unthemidator][runtime] added exception handler (VEH): 0x" <<
        std::hex << handler_address << " (priority=" << std::dec << first << ")" << std::endl;

    ctx->add_exception_handler(handler_address);
    ctx->set_result(handler_address);
}

void hooks::remove_veh(c_emulator_ctx *ctx) {
    const auto handler_address = ctx->get_arg(0);

    std::cout << "[unthemidator][runtime] removed exception handler (VEH): 0x" <<
        std::hex << handler_address << std::dec << std::endl;

    ctx->remove_exception_handler(handler_address);
    ctx->set_result(1);
}

void hooks::get_version(const c_emulator_ctx *ctx) {
    ctx->set_result(0x65F4000A); // Windows 11 24H2 (build 26100)
}

void hooks::virtual_alloc(c_emulator_ctx *ctx) {
    const auto base = ctx->allocate_virtual(ctx->get_arg(0), ctx->get_arg(1),
        static_cast<uint32_t>(ctx->get_arg(2)));

    if (!base) {
        write_last_error(ctx, 487);
    }

    ctx->set_result(base);
}

void hooks::virtual_free(c_emulator_ctx *ctx) {
    const auto result = ctx->free_virtual(ctx->get_arg(0), ctx->get_arg(1),
        static_cast<uint32_t>(ctx->get_arg(2)));

    if (!result) {
        write_last_error(ctx, 87);
    }

    ctx->set_result(result);
}

void hooks::virtual_protect(const c_emulator_ctx *ctx) {
    const auto address = ctx->get_arg(0);
    const auto size = static_cast<uint32_t>(ctx->get_arg(1));
    const auto new_prot = static_cast<uint32_t>(ctx->get_arg(2));
    const auto old_prot_ptr = ctx->get_arg(3);

    handle_virtual_protection(ctx, address, size, new_prot, old_prot_ptr);
    ctx->set_result(1);
}

void hooks::raise_exception(c_emulator_ctx *ctx) {
    const auto exception_code = static_cast<uint32_t>(ctx->get_arg(0));

    std::cout << "[unthemidator][runtime] raised exception for VEH: 0x" <<
        std::hex << exception_code << std::dec << std::endl;

    ctx->raise_exception(exception_code);
}

void hooks::map_view_of_file(c_emulator_ctx *ctx) {
    const auto handle = ctx->get_arg(0);
    const auto mapping = ctx->get_file_handle(handle, true);
    const auto access = static_cast<uint32_t>(ctx->get_arg(1));
    const auto bytes = ctx->get_arg(4);

    const auto offset = (static_cast<uint64_t>(static_cast<uint32_t>(ctx->get_arg(2))) << 32) |
        static_cast<uint32_t>(ctx->get_arg(3));

    if (!handle || offset & 0xFFFF) {
        write_last_error(ctx, !handle ? 6 : 1132);
        ctx->set_result(0);
        return;
    }

    const bool writable = !mapping || mapping->m_protection == 4 || mapping->m_protection == 0x40;
    const bool executable = !mapping || mapping->m_protection >= 0x20;

    if ((access & 2 && !writable) || (access & 0x20 && !executable)) {
        write_last_error(ctx, 5);

        ctx->set_result(0);
        return;
    }

    const auto &file = mapping ? *mapping->m_data : ctx->get_original_file_mapping();
    const auto file_size = mapping ? mapping->m_size : file.size();

    const auto [base, size, status] = map_file_view(ctx, file, file_size, offset, bytes);

    if (status) {
        write_last_error(ctx, status == 0xC0000005 ? 998 : 87);

        ctx->set_result(0);
        return;
    }

    if (uc_mem_protect(ctx->get_uc(), base, size, UC_PROT_READ | (access & 3 ? UC_PROT_WRITE : 0) |
        (access & 0x20 ? UC_PROT_EXEC : 0)) != UC_ERR_OK) {
        //
        ctx->free_storage(base);
        write_last_error(ctx, 998);

        ctx->set_result(0);
        return;
    }

    ctx->set_result(base);
}

void hooks::get_file_size(c_emulator_ctx *ctx) {
    const auto file_size_high_ptr = ctx->get_arg(1);

    const auto file = ctx->get_file_handle(ctx->get_arg(0), false);

    const auto file_size = file ? file->m_size : ctx->get_original_file_mapping().size();
    const auto file_size_low = static_cast<uint32_t>(file_size);

    if (const auto file_size_high = static_cast<uint32_t>(file_size >> 32); file_size_high_ptr &&
        !ctx->write<uint32_t>(file_size_high_ptr, file_size_high)) {
        //
        write_last_error(ctx, 998); // ERROR_NOACCESS
        ctx->set_result(0xFFFFFFFF);
        return;
    }

    if (file_size_low == UINT32_MAX) {
        write_last_error(ctx, 0); // Distinguish a valid size from INVALID_FILE_SIZE
    }

    ctx->set_result(file_size_low);
}

void hooks::get_token_information(c_emulator_ctx *ctx) {
    const auto required_size_ptr = ctx->get_arg(4);

    if (ctx->write<uint32_t>(required_size_ptr, 1)) {
        // ?
    }
}

void hooks::get_thread_context(c_emulator_ctx *ctx) {
    const auto ctx_ptr = ctx->get_arg(1);
    const bool is_x64 = ctx->get_arch() == e_architecture::k_amd64;

    const uint32_t flags_offset = is_x64 ? 0x30 : 0x00;

    if (const auto flags = ctx->read<uint32_t>(ctx_ptr + flags_offset);
        !flags || (*flags & 0x10) == 0) {
        //
        throw std::runtime_error("invalid context flags");
    }

    if (is_x64) {
        // Dr0-Dr3, Dr6, Dr7
        for (uint32_t offset = 0x48; offset <= 0x70; offset += 8) {
            if (!ctx->write<uint64_t>(ctx_ptr + offset, 0)) {
                ctx->set_result(0);
                return;
            }
        }
    } else {
        // Dr0-Dr3, Dr6, Dr7
        for (uint32_t offset = 0x04; offset <= 0x18; offset += 4) {
            if (!ctx->write<uint32_t>(ctx_ptr + offset, 0)) {
                ctx->set_result(0);
                return;
            }
        }
    }

    ctx->set_result(1);
}

void hooks::create_thread(const c_emulator_ctx *ctx) {
    ctx->get_themida_unpacker()->on_thread_create(ctx->get_arg(2), ctx->get_arg(3));
    ctx->set_result(k_created_thread_handle);
}

void hooks::message_box_ex_w(const c_emulator_ctx *ctx) {
    const auto title_ptr = ctx->get_arg(2);
    const auto text_ptr = ctx->get_arg(1);

    char16_t title_buffer[256]{}, text_buffer[512]{};

    if (title_ptr && uc_mem_read(ctx->get_uc(), title_ptr, title_buffer,
        sizeof(title_buffer) - sizeof(char16_t)) != UC_ERR_OK) {
        //
        throw std::runtime_error("MessageBoxExW: failed to read title");
    }

    if (text_ptr && uc_mem_read(ctx->get_uc(), text_ptr, text_buffer,
        sizeof(text_buffer) - sizeof(char16_t)) != UC_ERR_OK) {
        //
        throw std::runtime_error("MessageBoxExW: failed to read text");
    }

    const auto title_length = std::char_traits<char16_t>::length(title_buffer);
    const auto text_length = std::char_traits<char16_t>::length(text_buffer);

    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;

    const auto title = converter.to_bytes(title_buffer, title_buffer + title_length);
    const auto text = converter.to_bytes(text_buffer, text_buffer + text_length);

    printf("message box: %s\n\n%s\n", title.c_str(), text.c_str());

    throw std::runtime_error("enough...");
}

void hooks::message_box_ex_a(const c_emulator_ctx *ctx) {
    const auto title_ptr = ctx->get_arg(2);
    const auto text_ptr = ctx->get_arg(1);

    char title_buffer[256]{}, text_buffer[512]{};

    if (title_ptr && uc_mem_read(ctx->get_uc(), title_ptr, title_buffer,
        sizeof(title_buffer) - sizeof(char16_t)) != UC_ERR_OK) {
        //
        throw std::runtime_error("MessageBoxExA: failed to read title");
    }

    if (text_ptr && uc_mem_read(ctx->get_uc(), text_ptr, text_buffer,
        sizeof(text_buffer) - sizeof(char16_t)) != UC_ERR_OK) {
        //
        throw std::runtime_error("MessageBoxExA: failed to read text");
    }

    const auto title = std::string(title_buffer);
    const auto text = std::string(text_buffer);

    printf("message box: %s\n\n%s\n", title.c_str(), text.c_str());

    throw std::runtime_error("enough...");
}

void hooks::nt_query_information_process(c_emulator_ctx *ctx) {
    const auto proc_info_class = static_cast<uint32_t>(ctx->get_arg(1));
    const auto proc_info_buffer = ctx->get_arg(2);
    const auto proc_info_length = static_cast<uint32_t>(ctx->get_arg(3));

    uint32_t nt_status = 0;

    switch (proc_info_class) {
        case 7: {
            // query debug port
            std::cout << "[unthemidator][runtime] bypassed DebugPort (NtQueryProcessInformation) debugger check" << std::endl;

            if (proc_info_length != (ctx->get_arch() == e_architecture::k_x86 ? 4 : 8)) {
                nt_status = 0xC0000004; // STATUS_INFO_LENGTH_MISMATCH
                break;
            }

            if (!(ctx->get_arch() == e_architecture::k_x86 ? ctx->write<uint32_t>(proc_info_buffer, 0) :
                ctx->write<uint64_t>(proc_info_buffer, 0))) {
                nt_status = 0xC0000005; // STATUS_ACCESS_VIOLATION
            }

            break;
        }

        case 30: {
            // query debug object handle
            std::cout << "[unthemidator][runtime] bypassed DebugObject (NtQueryProcessInformation) debugger check" << std::endl;

            if (proc_info_length != (ctx->get_arch() == e_architecture::k_x86 ? 4 : 8)) {
                nt_status = 0xC0000004; // STATUS_INFO_LENGTH_MISMATCH
                break;
            }

            nt_status = 0xC0000353; // STATUS_PORT_NOT_SET

            if (!(ctx->get_arch() == e_architecture::k_x86 ? ctx->write<uint32_t>(proc_info_buffer, 0) :
                ctx->write<uint64_t>(proc_info_buffer, 0))) {
                nt_status = 0xC0000005; // STATUS_ACCESS_VIOLATION
            }

            break;
        }

        default:
            throw std::runtime_error("NtQueryInformationProcess: unsupported proc_info class");
    }

    ctx->set_result(nt_status);
}

void hooks::nt_query_system_information(const c_emulator_ctx *ctx) {
    const auto sys_info_class = static_cast<uint32_t>(ctx->get_arg(0));
    const auto sys_info_buffer = ctx->get_arg(1);
    const auto sys_info_length = static_cast<uint32_t>(ctx->get_arg(2));
    const auto return_length_buffer = ctx->get_arg(3);

    uint32_t nt_status = 0;

    if (sys_info_class == 11) {
        // SystemModuleInformation
        const auto query_modules = [&]<typename T>() {
            struct s_module_list {
                uint32_t number_of_modules;

                struct {
                    T section, mapped_base, image_base;
                    uint32_t image_size, flags;
                    uint16_t load_order_index, init_order_index, load_count, offset_to_file_name;
                    uint8_t full_path_name[256];
                } modules[1];
            };

            s_module_list info{};
            info.number_of_modules = 1;

            auto &module = info.modules[0];

            constexpr char module_path[] = R"(\SystemRoot\system32\ntoskrnl.exe)";
            [[maybe_unused]] constexpr char module_name[] = "ntoskrnl.exe";

            module.image_base = static_cast<T>(sizeof(T) == 4 ? 0x80400000ULL : 0xFFFFF80000000000ULL);
            module.image_size = 0x1000000;
            module.load_order_index = 0;
            module.init_order_index = 0;
            module.load_count = 1;
            module.offset_to_file_name = sizeof(module_path) - sizeof(module_name);

            memcpy(module.full_path_name, module_path, sizeof(module_path));

            constexpr uint32_t required_length = sizeof(info);

            if (return_length_buffer) {
                if (uc_mem_write(ctx->get_uc(), return_length_buffer, &required_length,
                    sizeof(required_length)) != UC_ERR_OK) {
                    //
                    nt_status = 0xC0000005; // STATUS_ACCESS_VIOLATION
                }
            }

            if (sys_info_length < required_length) {
                nt_status = 0xC0000004; // STATUS_INFO_LENGTH_MISMATCH
            }

            if (uc_mem_write(ctx->get_uc(), sys_info_buffer, &info, sizeof(info)) != UC_ERR_OK) {
                nt_status = 0xC0000005; // STATUS_ACCESS_VIOLATION
            }
        };

        if (ctx->get_arch() == e_architecture::k_x86) {
            query_modules.operator()<uint32_t>();
        } else {
            query_modules.operator()<uint64_t>();
        }
    } else {
        throw std::runtime_error("NtQuerySystemInformation: unsupported sys_info class");
    }

    ctx->set_result(nt_status);
}

void hooks::nt_protect_virtual_memory(const c_emulator_ctx *ctx) {
    const auto uc = ctx->get_uc();

    const auto base_address_ptr = ctx->get_arg(1);
    const auto region_size_ptr = ctx->get_arg(2);
    const auto new_prot = static_cast<uint32_t>(ctx->get_arg(3));

    const auto ptr_size = ctx->get_arch() == e_architecture::k_x86 ? 4 : 8;

    uint64_t address = 0;
    uint64_t size = 0;
    const auto old_prot_ptr = ctx->get_arg(4);

    if (uc_mem_read(uc, base_address_ptr, &address, ptr_size) != UC_ERR_OK ||
        uc_mem_read(uc, region_size_ptr, &size, ptr_size) != UC_ERR_OK) {
        //
        ctx->set_result(0xC0000005);
        return;
    }

    handle_virtual_protection(ctx, address, static_cast<uint32_t>(size), new_prot, old_prot_ptr);
    ctx->set_result(0);
}

void hooks::nt_query_object(c_emulator_ctx *ctx) {
    if (static_cast<uint32_t>(ctx->get_arg(1)) != 0) {
        // ObjectBasicInformation
        throw std::runtime_error("NtQueryObject: unsupported information class");
    }

    if (ctx->get_arg(0) != k_created_thread_handle) {
        ctx->set_result(0xC0000008); // STATUS_INVALID_HANDLE
        return;
    }

    // PUBLIC_OBJECT_BASIC_INFORMATION has the same layout on x86 and x64
    struct s_object_basic_information {
        uint32_t attributes, granted_access, handle_count, pointer_count;
        uint32_t reserved[10];
    };

    static_assert(sizeof(s_object_basic_information) == 0x38);

    constexpr s_object_basic_information info{
        .attributes = 0,
        .granted_access = 0x001FFFFF, // THREAD_ALL_ACCESS
        .handle_count = 1,
        .pointer_count = 2,
        .reserved = {}
    };

    if (const auto return_length = ctx->get_arg(4);
        return_length && !ctx->write<uint32_t>(return_length, sizeof(info))) {
        //
        ctx->set_result(0xC0000005); // STATUS_ACCESS_VIOLATION
        return;
    }

    if (static_cast<uint32_t>(ctx->get_arg(3)) < sizeof(info)) {
        ctx->set_result(0xC0000004); // STATUS_INFO_LENGTH_MISMATCH
        return;
    }

    if (const auto buffer = ctx->get_arg(2);
        !buffer || !ctx->write(buffer, info)) {
        //
        ctx->set_result(0xC0000005); // STATUS_ACCESS_VIOLATION
        return;
    }

    ctx->set_result(0);
}

void hooks::check_remote_debugger(c_emulator_ctx *ctx) {
    if (ctx->write<uint32_t>(ctx->get_arg(1), 0)) {
        std::cout << "[unthemidator][runtime] bypassed remote debugger check" << std::endl;
        ctx->set_result(1);
    } else {
        ctx->set_result(0);
    }
}

void hooks::is_wow64_process(c_emulator_ctx *ctx) {
    ctx->set_result(ctx->write<uint32_t>(ctx->get_arg(1), 0) ? 1 : 0);
}

void hooks::is_wow64_process2(c_emulator_ctx *ctx) {
    const auto process_machine_ptr = ctx->get_arg(1);
    const auto native_machine_ptr = ctx->get_arg(2);

    // The synthetic host is AMD64; native processes report IMAGE_FILE_MACHINE_UNKNOWN
    const uint16_t process_machine = ctx->get_arch() == e_architecture::k_x86 ? 0x014C : 0;

    if (constexpr uint16_t native_machine = 0x8664; !process_machine_ptr ||
        !ctx->write<uint16_t>(process_machine_ptr, process_machine) || (native_machine_ptr &&
            !ctx->write<uint16_t>(native_machine_ptr, native_machine))) {
        //
        write_last_error(ctx, 998); // ERROR_NOACCESS.

        ctx->set_result(0);
        return;
    }

    ctx->set_result(1);
}

void hooks::get_current_process_id(const c_emulator_ctx *ctx) {
    ctx->set_result(ctx->read<uint32_t>(teb_field(ctx, 0x20, 0x40)).value());
}

void hooks::get_current_thread_id(const c_emulator_ctx *ctx) {
    ctx->set_result(ctx->read<uint32_t>(teb_field(ctx, 0x24, 0x48)).value());
}

void hooks::get_last_error(const c_emulator_ctx *ctx) {
    ctx->set_result(ctx->read<uint32_t>(teb_field(ctx, 0x34, 0x68)).value());
}

void hooks::set_last_error(c_emulator_ctx *ctx) {
    write_last_error(ctx, static_cast<uint32_t>(ctx->get_arg(0)));
}

void hooks::create_toolhelp_snapshot(c_emulator_ctx *ctx) {
    const auto flags = static_cast<uint32_t>(ctx->get_arg(0));
    if (!(flags & 0x1F) || (flags & ~0x8000001FU)) {
        write_last_error(ctx, 87);
        ctx->set_result(UINT64_MAX);
        return;
    }

    const auto process_id = ctx->read<uint32_t>(teb_field(ctx, 0x20, 0x40)).value();
    ctx->set_result(ctx->create_process_snapshot(flags, process_id));
}

void hooks::close_handle(c_emulator_ctx *ctx) {
    const auto success = ctx->close_file_handle(ctx->get_arg(0)) ||
        ctx->close_process_snapshot(ctx->get_arg(0)) || ctx->get_arg(0) == 1;

    if (!success) {
        write_last_error(ctx, 6);
    }

    ctx->set_result(success ? 1 : 0);
}

void hooks::process_first(c_emulator_ctx *ctx) {
    if (ctx->get_arch() == e_architecture::k_x86) {
        write_process_entry<uint32_t, char>(ctx, true);
    } else {
        write_process_entry<uint64_t, char>(ctx, true);
    }
}

void hooks::process_first_w(c_emulator_ctx *ctx) {
    if (ctx->get_arch() == e_architecture::k_x86) {
        write_process_entry<uint32_t, char16_t>(ctx, true);
    } else {
        write_process_entry<uint64_t, char16_t>(ctx, true);
    }
}

void hooks::process_next(c_emulator_ctx *ctx) {
    if (ctx->get_arch() == e_architecture::k_x86) {
        write_process_entry<uint32_t, char>(ctx, false);
    } else {
        write_process_entry<uint64_t, char>(ctx, false);
    }
}

void hooks::process_next_w(c_emulator_ctx *ctx) {
    if (ctx->get_arch() == e_architecture::k_x86) {
        write_process_entry<uint32_t, char16_t>(ctx, false);
    } else {
        write_process_entry<uint64_t, char16_t>(ctx, false);
    }
}

void hooks::dummy_function(const c_emulator_ctx *ctx) {
    ctx->set_result(0);
}

void hooks::dummy_true_function(const c_emulator_ctx *ctx) {
    // return true (can also be a handle :thumbsup:)
    ctx->set_result(1);
}

void hooks::vm_enter(const c_emulator_ctx *ctx) {
    const auto vm_enter_address = ctx->get_pc();

    ctx->get_themida_unpacker()->on_original_pe_callback(vm_enter_address);
}
