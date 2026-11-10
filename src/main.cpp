#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <chrono>
#include <charconv>
#include <filesystem>

#include "emulator/hooks.hpp"
#include "helpers/utils.hpp"
#include "helpers/json.hpp"
#include "unpacker/c_themida_unpacker.hpp"
#include "pe/c_pe_builder.hpp"

int main(int argc, char *argv[]) {
    struct s_cli_options : s_unpacker_options {
        std::string m_output_path;
        std::string m_imports_path;
        std::string m_vms_path;
        std::string m_license_path;
        bool m_skip_startup = false;
    } options{};

    std::string input_path;
    std::vector<uint8_t> license_file{};

    try {
        bool positional_only = false;
        bool has_input = false;

        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];

            if (!positional_only && (arg == "--help" || arg == "-h")) {
                std::cout << "Usage: unthemidator [options] <path_to_binary>\n"
                    "  --out-file <path>      Output PE (default: <name>.unpacked.<extension>)\n"
                    "  --imports-file <path> Imports JSON (default: <name>.imports.json)\n"
                    "  --vms-file <path>     VM entries JSON (default: <name>.vms.json)\n"
                    "  --license-file <path> WinLicense protected application's license file (usually .dat)\n"
                    "  --vm-depth <0..65535> Virtualization layers to explore (default: 0)\n"
                    "  --no-imp             Skip imports lookup\n"
                    "  --no-startup         Only unpack the initial boot stage\n"
                    "  --no-vm-lookup       Skip virtual machines lookup\n"
                    "  --no-loader          Skip fixer loader generation\n";
                return 0;
            }

            if (!positional_only && arg == "--") {
                positional_only = true;
                continue;
            }

            if (!positional_only && (arg == "--out-file" || arg == "--imports-file" || arg == "--vms-file" ||
                arg == "--vm-depth" || arg == "--license-file")) {
                if (++i == argc || !argv[i][0] || std::string_view(argv[i]).starts_with("--")) {
                    throw std::runtime_error("missing value for " + arg);
                }

                const std::string value = argv[i];

                if (arg == "--out-file") {
                    options.m_output_path = value;
                } else if (arg == "--imports-file") {
                    options.m_imports_path = value;
                } else if (arg == "--vms-file") {
                    options.m_vms_path = value;
                } else if (arg == "--license-file") {
                    options.m_license_path = value;
                } else {
                    uint16_t depth = 0;

                    if (const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), depth);
                        error != std::errc{} || end != value.data() + value.size()) {
                        //
                        throw std::runtime_error("--vm-depth must be an integer from 0 to 65535");
                    }

                    options.m_max_nested_vms = depth;
                }
            } else if (!positional_only && arg == "--no-imp") {
                options.m_skip_imports = true;
            } else if (!positional_only && arg == "--no-startup") {
                options.m_skip_startup = true;
            } else if (!positional_only && arg == "--no-vm-lookup") {
                options.m_skip_vm_lookup = true;
            } else if (!positional_only && arg == "--no-loader") {
                options.m_skip_loader = true;
            } else if (!positional_only && arg.starts_with('-')) {
                throw std::runtime_error("unknown option: " + arg);
            } else {
                if (has_input || arg.empty()) {
                    throw std::runtime_error("expected one input binary");
                }

                input_path = arg;
                has_input = true;
            }
        }

        if (!has_input) {
            throw std::runtime_error("input binary is required: unthemidator [options] <path_to_binary>");
        }

        const std::filesystem::path input(input_path);
        const auto stem = input.parent_path() / input.stem();

        if (options.m_output_path.empty()) {
            options.m_output_path = stem.string() + ".unpacked" + input.extension().string();
        }

        if (options.m_imports_path.empty()) {
            options.m_imports_path = stem.string() + ".imports.json";
        }

        if (options.m_vms_path.empty()) {
            options.m_vms_path = stem.string() + ".vms.json";
        }

        std::vector<std::filesystem::path> paths{
            input,
            options.m_output_path,
            options.m_imports_path,
            options.m_vms_path,
        };

        if (!options.m_license_path.empty()) {
            paths.emplace_back(options.m_license_path);
        }

        for (size_t i = 0; i < paths.size(); ++i) {
            for (size_t j = 0; j < i; ++j) {
                if (std::filesystem::weakly_canonical(paths[i]) == std::filesystem::weakly_canonical(paths[j]) ||
                    (std::filesystem::exists(paths[i]) && std::filesystem::exists(paths[j]) &&
                    std::filesystem::equivalent(paths[i], paths[j]))) {
                    throw std::runtime_error("input, license and output paths must be distinct");
                }
            }
        }

        if (!options.m_license_path.empty()) {
            if (!std::filesystem::is_regular_file(options.m_license_path)) {
                throw std::runtime_error("license file is not a regular file: " + options.m_license_path);
            }

            std::ifstream license(options.m_license_path, std::ios::binary | std::ios::ate);
            const auto size = license.tellg();

            if (!license || size < 0 || static_cast<uint64_t>(size) > UINT32_MAX - 0xFFF) {
                throw std::runtime_error("failed to read license file: " + options.m_license_path);
            }

            license_file.resize(size);
            license.seekg(0);

            if (!license_file.empty() && !license.read(reinterpret_cast<char*>(license_file.data()), size)) {
                throw std::runtime_error("failed to read license file: " + options.m_license_path);
            }
        }
    } catch (const std::exception &e) {
        std::cerr << "[unthemidator] " << e.what() << std::endl;
        return 1;
    }

    const auto &output_path = options.m_output_path;

    std::cout << "[unthemidator] loading pe file..." << std::endl;
    std::cout << "[unthemidator] input file: " << input_path << std::endl;
    std::cout << "[unthemidator] output file: " << output_path << std::endl;

    auto raw = utils::read_file(input_path);

    if (raw.empty()) {
        std::cerr << "failed to read file" << std::endl;
        return 1;
    }

    std::shared_ptr<c_pe_image> pe_image;
    std::shared_ptr<c_emulator> emulator;
    std::shared_ptr<c_emulator_ctx> emulator_ctx;

    std::cout << "[pe] parsing PE file..." << std::endl;

    auto start = std::chrono::high_resolution_clock::now();

    try {
        pe_image = std::make_shared<c_pe_image>(raw);
    } catch (std::runtime_error& e) {
        std::cerr << "[pe] failed to parse: " << e.what() << std::endl;
        return 1;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << "[pe] successfully parsed PE file in " << duration << " ms" << std::endl;
    std::cout << "  [pe] image base: 0x" << std::hex << pe_image->get_image_base() << std::dec << std::endl;
    std::cout << "  [pe] entry point: 0x" << std::hex << pe_image->get_image_base() + pe_image->get_entry_rva() << std::dec << std::endl;
    std::cout << "  [pe] binary type: " << (pe_image->is_x64() ? "AMD64 (x86_64, 64-bit)" : "x86 (32-bit)") << std::endl;

    auto memory_manager = std::make_shared<c_memory_manager>(pe_image);

    std::cout << "[emulator] setting up..." << std::endl;

    start = std::chrono::high_resolution_clock::now();

    // setup unicorn
    try {
        emulator = std::make_shared<c_emulator>(
            pe_image->is_x64() ? e_architecture::k_amd64 : e_architecture::k_x86,
            input_path.ends_with(".sys") ? e_platform::k_windows_driver : e_platform::k_windows,
            memory_manager);

        emulator_ctx = emulator->create_context();
        emulator_ctx->set_file_sources(input_path, options.m_license_path, std::move(license_file));

        // preload modules APIs of which we hook
        emulator_ctx->get_imports()->load_module("ntdll.dll");
        emulator_ctx->get_imports()->load_module("kernel32.dll");
        emulator_ctx->get_imports()->load_module("user32.dll");
        emulator_ctx->get_imports()->load_module("advapi32.dll");
        emulator_ctx->get_imports()->load_module("shell.dll");

        // create API hooks
        using api_hook_t = std::pair<std::function<void(c_emulator_ctx*)>, uint32_t>;
        std::unordered_map<std::string, std::unordered_map<std::string, api_hook_t>> api_hooks = {
            {
                "kernel32.dll",
                {
                    { "GetModuleHandleA", { hooks::get_module_handle, 1 } },
                    { "GetModuleHandleW", { hooks::get_module_handle, 1 } },
                    { "LoadLibraryA", { hooks::get_module_handle, 1 } },
                    { "LoadLibraryW", { hooks::get_module_handle, 1 } },
                    { "GetProcAddress", { hooks::get_proc_address, 2 } },
                    { "GetCommandLineA", { hooks::get_command_line_a, 0 } },
                    { "GetCommandLineW", { hooks::get_command_line_w, 0 } },
                    { "GetVersion", { hooks::get_version, 0 } },
                    { "VirtualAlloc", { hooks::virtual_alloc, 4 } },
                    { "GetCurrentDirectoryW", { hooks::get_current_dir, 2 } },
                    { "MultiByteToWideChar", { hooks::dummy_function, 6 } },
                    { "WideCharToMultiByte", { hooks::dummy_function, 8 } },
                    { "GetVolumeInformationA", { hooks::get_volume_information_a, 8 } },
                    { "GetLocalTime", { hooks::get_local_time, 1 } },
                    { "SystemTimeToFileTime", { hooks::system_time_to_file_time, 2 } },
                    { "GetModuleFileNameW", { hooks::get_module_filename, 3 } },
                    { "VirtualProtect", { hooks::virtual_protect, 4 } },
                    { "RaiseException", { hooks::raise_exception, 4 } },
                    { "CheckRemoteDebuggerPresent", { hooks::check_remote_debugger, 2 } },
                    { "IsWow64Process", { hooks::is_wow64_process, 2 } },
                    { "IsWow64Process2", { hooks::is_wow64_process2, 3 } },
                    { "GetFileAttributesExA", { hooks::get_file_attributes_ex, 3 } },
                    { "GetFileAttributesExW", { hooks::get_file_attributes_ex, 3 } },
                    { "GetFileSize", { hooks::get_file_size, 2 } },
                    { "MapViewOfFile", { hooks::map_view_of_file, 5 } },
                    { "LocalAlloc", { hooks::local_alloc, 2 } },
                    { "CreateThread", { hooks::create_thread, 6 } },

                    { "CreateFileW", { hooks::create_file_w, 7 } },
                    { "CreateFileMappingW", { hooks::create_file_mapping, 6 } },
                    { "CreateFileMappingA", { hooks::create_file_mapping, 6 } },
                    { "UnmapViewOfFile", { hooks::dummy_true_function, 1 } },
                    { "GetUserDefaultUILanguage", { hooks::dummy_function, 0 } },
                    { "GetThreadContext", { hooks::get_thread_context, 2 } },
                    { "IsBadWritePtr", { hooks::dummy_function, 2 } },
                    { "IsBadReadPtr", { hooks::dummy_true_function, 2 } },
                    { "GetProcessHeap", { hooks::dummy_true_function, 0 } },
                    { "OpenThreadToken", { hooks::dummy_true_function, 4 } },
                    { "SetCurrentDirectoryW", { hooks::dummy_true_function, 1 } },
                    { "GetCurrentProcess", { hooks::dummy_true_function, 0 } },
                    { "CloseHandle", { hooks::close_handle, 1 } },
                    { "GetCurrentProcessId", { hooks::get_current_process_id, 0 } },
                    { "GetCurrentThreadId", { hooks::get_current_thread_id, 0 } },
                    { "GetLastError", { hooks::get_last_error, 0 } },
                    { "SetLastError", { hooks::set_last_error, 1 } },
                    { "GetCurrentThread", { hooks::dummy_true_function, 0 } },
                    { "OpenThread", { hooks::dummy_true_function, 3 } },
                    { "VirtualFree", { hooks::virtual_free, 3 } },
                    { "CreateToolhelp32Snapshot", { hooks::create_toolhelp_snapshot, 2 } },
                    { "Process32First", { hooks::process_first, 2 } },
                    { "Process32FirstW", { hooks::process_first_w, 2 } },
                    { "Process32Next", { hooks::process_next, 2 } },
                    { "Process32NextW", { hooks::process_next_w, 2 } },
                    { "lstrcmpiA", { hooks::dummy_true_function, 2 } },
                    { "GetSystemFirmwareTable", { hooks::dummy_function, 4 } },
                    { "SetEnvironmentVariableA", { hooks::dummy_function, 2 } },
                    { "SetEnvironmentVariableW", { hooks::dummy_function, 2 } },
                    { "Sleep", { hooks::dummy_function, 0 } },
                    { "FreeLibrary", { hooks::dummy_function, 1 } },
                    { "CreateFileA", { hooks::create_file_a, 7 } },
                    { "DeviceIoControl", { hooks::dummy_function, 8 } },
                    { "GetEnvironmentVariableA", { hooks::dummy_function, 3 } },
                    { "GetEnvironmentVariableW", { hooks::dummy_function, 3 } },
                    { "WriteFile", { hooks::dummy_true_function, 5 } },
                    { "ReadFile", { hooks::read_file, 5 } },
                    { "DeleteFileA", { hooks::dummy_true_function, 1 } },
                    { "DeleteFileW", { hooks::dummy_true_function, 1 } },
                    { "InitializeSListHead", { hooks::dummy_function, 1 } },
                }
            },
            {
                "ntdll.dll",
                {
                    { "RtlAllocateHeap", { hooks::rtl_allocate_heap, 3 } },
                    { "RtlReAllocateHeap", { hooks::rtl_reallocate_heap, 4 } },
                    { "RtlAddVectoredExceptionHandler", { hooks::add_veh, 2 } },
                    { "RtlRemoveVectoredExceptionHandler", { hooks::remove_veh, 1 } },
                    { "ZwQueryInformationProcess", { hooks::nt_query_information_process, 5 } },
                    { "NtQueryInformationProcess", { hooks::nt_query_information_process, 5 } },
                    { "ZwQuerySystemInformation", { hooks::nt_query_system_information, 4 } },
                    { "NtQuerySystemInformation", { hooks::nt_query_system_information, 4 } },
                    { "ZwProtectVirtualMemory", { hooks::nt_protect_virtual_memory, 5 } },
                    { "NtProtectVirtualMemory", { hooks::nt_protect_virtual_memory, 5 } },
                    { "NtQueryObject", { hooks::nt_query_object, 5 } },
                    { "ZwQueryObject", { hooks::nt_query_object, 5 } },
                    { "NtMapViewOfSection", { hooks::dummy_true_function, 10 } },
                    { "ZwMapViewOfSection", { hooks::dummy_true_function, 10 } },

                    { "RtlInitializeCriticalSection", { hooks::dummy_function, 1 } },
                    { "ZwSetInformationThread", { hooks::dummy_function, 4 } },
                    { "NtSetInformationThread", { hooks::dummy_function, 4 } },
                    { "RtlFreeHeap", { hooks::rtl_free_heap, 3 } },
                    { "ZwFlushInstructionCache", { hooks::dummy_function, 3 } },
                    { "NtFlushInstructionCache", { hooks::dummy_function, 3 } },
                    { "NtOpenSection", { hooks::dummy_function, 3 } },
                    { "ZwOpenSection", { hooks::dummy_function, 3 } },
                    { "NtClose", { hooks::dummy_function, 1 } },
                    { "ZwClose", { hooks::dummy_function, 1 } },
                }
            },
            {
                "user32.dll",
                {
                    { "MessageBoxExW", { hooks::message_box_ex_w, 5 } }, // never called unless there's an error
                    { "MessageBoxExA", { hooks::message_box_ex_w, 5 } }, // never called unless there's an error

                    { "FindWindowA", { hooks::dummy_function, 2 } },
                    { "GetWindowTextA", { hooks::dummy_function, 3 } },
                    { "GetForegroundWindow", { hooks::dummy_true_function, 0 } },
                    { "wsprintfA", { hooks::dummy_function, 2 } },
                    { "wsprintfW", { hooks::dummy_function, 2 } },
                }
            },
            {
                "advapi32.dll",
                {
                    { "GetTokenInformation", { hooks::get_token_information, 5 } },
                    { "OpenThreadToken", { hooks::dummy_true_function, 4 } },
                    { "RegOpenKeyA", { hooks::dummy_true_function, 3 } },
                    { "RegOpenKeyW", { hooks::dummy_true_function, 3 } },
                    { "RegCreateKeyExA", { hooks::dummy_true_function, 9 } },
                    { "RegCreateKeyExW", { hooks::dummy_true_function, 9 } },
                    { "RegSetValueExA", { hooks::dummy_true_function, 6 } },
                    { "RegSetValueExW", { hooks::dummy_true_function, 6 } },
                    { "RegQueryValueExA", { hooks::dummy_true_function, 6 } },
                    { "RegCloseKey", { hooks::dummy_function, 1 } },
                    { "AllocateAndInitializeSid", { hooks::dummy_true_function, 11 } },
                    { "FreeSid", { hooks::dummy_true_function, 1 } },
                    { "SetEntriesInAclA", { hooks::dummy_true_function, 4 } },
                    { "SetEntriesInAclW", { hooks::dummy_true_function, 4 } },
                    { "InitializeSecurityDescriptor", { hooks::dummy_true_function, 2 } },
                    { "SetSecurityDescriptorDacl", { hooks::dummy_true_function, 4 } },
                }
            },
            {
                "iphlpapi.dll",
                {
                    { "GetAdaptersInfo", { hooks::get_adapters_info, 2 } },
                }
            },
            {
                "shell32.dll",
                {
                    { "SHGetSpecialFolderPathW", { hooks::sh_get_special_folder_path_w, 4 } },
                    { "IsUserAnAdmin", { hooks::dummy_function, 0 } },
                    { "SHGetSpecialFolderPathW", { hooks::dummy_function, 4 } },
                }
            },
            {
                "Iphlpapi.dll",
                {
                    { "GetAdaptersInfo", { hooks::dummy_true_function, 2 } },
                }
            }
        };

        // setup hooks
        for (const auto &[mod_name, hooked_apis] : api_hooks) {
            const auto module_base = emulator_ctx->get_imports()->load_module(mod_name);

            for (const auto &[fn_name, hook_fn] : hooked_apis) {
                const auto fn_addr = emulator_ctx->get_imports()->resolve_import(module_base, fn_name);

                if (!fn_addr) {
                    throw std::runtime_error("failed to find export to hook");
                }

                emulator_ctx->add_hook(fn_addr, fn_name, hook_fn.first, hook_fn.second);
                memory_manager->tag_region(fn_addr, fn_name);
            }
        }

        // resolve imports
        for (const auto &[mod_name, functions] : pe_image->get_imports()) {
            const auto module_base = emulator_ctx->get_imports()->load_module(mod_name);

            for (const auto &[fn_name, iat_entry_orig_va] : functions) {
                const auto fn_addr = emulator_ctx->get_imports()->resolve_import(module_base, fn_name);

                std::vector<uint8_t> iat_entry(pe_image->get_ptr_size(), 0);

                if (pe_image->is_x64()) {
                    *reinterpret_cast<uint64_t*>(iat_entry.data()) = fn_addr;
                } else {
                    *reinterpret_cast<uint32_t*>(iat_entry.data()) = static_cast<uint32_t>(fn_addr);
                }

                const auto iat_entry_va = iat_entry_orig_va - pe_image->get_image_base() + memory_manager->get_image_base();

                memory_manager->write_memory(iat_entry_va, iat_entry);
                uc_mem_write(emulator_ctx->get_uc(), iat_entry_va, iat_entry.data(), iat_entry.size());
            }
        }
    } catch (std::runtime_error &e) {
        std::cerr << "[emulator] failed to setup emulator: " << e.what() << std::endl;
        return 1;
    }

    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << "[emulator] initialized emulator in " << duration << " ms" << std::endl << std::endl;

    // create unpacker instance
    const auto unpacker = std::make_shared<c_themida_unpacker>(options, pe_image, emulator_ctx, memory_manager);

    // decompress binary (if it's compressed)
    try {
       unpacker->decompress_bin();
    } catch (std::runtime_error &e) {
        std::cerr << "[unthemidator] failed to decompress binary: " << e.what() << std::endl;

        return 1; // decompression is a critical stage, if it fails, we can't proceed further
    }

    std::cout << std::endl;

    // startup Themida runtime (lightning VM entrypoint)
    try {
        if (!options.m_skip_startup) {
            unpacker->startup();
        }
    } catch (std::runtime_error &e) {
        std::cerr << "[unthemidator] failed to startup: " << e.what() << std::endl;

        return 1; // startup is a critical stage, if it fails, we can't proceed further
    }

    std::cout << std::endl;

    // find all Themida entry points and decompress the VMs (if applicable)
    try {
        if (!options.m_skip_startup && !options.m_skip_vm_lookup) {
            unpacker->decompress_vms();
        }
    } catch (std::runtime_error &e) {
        std::cerr << "[unthemidator] failed to decompress VMs: " << e.what() << std::endl;
    }

    std::cout << std::endl;

    start = std::chrono::high_resolution_clock::now();

    // rebuild unpacked PE file
    const auto pe_builder = std::make_shared<c_pe_builder>(pe_image, memory_manager);

    pe_builder->set_entry_rva(unpacker->get_oep_rva());
    pe_builder->set_imports(unpacker->get_recovered_imports());
    pe_builder->set_tls_callbacks(unpacker->get_tls_callbacks());

    if (!options.m_skip_loader) {
        pe_builder->set_loader_shellcode(unpacker->get_loader_shellcode());
    }

    try {
        pe_builder->build(*emulator_ctx);

        // save rebuilt PE file
        const auto &bin = pe_builder->get_built_pe();

        std::ofstream output_file(output_path, std::ios::binary);
        output_file.exceptions(std::ios::failbit | std::ios::badbit);
        output_file.write(reinterpret_cast<const char*>(bin.data()), static_cast<long long>(bin.size()));
        output_file.close();

        auto imports = nlohmann::json::array();
        auto vms = nlohmann::json::array();

        for (const auto &entry : unpacker->get_recovered_imports()) {
            imports.push_back({
                { "iat_rva", entry.m_iat_rva },
                { "module", entry.m_module },
                { "function", entry.m_function },
                { "is_ordinal", entry.m_is_ordinal },
                { "ordinal", entry.m_ordinal },
            });
        }

        for (const auto &entry : unpacker->get_vm_trampolines()) {
            vms.push_back({
                { "trampoline_address", entry.m_trampoline_address },
                { "vm_enter_address", entry.m_vm_enter_address },
                { "is_packed", entry.m_is_packed },
            });
        }

        for (const auto &[path, report] : {
            std::pair{ options.m_imports_path, &imports }, std::pair{ options.m_vms_path, &vms } }) {
            //
            std::ofstream file(path);
            file.exceptions(std::ios::failbit | std::ios::badbit);
            file << report->dump(4) << '\n';
            file.close();
        }
    } catch (std::runtime_error &e) {
        std::cerr << "[unthemidator] failed to build PE file: " << e.what() << std::endl;

        return 1;
    }

    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << "[unthemidator] PE built in " << duration <<
        " ms, saved unpacked PE file: " << output_path << std::endl;

    std::cout << "[unthemidator] Detected Themida version: " << unpacker->get_themida_version() << std::endl;

    if (argc == 1) {
        std::cout << std::endl << "[unthemidator] press any key to exit..." << std::endl;
        std::cin.get();
    }

    return 0;
}
