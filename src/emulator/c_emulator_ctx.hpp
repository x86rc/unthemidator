#ifndef UNTHEMIDATOR_EMULATOR_CTX_HPP
#define UNTHEMIDATOR_EMULATOR_CTX_HPP

#include <unicorn/unicorn.h>
#include <functional>
#include <optional>
#include <unordered_set>
#include <memory>

#include "../helpers/common.hpp"
#include "../memory/c_memory.hpp"
#include "c_imports.hpp"

using code_callback_t = void(uc_engine *uc, uint64_t address, uint32_t size);
using mem_callback_t = void(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value);

class c_emulator;
class c_emulator_ctx;
class c_memory_manager;
class c_memory;
class c_themida_unpacker;

struct s_hooked_function {
    uint64_t m_address; // original address
    std::string m_name{}; // hook nametag
    std::function<void(c_emulator_ctx*)> m_function; // target function
    uint32_t m_arg_count = 0;
};

class c_emulator_ctx {
public:
    explicit c_emulator_ctx(c_emulator* emulator, uc_engine* uc, const std::shared_ptr<c_memory_manager>& memory_manager);
    ~c_emulator_ctx();

    [[nodiscard]] e_architecture get_arch() const;
    [[nodiscard]] uc_engine* get_uc() const;

    [[nodiscard]] std::shared_ptr<c_memory> get_memory() const;
    [[nodiscard]] std::shared_ptr<c_imports> get_imports() const;
    [[nodiscard]] const std::vector<uint8_t>& get_original_file_mapping() const;

    struct s_file_handle {
        const std::vector<uint8_t> *m_data = nullptr;
        uint64_t m_size = 0;
        uint32_t m_protection = 0;
        bool m_is_mapping = false;
    };

    void set_file_sources(const std::string &input_name, const std::string &license_name, std::vector<uint8_t> license);
    [[nodiscard]] const std::string &get_input_path() const { return m_input_path; }

    uint64_t open_file(const std::string &path);
    uint64_t create_file_mapping(uint64_t handle, uint64_t size, uint32_t protection);

    const s_file_handle* get_file_handle(uint64_t handle, bool mapping);
    bool close_file_handle(uint64_t handle);

    void set_themida_unpacker(c_themida_unpacker* unpacker);
    [[nodiscard]] c_themida_unpacker* get_themida_unpacker() const;

    [[nodiscard]] uint64_t get_x86_reg_value(uc_x86_reg reg) const;
    void set_x86_reg_value(uc_x86_reg reg, uint64_t value) const;

    [[nodiscard]] uint64_t get_arg(uint32_t index) const;
    void set_arg(uint32_t index, uint64_t value);
    void set_result(uint64_t value) const;

    void add_hook(uint64_t address, const std::string &name, const std::function<void(c_emulator_ctx*)> &hook, uint32_t arg_count = 0);
    void remove_hook(uint64_t address);

    void add_mem_hook(uc_hook_type hook_type, std::function<mem_callback_t> callback, uint64_t start_address, uint64_t end_address);
    void remove_mem_hook(uint64_t address);

    struct s_process_snapshot {
        uint32_t m_flags = 0, m_process_id = 0, m_index = 0;
    };

    uint64_t create_process_snapshot(uint32_t flags, uint32_t process_id);
    s_process_snapshot* get_process_snapshot(uint64_t handle);
    bool close_process_snapshot(uint64_t handle);

    void add_exception_handler(uint64_t address);
    void remove_exception_handler(uint64_t address);
    void raise_exception(uint32_t exception_code);
    void run_thread(uint64_t address, uint64_t end, uint64_t param);

    const s_hooked_function* get_hook(uint64_t address);

    [[nodiscard]] uint64_t map_dummy_module(const std::vector<uint8_t>& image, const std::string &name) const;

    template <typename T>
    [[nodiscard]] std::optional<T> read(const uint64_t address) const {
        static_assert(std::is_trivially_copyable_v<T>, "read<T> requires a trivially copyable type");

        T value{};
        if (c_memory::overlaps_shared_data(address, sizeof(T))) {
            (void)get_memory()->get_shared_data();
        }
        if (uc_mem_read(m_uc, address, &value, sizeof(T)) != UC_ERR_OK) {
            return std::nullopt;
        }

        return value;
    }

    template <typename T>
    [[nodiscard]] bool write(const uint64_t address, T value) {
        static_assert(std::is_trivially_copyable_v<T>, "write<T> requires a trivially copyable type");

        if (c_memory::overlaps_shared_data(address, sizeof(T))) {
            return false;
        }

        if (uc_mem_write(m_uc, address, &value, sizeof(T)) != UC_ERR_OK) {
            return false;
        }

        return true;
    }

    void single_step(std::function<mem_callback_t> on_mem = nullptr);

    void stop(uint64_t address);
    void return_from_call(uint32_t arg_count);

    [[nodiscard]] bool is_stopped() const { return m_stop_requested; }
    void set_stop_on_import(const bool enabled) { m_stop_on_import = enabled; }
    [[nodiscard]] bool stops_on_import() const { return m_stop_on_import; }

    void run(uint64_t start, uint64_t end = 0, std::function<code_callback_t> on_code = nullptr,
        std::function<mem_callback_t> on_mem = nullptr);

    [[nodiscard]] uint64_t get_pc() const;
    void set_pc(uint64_t new_pc) const;

    uint64_t allocate_storage(uint32_t size, const std::string &tag = {});
    uint64_t allocate_heap(uint64_t size);
    uint64_t reallocate_heap(uint64_t address, uint64_t size, uint32_t flags);

    bool free_storage(uint64_t address);
    bool free_heap(uint64_t address);
    uint64_t allocate_virtual(uint64_t address, uint64_t size, uint32_t type);
    bool free_virtual(uint64_t address, uint64_t size, uint32_t type);

    void initialize_windows_ldr() const;
private:
    struct s_heap_allocation {
        uint32_t m_size;
        uint32_t m_capacity;
    };

    std::unordered_map<uint64_t, s_heap_allocation> m_heap_allocations{};
    std::unordered_set<uint64_t> m_storage_allocations{};

    struct s_virtual_allocation {
        std::vector<bool> m_committed_pages;
    };

    std::map<uint64_t, s_virtual_allocation> m_virtual_allocations{};

    static bool fetch_prot_callback(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, c_emulator_ctx* ctx);
    [[nodiscard]] uc_err emulate(uint64_t start, uint64_t end, size_t count);

    // Builds RTL_USER_PROCESS_PARAMETERS (image path, command line, current
    // directory, environment) and links it into PEB->ProcessParameters.
    void initialize_windows_process_parameters(uint64_t peb_base) const;

    std::optional<uint64_t> m_hook_resume;
    bool m_stop_requested = false;
    bool m_stop_on_import = false;
    size_t m_emulation_depth = 0;

    uc_engine *m_uc;
    c_emulator *m_emulator;

    uc_hook m_int_trace{}, m_cpuid_trace{}, m_fetch_trace{}, m_prot_trace{}, m_syscall_trace{};
    uc_hook m_shared_data_trace{};

    std::shared_ptr<c_memory_manager> m_memory_manager;
    std::shared_ptr<c_imports> m_imports;

    std::unordered_map<uint64_t, s_hooked_function> m_hooks{};

    std::unordered_set<uint64_t> m_exception_handlers{};

    std::unordered_map<uint64_t, s_process_snapshot> m_process_snapshots{};
    uint64_t m_next_handle = 0x10000;

    std::unordered_map<std::string, const std::vector<uint8_t>*> m_file_sources{};
    std::string m_input_path{};

    std::vector<uint8_t> m_license_file{};
    std::unordered_map<uint64_t, s_file_handle> m_file_handles{};

    uint64_t m_exception_stack = 0;
    uint64_t m_exception_return_address = 0;

    c_themida_unpacker *m_themida_unpacker = nullptr;

    struct s_mem_hook {
        uc_hook m_trace{};
        std::function<mem_callback_t> m_hook = nullptr;
    };

    std::unordered_map<uint64_t, s_mem_hook> m_mem_hooks{};
};

#endif //UNTHEMIDATOR_EMULATOR_CTX_HPP
