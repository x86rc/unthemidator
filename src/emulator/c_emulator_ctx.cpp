#include <array>
#include <cstring>
#include <fstream>
#include <sstream>
#include <utility>

#include "c_emulator.hpp"
#include "windows.hpp"

#include "../memory/c_memory_manager.hpp"
#include "../unpacker/c_themida_unpacker.hpp"

#undef min
#undef max

static void code_callback(uc_engine *uc, const uint64_t address, const uint32_t size, void* cb) {
    (*static_cast<std::function<code_callback_t>*>(cb))(uc, address, size);
}

static void mem_callback(uc_engine *uc, const uc_mem_type type, const uint64_t address,
    const int size, const int64_t value, void* cb) {
    //
    (*static_cast<std::function<mem_callback_t>*>(cb))(uc, type, address, size, value);
}

static bool mem_fault_callback(uc_engine *uc, const uc_mem_type type, const uint64_t address,
    const int size, const int64_t value, void* cb) {
    mem_callback(uc, type, address, size, value, cb);
    return false; // The observer does not repair the faulting mapping.
}

static bool mem_prot_callback(uc_engine*, const uc_mem_type, const uint64_t address, const int size, const int64_t, void*) {
    return !c_memory::overlaps_shared_data(address, static_cast<uint64_t>(size));
}

static void shared_data_callback(uc_engine*, uc_mem_type, uint64_t, int, int64_t, const c_memory* memory) {
    (void)memory->get_shared_data();
}

static int cpuid_callback(uc_engine *uc, void*) {
    uint32_t eax_in, ecx_in;
    uc_reg_read(uc, UC_X86_REG_EAX, &eax_in);
    uc_reg_read(uc, UC_X86_REG_ECX, &ecx_in);

    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;

    switch (eax_in) {
        case 0x0: {
            // max basic leaf + vendor string "AuthenticAMD"
            eax = 0x00000010; // max supported basic leaf (leaf 0x10 on Zen 3)
            ebx = 0x68747541; // "Auth"
            edx = 0x69746E65; // "enti"
            ecx = 0x444D4163; // "cAMD"
            break;
        }

        case 0x1: {
            eax = (0x0A << 20) | (0x2 << 16) | (0xF << 8) | (0x1 << 4) | 0x0;
            ebx = (0x00 << 24) | (32 << 16) | (8 << 8) | 0x00;
            ecx = (1u <<  0) | (1u <<  1) | (1u <<  3) |
                  (1u <<  9) | (1u << 12) | (1u << 13) |
                  (1u << 19) | (1u << 20) | (1u << 22) |
                  (1u << 23) | (1u << 25) | (1u << 26) |
                  (1u << 27) | (1u << 28) | (1u << 29) |
                  (1u << 30);
            edx = (1u <<  0) | (1u <<  1) | (1u <<  2) | (1u <<  3) |
                  (1u <<  4) | (1u <<  5) | (1u <<  6) | (1u <<  7) |
                  (1u <<  8) | (1u <<  9) | (1u << 11) | (1u << 12) |
                  (1u << 13) | (1u << 14) | (1u << 15) | (1u << 16) |
                  (1u << 17) | (1u << 19) | (1u << 23) | (1u << 24) |
                  (1u << 25) | (1u << 26) | (1u << 28);

            break;
        }

        default:
            // leaf not implemented РІР‚вЂќ return zeros
            break;
    }

    uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    uc_reg_write(uc, UC_X86_REG_EBX, &ebx);
    uc_reg_write(uc, UC_X86_REG_ECX, &ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &edx);

    return 1;
}

static bool dispatch_hook(uc_engine *uc, const uint64_t address, c_emulator_ctx* ctx) {
    if (ctx->stops_on_import() && ctx->get_imports()->find_import_by_address(address)) {
        ctx->stop(address);
        return false;
    }

    const auto hook = ctx->get_hook(address);

    const auto is_x86 = ctx->get_arch() == e_architecture::k_x86;
    const auto sp_reg = is_x86 ? UC_X86_REG_ESP : UC_X86_REG_RSP;

    auto sp = ctx->get_x86_reg_value(sp_reg);
    const auto ret_addr = is_x86 ? ctx->read<uint32_t>(sp).value() : ctx->read<uint64_t>(sp).value();

    if (!hook) {
        printf("exception thrown - 0x%llX (ret addy 0x%llX)\n", address, ret_addr);

        throw std::runtime_error("unexpected bp!");
    }

    /*
    if (hook->m_name != "GetProcessHeap" && hook->m_name != "RtlFreeHeap" && hook->m_name != "RtlAllocateHeap" &&
        hook->m_name != "RtlReAllocateHeap") {
        printf("[+] calling %s from 0x%llX, ret addr 0x%llX...\n", hook->m_name.c_str(), address, ret_addr);
    }*/

    const auto arg_count = hook->m_arg_count;

    // both INT3 and protected-fetch hooks see the actual hooked address.
    ctx->set_pc(address);
    hook->m_function(ctx);

    if (ctx->is_stopped()) {
        uc_emu_stop(uc);
        return false;
    }

    // adjust SP as if a RET has been made
    sp += is_x86 ? sizeof(uint32_t) * (1ULL + arg_count) : sizeof(uint64_t);

    ctx->set_x86_reg_value(sp_reg, sp);
    ctx->set_pc(ret_addr);

    return true;
}

static void int_callback(uc_engine *uc, const int exception, c_emulator_ctx* ctx) {
    if (exception != 3) {
        throw std::runtime_error("emulator ctx: unexpected interruption/exception");
    }

    // unicorn automatically steps forward after int3 exception occurs so to get actual address of breakpoint
    // we should calculate previous RIP which is current_rip - 0x1 (sizeof(int3))
    // (https://github.com/unicorn-engine/unicorn/issues/1027)
    const auto int3_addr = ctx->get_pc() - 0x1;
    dispatch_hook(uc, int3_addr, ctx);
}

static void syscall_callback(uc_engine *uc, void*) {
    throw std::runtime_error("syscall callback!"); // fixme
}

bool c_emulator_ctx::fetch_prot_callback(uc_engine *uc, uc_mem_type, const uint64_t address, int, int64_t, c_emulator_ctx* ctx) {
    if (ctx->m_stop_on_import && ctx->m_imports->find_import_by_address(address)) {
        ctx->stop(address);
        return false;
    }

    if (!ctx->get_hook(address)) {
        return false;
    }

    if (dispatch_hook(uc, address, ctx)) {
        ctx->m_hook_resume = ctx->get_pc();
    }

    uc_emu_stop(uc);
    return false;
}

c_emulator_ctx::c_emulator_ctx(c_emulator* emulator, uc_engine *uc, const std::shared_ptr<c_memory_manager>& memory_manager) :
    m_uc(uc), m_emulator(emulator), m_memory_manager(memory_manager) {
    //

    // setup interruption hook
    {
        uc_hook_add(m_uc, &m_int_trace, UC_HOOK_INTR, reinterpret_cast<void*>(int_callback),
            reinterpret_cast<void*>(this), 1, 0);
    }

    // setup cpuid hook
    uc_hook_add(m_uc, &m_cpuid_trace, UC_HOOK_INSN, reinterpret_cast<void*>(cpuid_callback),
        nullptr, 1, 0, UC_X86_INS_CPUID);

    // setup syscall hook
    uc_hook_add(m_uc, &m_syscall_trace, UC_HOOK_INSN, reinterpret_cast<void*>(syscall_callback),
        nullptr, 1, 0, UC_X86_INS_SYSCALL);

    uc_hook_add(m_uc, &m_fetch_trace, UC_HOOK_MEM_FETCH_PROT, reinterpret_cast<void*>(fetch_prot_callback),
        this, 1, 0);

    uc_hook_add(m_uc, &m_prot_trace, UC_HOOK_MEM_READ_PROT | UC_HOOK_MEM_WRITE_PROT,
        reinterpret_cast<void*>(mem_prot_callback), nullptr, 1, 0);

    m_imports = std::make_shared<c_imports>(this);

    if (uc_hook_add(m_uc, &m_shared_data_trace, UC_HOOK_MEM_READ,
        reinterpret_cast<void*>(shared_data_callback), m_memory_manager.get(),
        c_memory::k_shared_data_base, c_memory::k_shared_data_base + c_memory::k_shared_data_size - 1) != UC_ERR_OK) {
        //
        throw std::runtime_error("emulator ctx: failed to hook KUSER_SHARED_DATA reads");
    }
}

c_emulator_ctx::~c_emulator_ctx() {
    uc_hook_del(m_uc, m_shared_data_trace);
    uc_hook_del(m_uc, m_int_trace);
    uc_hook_del(m_uc, m_fetch_trace);
    uc_hook_del(m_uc, m_prot_trace);
    uc_hook_del(m_uc, m_cpuid_trace);
    uc_hook_del(m_uc, m_syscall_trace);

    uc_close(m_uc);
}

e_architecture c_emulator_ctx::get_arch() const {
    return m_emulator->get_arch();
}

uc_engine* c_emulator_ctx::get_uc() const {
    return m_uc;
}

std::shared_ptr<c_memory> c_emulator_ctx::get_memory() const {
    return m_memory_manager;
}

std::shared_ptr<c_imports> c_emulator_ctx::get_imports() const {
    return m_imports;
}

c_themida_unpacker * c_emulator_ctx::get_themida_unpacker() const {
    return m_themida_unpacker;
}

const std::vector<uint8_t>& c_emulator_ctx::get_original_file_mapping() const {
    return m_memory_manager->get_pe_image()->get_original_mapping();
}

namespace {
    std::string file_name(std::string path) {
        if (const auto separator = path.find_last_of("/\\"); separator != std::string::npos) {
            path.erase(0, separator + 1);
        }

        for (auto &character : path) {
            if (character >= 'A' && character <= 'Z') {
                character += 'a' - 'A';
            }
        }

        return path;
    }
}

void c_emulator_ctx::set_file_sources(const std::string &input_name, const std::string &license_name,
    std::vector<uint8_t> license) {
    //
    if (!m_file_handles.empty()) {
        throw std::runtime_error("emulator ctx: file sources are already in use");
    }

    m_input_path = input_name;

    const auto input = file_name(input_name);
    const auto license_file = file_name(license_name);

    if (input.empty() || (!license_name.empty() && (license_file.empty() || license_file == input))) {
        throw std::runtime_error("emulator ctx: input and license filenames must be distinct");
    }

    m_file_sources.clear();
    m_license_file = std::move(license);
    m_file_sources.emplace(input, &get_original_file_mapping());

    if (!license_name.empty()) {
        m_file_sources.emplace(license_file, &m_license_file);
    }
}

uint64_t c_emulator_ctx::open_file(const std::string &path) {
    const auto file = m_file_sources.find(file_name(path));
    const auto data = file == m_file_sources.end() ? &get_original_file_mapping() : file->second;

    const auto handle = m_next_handle++;
    m_file_handles.emplace(handle, s_file_handle{data, data->size(), 0, false});

    return handle;
}

const c_emulator_ctx::s_file_handle* c_emulator_ctx::get_file_handle(const uint64_t handle, const bool mapping) {
    const auto file = m_file_handles.find(handle);
    return file == m_file_handles.end() || file->second.m_is_mapping != mapping ? nullptr : &file->second;
}

uint64_t c_emulator_ctx::create_file_mapping(const uint64_t handle, const uint64_t size, const uint32_t protection) {
    const auto file = get_file_handle(handle, false);

    const auto data = file ? file->m_data : &get_original_file_mapping();
    const auto file_size = file ? file->m_size : data->size();

    if (!handle || !file_size || size > file_size) {
        return 0;
    }

    const s_file_handle mapping{data, size ? size : file_size, protection, true};
    const auto mapping_handle = m_next_handle++;

    m_file_handles.emplace(mapping_handle, mapping);

    return mapping_handle;
}

bool c_emulator_ctx::close_file_handle(const uint64_t handle) {
    return m_file_handles.erase(handle) != 0;
}

void c_emulator_ctx::set_themida_unpacker(c_themida_unpacker *unpacker) {
    m_themida_unpacker = unpacker;
}

uint64_t c_emulator_ctx::get_x86_reg_value(const uc_x86_reg reg) const {
    uint64_t reg_value = 0;
    uc_reg_read(m_uc, reg, &reg_value);

    return reg_value;
}

void c_emulator_ctx::set_x86_reg_value(const uc_x86_reg reg, const uint64_t value) const {
    uc_reg_write(m_uc, reg, &value);
}

uint64_t c_emulator_ctx::get_arg(const uint32_t index) const {
    if (get_arch() == e_architecture::k_x86) {
        return read<uint32_t>(get_x86_reg_value(UC_X86_REG_ESP) + 4ULL * (index + 1ULL)).value();
    }

    if (constexpr std::array regs = { UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9 };
        index < regs.size()) {
        //
        return get_x86_reg_value(regs[index]);
    }

    return read<uint64_t>(get_x86_reg_value(UC_X86_REG_RSP) + 8ULL * (index + 1ULL)).value();
}

void c_emulator_ctx::set_arg(const uint32_t index, const uint64_t value) {
    if (get_arch() == e_architecture::k_x86) {
        if (!write<uint32_t>(get_x86_reg_value(UC_X86_REG_ESP) + 4ULL * (index + 1ULL),
            static_cast<uint32_t>(value))) {
            //
            throw std::runtime_error("emulator ctx: failed to write argument");
        }

        return;
    }

    if (constexpr std::array regs = { UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9 };
        index < regs.size()) {
        //
        set_x86_reg_value(regs[index], value);
        return;
    }

    if (!write<uint64_t>(get_x86_reg_value(UC_X86_REG_RSP) + 8ULL * (index + 1ULL), value)) {
        throw std::runtime_error("emulator ctx: failed to write argument");
    }
}

void c_emulator_ctx::set_result(const uint64_t value) const {
    set_x86_reg_value(get_arch() == e_architecture::k_x86 ? UC_X86_REG_EAX : UC_X86_REG_RAX, value);
}

void c_emulator_ctx::add_hook(const uint64_t address, const std::string& name,
    const std::function<void(c_emulator_ctx *)> &hook, const uint32_t arg_count) {
    //
    m_hooks.emplace(address, s_hooked_function{
        .m_address = address,
        .m_name = name,
        .m_function = hook,
        .m_arg_count = arg_count
    });
}

void c_emulator_ctx::remove_hook(const uint64_t address) {
    m_hooks.erase(address);
}

void c_emulator_ctx::add_mem_hook(const uc_hook_type hook_type, std::function<mem_callback_t> callback,
    const uint64_t start_address, const uint64_t end_address) {
    //
    m_mem_hooks[start_address] = s_mem_hook{
        .m_trace = {},
        .m_hook = std::move(callback),
    };

    const auto trampoline = hook_type & UC_HOOK_MEM_INVALID ?
        reinterpret_cast<void*>(mem_fault_callback) : reinterpret_cast<void*>(mem_callback);

    uc_hook_add(m_uc, &m_mem_hooks.at(start_address).m_trace, hook_type, trampoline,
        reinterpret_cast<void*>(&m_mem_hooks.at(start_address).m_hook), start_address, end_address);
}

void c_emulator_ctx::remove_mem_hook(const uint64_t address) {
    if (!m_mem_hooks.contains(address)) {
        return;
    }

    uc_hook_del(m_uc, m_mem_hooks.at(address).m_trace);
    m_mem_hooks.erase(address);
}

void c_emulator_ctx::add_exception_handler(const uint64_t address) {
    m_exception_handlers.insert(address);
}

void c_emulator_ctx::remove_exception_handler(const uint64_t address) {
    m_exception_handlers.erase(address);
}

void c_emulator_ctx::raise_exception(const uint32_t exception_code) {
    if (m_exception_handlers.empty()) {
        return;
    }

    if (!m_exception_stack) {
        m_exception_stack = allocate_storage(0x1000);
    }

    if (!m_exception_return_address) {
        m_exception_return_address = allocate_storage(0x1000);
    }

    const auto is_x86 = get_arch() == e_architecture::k_x86;

    constexpr uint64_t k_stack_size = 0x1000;
    constexpr uint64_t k_record_offset = 0x00;
    constexpr uint64_t k_pointers_offset = 0xA0;
    constexpr uint64_t k_context_offset = 0x100;
    constexpr size_t k_context_size = 0x4D0;

    const auto context_size = is_x86 ? 0x2CC : k_context_size;

    uc_context *saved = nullptr;

    if (uc_context_alloc(m_uc, &saved) != UC_ERR_OK) {
        throw std::runtime_error("failed to allocate exception context");
    }

    const std::unique_ptr<uc_context, decltype(&uc_context_free)> original(saved, uc_context_free);

    if (uc_context_save(m_uc, saved) != UC_ERR_OK) {
        throw std::runtime_error("failed to save exception context");
    }

    const auto record_address = m_exception_stack + k_record_offset;
    const auto pointers_address = m_exception_stack + k_pointers_offset;
    const auto context_address = m_exception_stack + k_context_offset;
    const auto return_address = m_exception_return_address;
    const auto stack_pointer = m_exception_stack + k_stack_size - 0x28;

    unthemidator::windows::s_exception_record record{};
    record.exception_code = exception_code;
    record.exception_address = get_pc();

    unthemidator::windows::s_exception_pointers pointers{};
    pointers.exception_record = record_address;
    pointers.context_record = context_address;

    std::array<uint8_t, k_context_size> context{};

    const auto write_field = [&](const size_t offset, const auto value) {
        memcpy(context.data() + offset, &value, sizeof(value));
    };

    if (is_x86) {
        write_field(0, uint32_t{0x00010007});
    } else {
        write_field(0x30, uint32_t{0x00100003});
    }

    constexpr std::array x86_regs = {
        UC_X86_REG_GS, UC_X86_REG_FS, UC_X86_REG_ES, UC_X86_REG_DS,
        UC_X86_REG_EDI, UC_X86_REG_ESI, UC_X86_REG_EBX, UC_X86_REG_EDX, UC_X86_REG_ECX, UC_X86_REG_EAX,
        UC_X86_REG_EBP, UC_X86_REG_EIP, UC_X86_REG_CS, UC_X86_REG_EFLAGS, UC_X86_REG_ESP, UC_X86_REG_SS
    };

    const auto capture = [&](const size_t offset, const uc_x86_reg reg) {
        write_field(offset, get_x86_reg_value(reg));
    };

    if (is_x86) {
        for (size_t i = 0; i < x86_regs.size(); ++i) {
            write_field(0x8C + i * 4, static_cast<uint32_t>(get_x86_reg_value(x86_regs[i])));
        }
    } else {
        capture(0x78, UC_X86_REG_RAX);
        capture(0x80, UC_X86_REG_RCX);
        capture(0x88, UC_X86_REG_RDX);
        capture(0x90, UC_X86_REG_RBX);
        capture(0x98, UC_X86_REG_RSP);
        capture(0xA0, UC_X86_REG_RBP);
        capture(0xA8, UC_X86_REG_RSI);
        capture(0xB0, UC_X86_REG_RDI);
        capture(0xB8, UC_X86_REG_R8);
        capture(0xC0, UC_X86_REG_R9);
        capture(0xC8, UC_X86_REG_R10);
        capture(0xD0, UC_X86_REG_R11);
        capture(0xD8, UC_X86_REG_R12);
        capture(0xE0, UC_X86_REG_R13);
        capture(0xE8, UC_X86_REG_R14);
        capture(0xF0, UC_X86_REG_R15);
        capture(0xF8, UC_X86_REG_RIP);

        write_field(0x44, static_cast<uint32_t>(get_x86_reg_value(UC_X86_REG_EFLAGS)));
    }

    const auto check_write = [&](const uint64_t address, const void *data, const size_t size) {
        if (uc_mem_write(m_uc, address, data, size) != UC_ERR_OK) {
            throw std::runtime_error("failed to write exception data");
        }
    };

    try {
        if (is_x86) {
            std::array<uint32_t, 20> record32{};
            record32[0] = exception_code;
            record32[3] = static_cast<uint32_t>(get_pc());
            const std::array pointers32 = { static_cast<uint32_t>(record_address), static_cast<uint32_t>(context_address) };
            check_write(record_address, record32.data(), sizeof(record32));
            check_write(pointers_address, pointers32.data(), sizeof(pointers32));
        } else {
            check_write(record_address, &record, sizeof(record));
            check_write(pointers_address, &pointers, sizeof(pointers));
        }
        check_write(context_address, context.data(), context_size);

        for (const auto address : m_exception_handlers) {
            if (uc_context_restore(m_uc, saved) != UC_ERR_OK) {
                throw std::runtime_error("failed to restore exception context");
            }

            check_write(stack_pointer, &return_address, is_x86 ? 4 : 8);

            set_x86_reg_value(is_x86 ? UC_X86_REG_ESP : UC_X86_REG_RSP, stack_pointer);
            set_arg(0, pointers_address);
            set_pc(address);

            if (const auto err = emulate(address, return_address, 0);
                err != UC_ERR_OK) {
                throw std::runtime_error("exception handler failed to return");
            }

            if (m_stop_requested) {
                const auto stopped_pc = get_pc();

                if (uc_context_restore(m_uc, saved) != UC_ERR_OK) {
                    throw std::runtime_error("failed to restore exception context");
                }

                stop(stopped_pc);
                return;
            }

            if (static_cast<int32_t>(get_x86_reg_value(UC_X86_REG_EAX)) != -1) {
                continue;
            }

            if (uc_mem_read(m_uc, context_address, context.data(), context_size) != UC_ERR_OK) {
                throw std::runtime_error("failed to read exception context");
            }

            if (uc_context_restore(m_uc, saved) != UC_ERR_OK) {
                throw std::runtime_error("failed to restore exception context");
            }

            const auto apply = [&](const size_t offset, const uc_x86_reg reg) {
                uint64_t value = 0;
                memcpy(&value, context.data() + offset, sizeof(value));
                set_x86_reg_value(reg, value);
            };

            if (is_x86) {
                for (size_t i = 0; i < x86_regs.size(); ++i) {
                    uint32_t value = 0;
                    memcpy(&value, context.data() + 0x8C + i * 4, sizeof(value));
                    set_x86_reg_value(x86_regs[i], value);
                }
            } else {
                apply(0x78, UC_X86_REG_RAX);
                apply(0x80, UC_X86_REG_RCX);
                apply(0x88, UC_X86_REG_RDX);
                apply(0x90, UC_X86_REG_RBX);
                apply(0x98, UC_X86_REG_RSP);
                apply(0xA0, UC_X86_REG_RBP);
                apply(0xA8, UC_X86_REG_RSI);
                apply(0xB0, UC_X86_REG_RDI);
                apply(0xB8, UC_X86_REG_R8);
                apply(0xC0, UC_X86_REG_R9);
                apply(0xC8, UC_X86_REG_R10);
                apply(0xD0, UC_X86_REG_R11);
                apply(0xD8, UC_X86_REG_R12);
                apply(0xE0, UC_X86_REG_R13);
                apply(0xE8, UC_X86_REG_R14);
                apply(0xF0, UC_X86_REG_R15);
                apply(0xF8, UC_X86_REG_RIP);

                uint32_t eflags = 0;
                memcpy(&eflags, context.data() + 0x44, sizeof(eflags));
                set_x86_reg_value(UC_X86_REG_EFLAGS, eflags);
            }

            return;
        }
    } catch (...) {
        uc_context_restore(m_uc, saved);
        throw;
    }

    if (uc_context_restore(m_uc, saved) != UC_ERR_OK) {
        throw std::runtime_error("failed to restore original context");
    }
}

void c_emulator_ctx::run_thread(const uint64_t address, const uint64_t end, const uint64_t param) {
    uc_context *saved = nullptr;

    if (uc_context_alloc(m_uc, &saved) != UC_ERR_OK) {
        throw std::runtime_error("failed to allocate thread context");
    }

    const std::unique_ptr<uc_context, decltype(&uc_context_free)> original(saved, uc_context_free);

    if (uc_context_save(m_uc, saved) != UC_ERR_OK) {
        throw std::runtime_error("failed to save thread context");
    }

    constexpr uint32_t k_stack_size = 0x10000;

    const auto stack = allocate_storage(k_stack_size);
    const auto hook_resume = m_hook_resume;
    const auto is_x86 = get_arch() == e_architecture::k_x86;
    const auto sp = stack + k_stack_size - (is_x86 ? 8 : 0x28);

    try {
        set_x86_reg_value(is_x86 ? UC_X86_REG_ESP : UC_X86_REG_RSP, sp);
        set_arg(0, param);
        set_pc(address);

        if (const auto err = emulate(address, end, 0); err != UC_ERR_OK) {
            throw std::runtime_error("thread emulation failed: " + std::to_string(err));
        }
    } catch (...) {
        m_hook_resume = hook_resume;

        uc_context_restore(m_uc, saved);
        free_storage(stack);

        throw;
    }

    const auto stopped_pc = get_pc();

    m_hook_resume = m_stop_requested ? std::nullopt : hook_resume;

    const auto err = uc_context_restore(m_uc, saved);
    free_storage(stack);

    if (err != UC_ERR_OK) {
        throw std::runtime_error("failed to restore original context");
    }

    if (m_stop_requested) {
        stop(stopped_pc);
    }
}

uint64_t c_emulator_ctx::create_process_snapshot(const uint32_t flags, const uint32_t process_id) {
    const auto handle = m_next_handle++;

    m_process_snapshots.emplace(handle, s_process_snapshot{
        .m_flags = flags,
        .m_process_id = process_id,
    });

    return handle;
}

c_emulator_ctx::s_process_snapshot* c_emulator_ctx::get_process_snapshot(const uint64_t handle) {
    const auto it = m_process_snapshots.find(handle);
    return it == m_process_snapshots.end() ? nullptr : &it->second;
}

bool c_emulator_ctx::close_process_snapshot(const uint64_t handle) {
    return m_process_snapshots.erase(handle) != 0;
}

const s_hooked_function* c_emulator_ctx::get_hook(const uint64_t address) {
    const auto hook = m_hooks.find(address);

    if (hook == m_hooks.end()) {
        return nullptr;
    }

    return &hook->second;
}

uint64_t c_emulator_ctx::map_dummy_module(const std::vector<uint8_t> &image, const std::string &name) const {
    const auto image_base = m_memory_manager->allocate_helper_stub(static_cast<uint32_t>(image.size()));

    auto err = uc_mem_map(m_uc, image_base, page_up(image.size(), 0x1000), UC_PROT_READ);

    if (err != UC_ERR_OK) {
        throw std::runtime_error("emulator ctx: failed to map dummy module: " + std::to_string(err));
    }

    err = uc_mem_write(m_uc, image_base, image.data(), image.size());

    if (err != UC_ERR_OK) {
        throw std::runtime_error("emulator ctx: failed to write dummy module: " + std::to_string(err));
    }

    m_memory_manager->tag_region(image_base, name);
    return image_base;
}

void c_emulator_ctx::stop(const uint64_t address) {
    m_stop_requested = true;
    m_hook_resume.reset();

    set_pc(address);
    uc_emu_stop(m_uc);
}

void c_emulator_ctx::return_from_call(const uint32_t arg_count) {
    const auto is_x86 = get_arch() == e_architecture::k_x86;
    const auto sp_reg = is_x86 ? UC_X86_REG_ESP : UC_X86_REG_RSP;
    const auto sp = get_x86_reg_value(sp_reg);
    const auto address = is_x86 ? read<uint32_t>(sp).value() : read<uint64_t>(sp).value();

    set_x86_reg_value(sp_reg, sp + (is_x86 ? 4ULL * (arg_count + 1ULL) : 8ULL));
    set_pc(address);

    m_hook_resume = address;

    uc_emu_stop(m_uc);
}

uc_err c_emulator_ctx::emulate(uint64_t start, const uint64_t end, const size_t count) {
    if (!m_emulation_depth) {
        m_stop_requested = false;
    }

    ++m_emulation_depth;
    auto result = UC_ERR_OK;
    try {
        while (!m_stop_requested) {
            m_hook_resume.reset();
            result = uc_emu_start(m_uc, start, end, 0, count);

            if (m_stop_requested) {
                m_hook_resume.reset();
                if (result == UC_ERR_FETCH_PROT) {
                    result = UC_ERR_OK;
                }
                break;
            }

            if (!m_hook_resume || (result != UC_ERR_OK && result != UC_ERR_FETCH_PROT)) {
                break;
            }

            start = *m_hook_resume;
            set_pc(start);
            result = UC_ERR_OK;
            if (count == 1 || (end && start == end)) {
                break;
            }
        }
    } catch (...) {
        --m_emulation_depth;
        throw;
    }
    --m_emulation_depth;
    return result;
}

void c_emulator_ctx::single_step(std::function<mem_callback_t> on_mem) {
    uc_hook mem_trace;

    if (on_mem) {
        uc_hook_add(m_uc, &mem_trace, UC_HOOK_MEM_READ | UC_HOOK_MEM_READ_UNMAPPED |
            UC_HOOK_MEM_READ_PROT | UC_HOOK_MEM_WRITE | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_WRITE_PROT,
            reinterpret_cast<void*>(mem_callback), reinterpret_cast<void*>(&on_mem), 1, 0);
    }

    uc_ctl_remove_cache(m_uc, 0, UINT64_MAX);
    uc_ctl_flush_tb(m_uc);

    if (const auto err = emulate(get_pc(), 0, 1); err != UC_ERR_OK) {
        throw std::runtime_error("emulator ctx: failed to start single step emulation: " +
            std::to_string(err));
    }

    if (on_mem) {
        uc_hook_del(m_uc, mem_trace);
    }
}

void c_emulator_ctx::run(const uint64_t start, const uint64_t end, std::function<code_callback_t> on_code,
    std::function<mem_callback_t> on_mem) {
    //
    uc_hook code_trace, mem_trace;
    auto err = UC_ERR_OK;

    // if code callback function was provided, set up single step hook
    if (on_code) {
        err = uc_hook_add(m_uc, &code_trace, UC_HOOK_CODE, reinterpret_cast<void*>(code_callback),
            reinterpret_cast<void*>(&on_code), 1, 0);

        if (err != UC_ERR_OK) {
            throw std::runtime_error("emulator ctx: failed to place code hook: " +
                std::to_string(err));
        }
    }

    // if memory callback function was provided, set up single step hook
    if (on_mem) {
        err = uc_hook_add(m_uc, &mem_trace, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, reinterpret_cast<void*>(mem_callback),
            on_mem ? reinterpret_cast<void*>(&on_mem) : nullptr, 1, 0);

        if (err != UC_ERR_OK) {
            throw std::runtime_error("emulator ctx: failed to place mem hook: " +
                std::to_string(err));
        }
    }

    uc_ctl_remove_cache(m_uc, 0, UINT64_MAX);
    uc_ctl_flush_tb(m_uc);

    err = emulate(start, end, 0);

    if (err != UC_ERR_OK) {
        /*
        printf("failed at 0x%llX , rsi - 0x%llX , rdi - 0x%llX , rax - 0x%llX , rbx - 0x%llX , r10 - 0x%llX, rbp - 0x%llX,"
               " r15 - 0x%llX, rcx - 0x%llX, r12 - 0x%llX\n",
            get_pc(),
            get_x86_reg_value(UC_X86_REG_RSI), get_x86_reg_value(UC_X86_REG_RDI), get_x86_reg_value(UC_X86_REG_RAX),
            get_x86_reg_value(UC_X86_REG_RBX), get_x86_reg_value(UC_X86_REG_R10), get_x86_reg_value(UC_X86_REG_RBP),
            get_x86_reg_value(UC_X86_REG_R15), get_x86_reg_value(UC_X86_REG_RCX), get_x86_reg_value(UC_X86_REG_R12));*/

        throw std::runtime_error("emulation error: " + std::to_string(err));
    }

    // remove callbacks
    if (on_code) {
        uc_hook_del(m_uc, code_trace);
    }

    if (on_mem) {
        uc_hook_del(m_uc, mem_trace);
    }
}

uint64_t c_emulator_ctx::get_pc() const {
    switch (m_emulator->get_arch()) {
        case e_architecture::k_x86: {
            uint32_t eip;
            uc_reg_read(m_uc, UC_X86_REG_EIP, &eip);

            return eip;
        }

        case e_architecture::k_amd64: {
            uint64_t rip;
            uc_reg_read(m_uc, UC_X86_REG_RIP, &rip);

            return rip;
        }

        default:
            throw std::runtime_error("emulator ctx: unsupported architecture " +
                std::to_string(static_cast<int>(m_emulator->get_arch())));
    }
}

void c_emulator_ctx::set_pc(const uint64_t new_pc) const {
    switch (m_emulator->get_arch()) {
        case e_architecture::k_amd64: {
            uc_reg_write(m_uc, UC_X86_REG_RIP, &new_pc);
            break;
        }

        case e_architecture::k_x86: {
            const auto eip = static_cast<uint32_t>(new_pc);
            uc_reg_write(m_uc, UC_X86_REG_EIP, &eip);
            break;
        }

        default:
            throw std::runtime_error("emulator ctx: unsupported architecture");
    }
}

uint64_t c_emulator_ctx::allocate_heap(const uint64_t size) {
    if (size > 0xFFFFF000ULL) {
        return 0;
    }

    const auto capacity = static_cast<uint32_t>(page_up(size ? size : 1, 0x1000));
    const auto address = allocate_storage(capacity, "heap");

    m_heap_allocations.emplace(address, s_heap_allocation{
        .m_size = static_cast<uint32_t>(size),
        .m_capacity = capacity,
    });

    return address;
}

bool c_emulator_ctx::free_heap(const uint64_t address) {
    if (!address) {
        return true;
    }

    if (!m_heap_allocations.contains(address) || !free_storage(address)) {
        return false;
    }

    m_heap_allocations.erase(address);
    return true;
}

uint64_t c_emulator_ctx::reallocate_heap(const uint64_t address, const uint64_t size, const uint32_t flags) {
    const auto entry = m_heap_allocations.find(address);

    if (entry == m_heap_allocations.end() || size > 0xFFFFF000ULL) {
        return 0;
    }

    const auto [entry_size, entry_capacity] = entry->second;

    if (size <= entry_capacity) {
        if (flags & 0x8 && size > entry_size) {
            const std::vector<uint8_t> zeros(size - entry_size, 0);

            if (uc_mem_write(m_uc, address + entry_size, zeros.data(), zeros.size()) != UC_ERR_OK) {
                return 0;
            }
        }

        entry->second.m_size = static_cast<uint32_t>(size);
        return address;
    }

    if (flags & 0x10) {
        return 0;
    }

    std::vector<uint8_t> contents(entry_size);
    if (!contents.empty() && uc_mem_read(m_uc, address, contents.data(), contents.size()) != UC_ERR_OK) {
        return 0;
    }

    const auto replacement = allocate_heap(size);
    if (!replacement) {
        return 0;
    }

    if ((!contents.empty() && uc_mem_write(m_uc, replacement, contents.data(), contents.size()) != UC_ERR_OK) ||
        !free_heap(address)) {
        //
        free_heap(replacement);
        return 0;
    }

    return replacement;
}

uint64_t c_emulator_ctx::allocate_storage(const uint32_t size, const std::string &tag) {
    const auto region_base = m_memory_manager->allocate_helper_stub(size);
    const auto aligned_size = m_memory_manager->get_region_size(region_base);

    if (const auto err = uc_mem_map(m_uc, region_base, aligned_size, UC_PROT_ALL);
        err != UC_ERR_OK) {
        //
        m_memory_manager->free_region(region_base);
        throw std::runtime_error("emulator ctx: failed to allocate region: " + std::to_string(err));
    }

    m_storage_allocations.insert(region_base);

    if (!tag.empty()) {
        std::stringstream tag_with_addr_stream;
        tag_with_addr_stream << tag;
        tag_with_addr_stream << "_0x" << std::hex << region_base;

        m_memory_manager->tag_region(region_base, tag_with_addr_stream.str());
    }

    return region_base;
}

bool c_emulator_ctx::free_storage(const uint64_t address) {
    if (!m_storage_allocations.contains(address)) {
        return false;
    }

    if (const auto size = m_memory_manager->get_region_size(address);
        !size || uc_mem_unmap(m_uc, address, size) != UC_ERR_OK) {
        //
        return false;
    }

    m_storage_allocations.erase(address);

    return m_memory_manager->free_region(address);
}

uint64_t c_emulator_ctx::allocate_virtual(const uint64_t address, const uint64_t size, const uint32_t type) {
    if (!size || size > 0xFFFFF000ULL || !(type & 0x3000) || type & ~0x3000U) {
        return 0;
    }

    if (!address) {
        const auto base = allocate_storage(static_cast<uint32_t>(size), "vm");
        const auto capacity = m_memory_manager->get_region_size(base);
        const bool committed = (type & 0x1000) != 0;

        if (!committed && uc_mem_unmap(m_uc, base, capacity) != UC_ERR_OK) {
            free_storage(base);
            return 0;
        }

        m_storage_allocations.erase(base);
        m_virtual_allocations.emplace(base, s_virtual_allocation{std::vector<bool>(capacity / 0x1000, committed)});

        return base;
    }

    auto entry = m_virtual_allocations.upper_bound(address);

    if (type != 0x1000 || entry == m_virtual_allocations.begin()) {
        return 0;
    }

    --entry;

    const auto capacity = entry->second.m_committed_pages.size() * 0x1000;
    const auto offset = address - entry->first;

    if (offset >= capacity || size > capacity - offset) {
        return 0;
    }

    const auto first_page = offset / 0x1000;
    const auto last_page = page_up(offset + size, 0x1000) / 0x1000;

    std::vector<size_t> mapped_pages{};

    for (auto page = first_page; page < last_page; ++page) {
        if (entry->second.m_committed_pages[page]) {
            continue;
        }

        if (uc_mem_map(m_uc, entry->first + page * 0x1000, 0x1000, UC_PROT_ALL) != UC_ERR_OK) {
            for (const auto mapped_page : mapped_pages) {
                uc_mem_unmap(m_uc, entry->first + mapped_page * 0x1000, 0x1000);
                entry->second.m_committed_pages[mapped_page] = false;
            }

            return 0;
        }

        entry->second.m_committed_pages[page] = true;
        mapped_pages.push_back(page);
    }

    return entry->first + first_page * 0x1000;
}

bool c_emulator_ctx::free_virtual(const uint64_t address, const uint64_t size, const uint32_t type) {
    auto entry = m_virtual_allocations.upper_bound(address);

    if (entry == m_virtual_allocations.begin() || (type != 0x8000 && type != 0x4000)) {
        return false;
    }

    --entry;

    const auto capacity = entry->second.m_committed_pages.size() * 0x1000;
    const auto offset = address - entry->first;

    if (offset >= capacity || size > capacity - offset || (type == 0x8000 && (offset || size)) || (!size && offset)) {
        return false;
    }

    const auto first_page = offset / 0x1000;
    const auto last_page = size ? page_up(offset + size, 0x1000) / 0x1000 : capacity / 0x1000;

    for (auto page = first_page; page < last_page; ++page) {
        if (!entry->second.m_committed_pages[page]) {
            continue;
        }

        const auto page_address = entry->first + page * 0x1000;

        if (uc_mem_unmap(m_uc, page_address, 0x1000) != UC_ERR_OK) {
            return false;
        }

        entry->second.m_committed_pages[page] = false;
        m_memory_manager->write_memory(page_address, std::vector<uint8_t>(0x1000, 0));
    }

    if (type == 0x8000) {
        m_memory_manager->free_region(entry->first);
        m_virtual_allocations.erase(entry);
    }

    return true;
}

void c_emulator_ctx::initialize_windows_ldr() const {
    const auto is_x86 = get_arch() == e_architecture::k_x86;
    const uint32_t ptr_size = is_x86 ? 4 : 8;

    if (get_arch() != e_architecture::k_amd64 && get_arch() != e_architecture::k_x86) {
        throw std::runtime_error("unsupported architecture");
    }

    auto *uc = m_uc;

    const auto read_ptr = [&](uint64_t address) -> uint64_t {
        uint64_t value = 0;

        if (uc_mem_read(uc, address, &value, ptr_size) != UC_ERR_OK) {
            throw std::runtime_error("failed to read Windows loader memory");
        }

        return value;
    };

    const auto write = [&](uint64_t address, const void *data, size_t size) {
        if (uc_mem_write(uc, address, data, size) != UC_ERR_OK) {
            throw std::runtime_error("failed to write Windows loader memory");
        }
    };

    const auto write32 = [&](uint64_t address, uint32_t value) {
        write(address, &value, sizeof(value));
    };

    const auto write_ptr = [&](uint64_t address, uint64_t value) {
        write(address, &value, ptr_size);
    };

    uc_x86_msr msr{};
    msr.rid = static_cast<uint32_t>(unthemidator::windows::e_msr::k_ia32_gs_base);

    if (!is_x86 && uc_reg_read(uc, UC_X86_REG_MSR, &msr) != UC_ERR_OK) {
        throw std::runtime_error("failed to read GS base");
    }

    const uint64_t teb_base = is_x86 ? m_memory_manager->get_address_by_tag("TEB").value() : msr.value;
    const uint64_t peb_base = read_ptr(teb_base + (is_x86 ? 0x30 : 0x60));
    const uint64_t ldr_base = read_ptr(peb_base + (is_x86 ? 0x0C : 0x18));

    if (!teb_base || !peb_base || !ldr_base) {
        throw std::runtime_error("Windows loader environment is not initialized");
    }

    const uint64_t ntdll_base = m_imports->load_module("ntdll.dll");

    if (!ntdll_base) {
        throw std::runtime_error("failed to load ntdll.dll");
    }

    // Extract image metadata from the mapped ntdll.dll.
    uint16_t dos_magic = 0;
    uint32_t nt_offset = 0;
    uint32_t nt_signature = 0;
    uint16_t optional_magic = 0;
    uint32_t entry_rva = 0;
    uint32_t image_size = 0;

    const auto read = [&](uint64_t address, void *data, size_t size) {
        if (uc_mem_read(uc, address, data, size) != UC_ERR_OK) {
            throw std::runtime_error("failed to read ntdll.dll headers");
        }
    };

    read(ntdll_base, &dos_magic, sizeof(dos_magic));
    read(ntdll_base + 0x3C, &nt_offset, sizeof(nt_offset));

    if (dos_magic != 0x5A4D || nt_offset > 0x1000 - 0x60) {
        throw std::runtime_error("invalid ntdll.dll DOS header");
    }

    const uint64_t nt_header = ntdll_base + nt_offset;
    const uint64_t optional_header = nt_header + 4 + 20;

    read(nt_header, &nt_signature, sizeof(nt_signature));
    read(optional_header, &optional_magic, sizeof(optional_magic));

    if (nt_signature != 0x00004550 || optional_magic != (is_x86 ? 0x10B : 0x20B)) {
        throw std::runtime_error("invalid ntdll.dll PE32+ headers");
    }

    read(optional_header + 0x10, &entry_rva, sizeof(entry_rva));
    read(optional_header + 0x38, &image_size, sizeof(image_size));

    if (!image_size || entry_rva >= image_size ||
        ntdll_base > std::numeric_limits<uint64_t>::max() - image_size) {
        throw std::runtime_error("invalid ntdll.dll image metadata");
    }

    constexpr uint64_t k_page_size = 0x1000;
    constexpr uint64_t k_full_name_offset = 0x100;
    constexpr uint64_t k_base_name_offset = 0x180;

    constexpr char16_t k_full_name[] = u"C:\\Windows\\System32\\ntdll.dll";
    constexpr char16_t k_base_name[] = u"ntdll.dll";

    const uint64_t entry_base = m_memory_manager->allocate_helper_stub(k_page_size);

    if (!entry_base || entry_base > std::numeric_limits<uint64_t>::max() - k_page_size) {
        throw std::runtime_error("invalid LDR entry address");
    }

    std::array<uint8_t, k_page_size> entry{};

    const auto set16 = [&](size_t offset, uint16_t value) {
        std::memcpy(entry.data() + offset, &value, sizeof(value));
    };

    const auto set32 = [&](size_t offset, uint32_t value) {
        std::memcpy(entry.data() + offset, &value, sizeof(value));
    };

    const auto set_ptr = [&](size_t offset, uint64_t value) {
        std::memcpy(entry.data() + offset, &value, ptr_size);
    };

    const auto set_unicode_string = [&](size_t offset, uint64_t string_offset,
        const char16_t *value, size_t byte_size) {
        //
        const auto length = static_cast<uint16_t>(byte_size - sizeof(char16_t));
        const auto maximum_length = static_cast<uint16_t>(byte_size);

        set16(offset, length);
        set16(offset + 2, maximum_length);
        set_ptr(offset + ptr_size, entry_base + string_offset);

        std::memcpy(entry.data() + string_offset, value, byte_size);
    };

    // LDR_DATA_TABLE_ENTRY: list links
    const std::array<uint64_t, 3> k_entry_list_offsets = { 0, 2ULL * ptr_size, 4ULL * ptr_size };
    const std::array k_ldr_list_offsets = { 8ULL + ptr_size, 8ULL + 3 * ptr_size, 8ULL + 5 * ptr_size };

    for (size_t i = 0; i < k_entry_list_offsets.size(); ++i) {
        const uint64_t head = ldr_base + k_ldr_list_offsets[i];
        const uint64_t node = entry_base + k_entry_list_offsets[i];

        // LIST_ENTRY.Flink / LIST_ENTRY.Blink
        set_ptr(k_entry_list_offsets[i], head);
        set_ptr(k_entry_list_offsets[i] + ptr_size, head);
    }

    set_ptr(is_x86 ? 0x18 : 0x30, ntdll_base);
    set_ptr(is_x86 ? 0x1C : 0x38, entry_rva ? ntdll_base + entry_rva : 0);
    set32(is_x86 ? 0x20 : 0x40, image_size);

    set_unicode_string(is_x86 ? 0x24 : 0x48, k_full_name_offset,
        k_full_name, sizeof(k_full_name));

    set_unicode_string(is_x86 ? 0x2C : 0x58, k_base_name_offset,
        k_base_name, sizeof(k_base_name));

    // Map and populate LDR_DATA_TABLE_ENTRY and both Unicode strings
    if (uc_mem_map(uc, entry_base, k_page_size, UC_PROT_READ | UC_PROT_WRITE) != UC_ERR_OK) {
        throw std::runtime_error("failed to map LDR entry");
    }

    write(entry_base, entry.data(), entry.size());

    // Initialize PEB_LDR_DATA fields
    write32(ldr_base + 0x00, is_x86 ? 0x30 : 0x58);

    constexpr uint8_t initialized = 1;
    write(ldr_base + 0x04, &initialized, sizeof(initialized));

    // Link all three lists to the single entry
    for (size_t i = 0; i < k_ldr_list_offsets.size(); ++i) {
        const uint64_t head = ldr_base + k_ldr_list_offsets[i];
        const uint64_t node = entry_base + k_entry_list_offsets[i];

        write_ptr(head, node);
        write_ptr(head + ptr_size, node);
    }

    initialize_windows_process_parameters(peb_base);
}

void c_emulator_ctx::initialize_windows_process_parameters(const uint64_t peb_base) const {
    constexpr uint64_t k_page_size = 0x1000;

    const auto is_x86 = get_arch() == e_architecture::k_x86;

    if (get_arch() != e_architecture::k_amd64 && get_arch() != e_architecture::k_x86) {
        return;
    }

    auto *uc = m_uc;

    // RTL_USER_PROCESS_PARAMETERS field offsets (Windows 10 x64 / x86 layout).
    const uint64_t off_maximum_length = 0x00;
    const uint64_t off_length = 0x04;
    const uint64_t off_current_directory = is_x86 ? 0x24 : 0x38;
    const uint64_t off_dll_path = is_x86 ? 0x30 : 0x50;
    const uint64_t off_image_path_name = is_x86 ? 0x38 : 0x60;
    const uint64_t off_command_line = is_x86 ? 0x40 : 0x70;
    const uint64_t off_environment = is_x86 ? 0x48 : 0x80;

    // String storage inside the parameters page.
    constexpr uint64_t k_image_path_offset = 0x200;
    constexpr uint64_t k_command_line_offset = 0x300;
    constexpr uint64_t k_current_directory_offset = 0x400;
    constexpr uint64_t k_dll_path_offset = 0x500;
    constexpr uint64_t k_environment_offset = 0x600;

    const auto to_utf16 = [](const std::string &value) {
        std::u16string result{};
        result.reserve(value.size());

        for (const char character : value) {
            result.push_back(static_cast<char16_t>(static_cast<unsigned char>(character)));
        }

        return result;
    };

    std::string image_path = m_input_path;

    if (image_path.empty()) {
        image_path = "C:\\unthemidator.exe";
    } else if (image_path.size() < 2 || image_path[1] != ':') {
        image_path = "C:\\" + file_name(image_path);
    }

    std::string current_directory = "C:\\";

    if (const auto separator = image_path.find_last_of("\\/"); separator != std::string::npos) {
        current_directory = image_path.substr(0, separator);

        if (current_directory.size() == 2) {
            current_directory += "\\";
        }
    }

    const auto image_path_utf16 = to_utf16(image_path);
    const auto command_line_utf16 = to_utf16("\"" + image_path + "\"");
    const auto current_directory_utf16 = to_utf16(current_directory);
    const auto dll_path_utf16 = to_utf16("C:\\Windows\\System32");

    const auto params_base = m_memory_manager->allocate_helper_stub(k_page_size);

    if (!params_base) {
        throw std::runtime_error("failed to allocate Windows process parameters");
    }

    std::array<uint8_t, k_page_size> params{};

    const auto write_raw = [&](const uint64_t offset, const void *data, const size_t size) {
        std::memcpy(params.data() + offset, data, size);
    };

    const auto write16 = [&](const uint64_t offset, const uint16_t value) {
        write_raw(offset, &value, sizeof(value));
    };

    const auto write32 = [&](const uint64_t offset, const uint32_t value) {
        write_raw(offset, &value, sizeof(value));
    };

    const auto write_ptr = [&](const uint64_t offset, const uint64_t value) {
        if (is_x86) {
            write32(offset, static_cast<uint32_t>(value));
        } else {
            write_raw(offset, &value, sizeof(value));
        }
    };

    const auto write_unicode_string = [&](const uint64_t offset, const uint64_t string_offset,
        const std::u16string &value) {
        const auto byte_size = static_cast<uint16_t>(value.size() * sizeof(char16_t));

        write16(offset, byte_size);
        write16(offset + 2, static_cast<uint16_t>(byte_size + sizeof(char16_t)));
        write_ptr(offset + (is_x86 ? 4 : 8), params_base + string_offset);
        write_raw(string_offset, value.data(), byte_size);
    };

    write32(off_maximum_length, static_cast<uint32_t>(k_page_size));
    write32(off_length, static_cast<uint32_t>(k_page_size));

    write_unicode_string(off_current_directory, k_current_directory_offset, current_directory_utf16);
    write_unicode_string(off_dll_path, k_dll_path_offset, dll_path_utf16);
    write_unicode_string(off_image_path_name, k_image_path_offset, image_path_utf16);
    write_unicode_string(off_command_line, k_command_line_offset, command_line_utf16);

    // Environment block: empty, double null terminated (the page is zeroed).
    write_ptr(off_environment, params_base + k_environment_offset);

    if (uc_mem_map(uc, params_base, k_page_size, UC_PROT_READ | UC_PROT_WRITE) != UC_ERR_OK) {
        throw std::runtime_error("failed to map Windows process parameters");
    }

    if (uc_mem_write(uc, params_base, params.data(), params.size()) != UC_ERR_OK) {
        throw std::runtime_error("failed to write Windows process parameters");
    }

    // PEB->ProcessParameters
    if (is_x86) {
        const auto value = static_cast<uint32_t>(params_base);

        if (uc_mem_write(uc, peb_base + 0x10, &value, sizeof(value)) != UC_ERR_OK) {
            throw std::runtime_error("failed to link Windows process parameters");
        }
    } else {
        if (uc_mem_write(uc, peb_base + 0x20, &params_base, sizeof(params_base)) != UC_ERR_OK) {
            throw std::runtime_error("failed to link Windows process parameters");
        }
    }
}
