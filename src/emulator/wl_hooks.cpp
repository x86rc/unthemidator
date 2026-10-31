#include "hooks.hpp"

#include <string>
#include <type_traits>
#include <chrono>
#include <ctime>
#include <mutex>

namespace {
    struct s_system_time {
        uint16_t m_year;
        uint16_t m_month;
        uint16_t m_day_of_week;
        uint16_t m_day;
        uint16_t m_hour;
        uint16_t m_minute;
        uint16_t m_second;
        uint16_t m_milliseconds;
    };

    struct s_file_time {
        uint32_t m_low;
        uint32_t m_high;
    };

    static_assert(sizeof(s_system_time) == 16);
    static_assert(sizeof(s_file_time) == 8);

    void write_last_error(c_emulator_ctx *ctx, const uint32_t error) {
        if (const auto teb = ctx->get_memory()->get_address_by_tag("TEB").value();
            !ctx->write<uint32_t>(teb + (ctx->get_arch() == e_architecture::k_x86 ? 0x34 : 0x68), error)) {
            //
            throw std::runtime_error("failed to write last error");
        }
    }

    template<typename Pointer>
    struct ip_address_string {
        Pointer next{};
        char address[16]{};
        char mask[16]{};
        uint32_t context{};
    };

    template<typename Pointer>
    struct adapter_info {
        Pointer next{};
        uint32_t combo_index{};
        char name[260] = "{12345678-1234-5678-9ABC-123456789ABC}";
        char description[132] = "Ethernet Adapter";
        uint32_t address_length = 6;
        uint8_t address[8] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
        uint32_t index = 1;
        uint32_t type = 6; // Ethernet.
        uint32_t dhcp_enabled{};
        Pointer current_ip_address{};
        ip_address_string<Pointer> ip{}, gateway{}, dhcp_server{};
        uint32_t have_wins{};
        ip_address_string<Pointer> primary_wins{}, secondary_wins{};
        std::conditional_t<sizeof(Pointer) == 4, int32_t, int64_t> lease_obtained{}, lease_expires{};
    };

    static_assert(sizeof(adapter_info<uint32_t>) == 640);
    static_assert(sizeof(adapter_info<uint64_t>) == 704);
}

void hooks::get_local_time(c_emulator_ctx *ctx) {
    const auto now = std::chrono::system_clock::now();
    const auto seconds = floor<std::chrono::seconds>(now);
    const auto timestamp = std::chrono::system_clock::to_time_t(seconds);

    std::tm local{};
    {
        static std::mutex time_mutex;
        const std::lock_guard lock(time_mutex);
        const auto result = std::localtime(&timestamp);

        if (!result) {
            throw std::runtime_error("hooks: failed to get local time");
        }

        local = *result;
    }

    const s_system_time time{
        static_cast<uint16_t>(local.tm_year + 1900),
        static_cast<uint16_t>(local.tm_mon + 1),
        static_cast<uint16_t>(local.tm_wday),
        static_cast<uint16_t>(local.tm_mday),
        static_cast<uint16_t>(local.tm_hour),
        static_cast<uint16_t>(local.tm_min),
        static_cast<uint16_t>(local.tm_sec),
        static_cast<uint16_t>(duration_cast<std::chrono::milliseconds>(now - seconds).count()),
    };

    if (!ctx->write(ctx->get_arg(0), time)) {
        throw std::runtime_error("hooks: failed to write local time");
    }
}

void hooks::system_time_to_file_time(c_emulator_ctx *ctx) {
    const auto time = ctx->read<s_system_time>(ctx->get_arg(0));

    if (!time) {
        write_last_error(ctx, 998);
        ctx->set_result(0);
        return;
    }

    const std::chrono::year_month_day date{
        std::chrono::year{time->m_year},
        std::chrono::month{time->m_month},
        std::chrono::day{time->m_day},
    };

    if (time->m_year < 1601 || time->m_year > 30827 || !date.ok() || time->m_hour > 23 ||
        time->m_minute > 59 || time->m_second > 59 || time->m_milliseconds > 999) {
        write_last_error(ctx, 87);
        ctx->set_result(0);
        return;
    }

    using namespace std::chrono;

    using ticks = duration<uint64_t, std::ratio<1, 10'000'000> >;
    const auto value = std::chrono::duration_cast<ticks>(sys_days{date} - sys_days{1601y / January / 1} +
                                                         hours{time->m_hour} + minutes{time->m_minute} + seconds{time->m_second} +
                                                         milliseconds{time->m_milliseconds}).count();

    if (const s_file_time file_time{static_cast<uint32_t>(value), static_cast<uint32_t>(value >> 32)};
        !ctx->write(ctx->get_arg(1), file_time)) {
        //
        write_last_error(ctx, 998);

        ctx->set_result(0);
        return;
    }

    ctx->set_result(1);
}

void hooks::get_adapters_info(c_emulator_ctx *ctx) {
    const auto buffer = ctx->get_arg(0);
    const auto length_pointer = ctx->get_arg(1);
    const auto length = ctx->read<uint32_t>(length_pointer);

    if (!length_pointer || !length) {
        ctx->set_result(87); // ERROR_INVALID_PARAMETER
        return;
    }

    const auto fill = [&]<typename Pointer>() {
        adapter_info<Pointer> adapter{};
        const auto required = static_cast<uint32_t>(sizeof(adapter));

        if (!ctx->write<uint32_t>(length_pointer, required)) {
            ctx->set_result(87);
            return;
        }

        if (!buffer || *length < required) {
            ctx->set_result(111); // ERROR_BUFFER_OVERFLOW
            return;
        }

        std::memcpy(adapter.ip.address, "192.168.1.100", sizeof("192.168.1.100"));
        std::memcpy(adapter.ip.mask, "255.255.255.0", sizeof("255.255.255.0"));
        std::memcpy(adapter.gateway.address, "192.168.1.1", sizeof("192.168.1.1"));
        std::memcpy(adapter.gateway.mask, "0.0.0.0", sizeof("0.0.0.0"));

        ctx->set_result(ctx->write(buffer, adapter) ? 0 : 87);
    };

    if (ctx->get_arch() == e_architecture::k_x86) {
        fill.operator()<uint32_t>();
    } else {
        fill.operator()<uint64_t>();
    }
}

void hooks::sh_get_special_folder_path_w(const c_emulator_ctx *ctx) {
    const auto output = ctx->get_arg(1);
    const auto csidl = static_cast<uint32_t>(ctx->get_arg(2)) & 0xFF;
    const bool x86 = ctx->get_arch() == e_architecture::k_x86;

    std::u16string path;
    switch (csidl) {
        case 0x00:
        case 0x10: path = u"C:\\Users\\User\\Desktop";
            break;
        case 0x05: path = u"C:\\Users\\User\\Documents";
            break;
        case 0x1A: path = u"C:\\Users\\User\\AppData\\Roaming";
            break;
        case 0x1C: path = u"C:\\Users\\User\\AppData\\Local";
            break;
        case 0x23: path = u"C:\\ProgramData";
            break;
        case 0x24: path = u"C:\\Windows";
            break;
        case 0x25: path = x86 ? u"C:\\Windows\\SysWOW64" : u"C:\\Windows\\System32";
            break;
        case 0x26: path = x86 ? u"C:\\Program Files (x86)" : u"C:\\Program Files";
            break;
        case 0x28: path = u"C:\\Users\\User";
            break;
        case 0x29: path = u"C:\\Windows\\SysWOW64";
            break;
        case 0x2A: path = u"C:\\Program Files (x86)";
            break;
        case 0x2B: path = x86 ? u"C:\\Program Files (x86)\\Common Files" : u"C:\\Program Files\\Common Files";
            break;
        case 0x2C: path = u"C:\\Program Files (x86)\\Common Files";
            break;
        default: ctx->set_result(0);
            return;
    }

    const auto bytes = (path.size() + 1) * sizeof(char16_t);
    ctx->set_result(output && !c_memory::overlaps_shared_data(output, bytes) &&
                    uc_mem_write(ctx->get_uc(), output, path.c_str(), bytes) == UC_ERR_OK);
}

void hooks::get_volume_information_a(c_emulator_ctx *ctx) {
    constexpr char volume_name[] = "Local Disk";
    constexpr char file_system[] = "NTFS";

    const auto volume_buffer = ctx->get_arg(1);
    const auto serial_number = ctx->get_arg(3);
    const auto max_component_length = ctx->get_arg(4);
    const auto file_system_flags = ctx->get_arg(5);
    const auto file_system_buffer = ctx->get_arg(6);

    if ((volume_buffer && ctx->get_arg(2) < sizeof(volume_name)) || (file_system_buffer && ctx->get_arg(7) < sizeof(file_system))) {
        write_last_error(ctx, 234); // ERROR_MORE_DATA

        ctx->set_result(0);
        return;
    }

    if ((volume_buffer && uc_mem_write(ctx->get_uc(), volume_buffer, volume_name, sizeof(volume_name)) != UC_ERR_OK) ||
        (file_system_buffer && uc_mem_write(ctx->get_uc(), file_system_buffer, file_system, sizeof(file_system)) != UC_ERR_OK) ||
        (serial_number && !ctx->write<uint32_t>(serial_number, 0x12345678)) ||
        (max_component_length && !ctx->write<uint32_t>(max_component_length, 255)) ||
        (file_system_flags && !ctx->write<uint32_t>(file_system_flags, 0x0000000E))) {
        //
        write_last_error(ctx, 998); // 998

        ctx->set_result(0);
        return;
    }

    ctx->set_result(1);
}

namespace {
    // Copies an ASCII/ANSI path into a UTF-16 buffer with a terminating NUL and
    // returns the number of characters written (excluding the NUL). The buffer
    // capacity argument follows the Win32 convention: it counts characters and
    // includes the space needed for the terminator.
    uint32_t write_wide_path(const c_emulator_ctx *ctx, uint64_t buffer, uint64_t capacity, const std::string &text) {
        std::u16string wide;
        wide.reserve(text.size());
        for (const char c : text) {
            wide.push_back(static_cast<char16_t>(static_cast<unsigned char>(c)));
        }

        if (capacity > 0 && wide.size() > capacity - 1) {
            wide.resize(static_cast<size_t>(capacity - 1));
        }

        if (buffer && !wide.empty()) {
            uc_mem_write(ctx->get_uc(), buffer, wide.data(), wide.size() * sizeof(char16_t));
        }

        const char16_t terminator = 0;
        if (buffer) {
            uc_mem_write(ctx->get_uc(), buffer + wide.size() * sizeof(char16_t), &terminator, sizeof(terminator));
        }

        return static_cast<uint32_t>(wide.size());
    }

    // The emulated process lives in a fictional drive root: the packer only needs
    // a consistent, well formed path, not the real location of the file on disk.
    std::string sandbox_file_path(const c_emulator_ctx *ctx) {
        const auto input = ctx->get_input_path();
        const auto separator = input.find_last_of("\\/");
        const std::string file = separator == std::string::npos ? input : input.substr(separator + 1);
        return "C:\\" + file;
    }
}

void hooks::get_current_dir(const c_emulator_ctx *ctx) {
    // GetCurrentDirectoryW(nBufferLength, lpBuffer)
    const std::string directory = "C:\\";
    const auto written = write_wide_path(ctx, ctx->get_arg(1), ctx->get_arg(0), directory);
    ctx->set_result(written);
}

void hooks::get_module_filename(const c_emulator_ctx *ctx) {
    // GetModuleFileNameW(hModule, lpFilename, nSize)
    const auto path = sandbox_file_path(ctx);
    const auto written = write_wide_path(ctx, ctx->get_arg(1), ctx->get_arg(2), path);
    ctx->set_result(written);
}
