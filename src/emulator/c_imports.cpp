#include <filesystem>

#include "c_emulator_ctx.hpp"
#include "../helpers/utils.hpp"
#include "../helpers/json.hpp"
#include "../pe/c_pe_image.hpp"
#include "../pe/pe_structs.hpp"
#include "../pe/pe_utils.hpp"

static std::shared_ptr<const nlohmann::json> get_catalog(const std::string &catalog_name) {
    static std::unordered_map<std::string, std::shared_ptr<const nlohmann::json>> cache;

    if (const auto it = cache.find(catalog_name); it != cache.end()) {
        return it->second;
    }

    std::shared_ptr<const nlohmann::json> catalog = nullptr;

    if (std::filesystem::exists(catalog_name)) {
        std::ifstream catalog_stream(catalog_name);
        catalog = std::make_shared<const nlohmann::json>(nlohmann::json::parse(catalog_stream));
    }

    cache.emplace(catalog_name, catalog);
    return catalog;
}

c_imports::c_imports(c_emulator_ctx *emulator_ctx) : m_emulator_ctx(emulator_ctx) {
    // create modules directory if it doesn't exist
    if (!std::filesystem::is_directory("modules")) {
        std::filesystem::create_directory("modules");
    }
}

uint64_t c_imports::load_module(std::string module_name) {
    std::ranges::transform(module_name, module_name.begin(), [](const unsigned char c) {
        return std::tolower(c);
    });

    if (const auto module = m_module_addresses.find(module_name); module != m_module_addresses.end()) {
        return module->second;
    }

    std::shared_ptr<c_pe_image> pe_image = nullptr;
    std::vector<s_dummy_export> exports = {};

    // if the module exists in local directory, load it from there
    if (std::filesystem::exists("modules/" + module_name)) {
        pe_image = std::make_shared<c_pe_image>(utils::read_file("modules/" + module_name));
    }

    const std::string catalog_name = m_emulator_ctx->get_arch() == e_architecture::k_x86 ?
        "catalog_32.json" : "catalog.json";

    // fallback to resolving from catalog
    const auto catalog_ptr = pe_image ? nullptr : get_catalog(catalog_name);

    if (catalog_ptr) {
        const auto &catalog = *catalog_ptr;

        // resolve api set (if applicable)
        if (catalog.contains("api_sets") && catalog.at("api_sets").contains(module_name)) {
            module_name = catalog.at("api_sets").at(module_name).get<std::string>();
        }

        // manually parse exports if the record in catalog DOES exist
        if (catalog.contains("modules") && catalog.at("modules").contains(module_name)) {
            const auto &catalog_exports = catalog.at("modules").at(module_name).at(
                "exports").get_ref<const nlohmann::json::array_t&>();
            exports.reserve(catalog_exports.size());
            for (const auto &pe_export : catalog_exports) {
                //
                exports.push_back(s_dummy_export{
                    .m_name = pe_export.at("name").is_string() ? pe_export.at("name").get<std::string>() :
                        std::to_string(pe_export.at("ordinal").get<uint32_t>()),
                    .m_module = module_name,
                    .m_ordinal = pe_export.at("ordinal").get<uint32_t>(),
                    .m_entry_address = 0,
                });
            }
        }
    }

    if (!pe_image && exports.empty()) {
        return 0;
    }

    uint64_t original_image_base = 0x1000000;

    if (pe_image) {
        exports.reserve(pe_image->get_exports().size());
        for (const auto &pe_export : pe_image->get_exports()) {
            exports.push_back(s_dummy_export{
                .m_name = pe_export.m_name,
                .m_module = module_name,
                .m_ordinal = pe_export.m_ordinal,
                .m_entry_address = 0,
            });
        }

        original_image_base = pe_image->get_image_base();
    }

    // create dummy DLL with export descriptors only
    const auto dummy = pe_utils::create_dummy_dll(m_emulator_ctx->get_arch(),
        original_image_base, module_name, exports);

    const auto image_base = m_emulator_ctx->map_dummy_module(dummy, module_name);

    const auto nt_offset = *reinterpret_cast<const uint32_t*>(dummy.data() +
        offsetof(unthemidator::pe::s_dos_header, e_lfanew));
    const auto optional_header = image_base + nt_offset + sizeof(uint32_t) +
        sizeof(unthemidator::pe::s_coff_header);

    // update base address
    switch (m_emulator_ctx->get_arch()) {
        case e_architecture::k_x86: {
            const auto new_base = static_cast<uint32_t>(image_base);

            uc_mem_write(m_emulator_ctx->get_uc(), optional_header +
                offsetof(unthemidator::pe::s_optional_header_32, image_base), &new_base, sizeof(new_base));

            break;
        }

        case e_architecture::k_amd64: {
            uc_mem_write(m_emulator_ctx->get_uc(), optional_header +
                offsetof(unthemidator::pe::s_optional_header_64, image_base), &image_base, sizeof(image_base));

            break;
        }

        default:
            throw std::runtime_error("unsupported architecture");
    }

    m_module_addresses.emplace(module_name, image_base);
    m_modules.emplace(image_base, module_name);
    m_exports_by_name.emplace(module_name, std::unordered_map<std::string, s_dummy_export>{});
    auto &module_exports = m_exports_by_name.at(module_name);
    module_exports.reserve(exports.size());

    // save all export addresses
    for (auto &pe_export : exports) {
        pe_export.m_entry_address += image_base;

        module_exports.emplace(pe_export.m_name, pe_export);
        m_exports_by_va.emplace(pe_export.m_entry_address, std::make_pair(module_name, pe_export.m_name));

        /*
        if (module_name.find("ucrt") != std::string::npos || module_name.find("api-") != std::string::npos ||
            module_name.find("msvc") != std::string::npos) {
            continue;
        }

        printf("0x%llX - %s %s\n", pe_export.m_entry_address, module_name.c_str(), pe_export.m_name.c_str());*/
    }

    return image_base;
}

uint64_t c_imports::resolve_import(const std::string &module_name, const std::string &function_name) const {
    const auto it_mod_exports = m_exports_by_name.find(module_name);

    if (it_mod_exports == m_exports_by_name.end()) {
        return 0;
    }

    const auto it_export = it_mod_exports->second.find(function_name);

    if (it_export == it_mod_exports->second.end()) {
        return 0;
    }

    return it_export->second.m_entry_address;
}

uint64_t c_imports::resolve_import(const uint64_t module_base, const std::string &function_name) const {
    const auto module = m_modules.find(module_base);

    if (module == m_modules.end()) {
        return 0;
    }

    const auto &mod_exports = m_exports_by_name.at(module->second);
    const auto it_export = mod_exports.find(function_name);

    if (it_export == mod_exports.end()) {
        return 0;
    }

    return it_export->second.m_entry_address;
}

uint64_t c_imports::resolve_import(const uint64_t module_base, const uint16_t ordinal) const {
    const auto module = m_modules.find(module_base);
    if (module == m_modules.end()) {
        return 0;
    }

    for (const auto &[name, entry] : m_exports_by_name.at(module->second)) {
        if (entry.m_ordinal == ordinal) {
            return entry.m_entry_address;
        }
    }

    return 0;
}

const s_dummy_export * c_imports::find_import_by_address(const uint64_t address) {
    const auto entry = m_exports_by_va.find(address);
    if (entry == m_exports_by_va.end()) {
        return nullptr;
    }

    const auto &[mod_name, fn_name] = entry->second;
    return &m_exports_by_name.at(mod_name).at(fn_name);
}
