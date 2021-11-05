#pragma once

#include "data_types.h"
#include "analyzer/disassembler.h"
#include "analyzer/api/MmMapIoSpace.h"

namespace driver_analyzer {

namespace static_analyzer {

struct SuspiciousProperties
{
    std::vector<std::string> imported_functions;
};

class Vulnerability
{
public:
    Vulnerability(const std::string &          pe_file_name,
                  const SuspiciousProperties & suspicious_properties) :
        pe_file_name_(pe_file_name),
        suspicious_properties_(suspicious_properties)

    {
        try
        {
            m_peFile = LIEF::PE::Parser::parse(pe_file_name);
        }
        catch (const LIEF::exception & err)
        {
            std::cerr << err.what() << std::endl;
        }
    }

    bool AnalazeFile()
    {
        const auto imports = GetImportTable();
        if (imports.has_value())
            import_table_ = imports.value();

        GetExecutableSectionDisassembly(ExecutableSectionDisassembly);

        is_analyzed_ = true;

        return is_analyzed_;
    }

    data_types::SuspiciousInstructions
    CheckForReadWriteOnMsr(const std::vector<data_types::disassemlber::DisInstruction> & instructions)
    {
        data_types::SuspiciousInstructions result = {};

        for (const auto & inst : instructions)
        {
            if (IsInstructionMsrAccess(inst))
            {
                data_types::Instruction_t entry;
                entry.Offset               = inst.Address;
                entry.Instruction          = inst;
                entry.FormattedInstruction = m_disassembler->FormatInstruction(inst);

                result.Instructions.push_back(entry);
            }
        }

        return result;
    }

    data_types::SuspiciousInstructions
    CheckForCr3(const std::vector<data_types::disassemlber::DisInstruction> & instructions)
    {
        data_types::SuspiciousInstructions result = {};
        data_types::Instruction_t          entry  = {};
        for (auto & instruction : instructions)
        {
            // intrinsic
            // __readcr3()  mov rax, cr3
            // __writecr3() mov cr3, rcx
            //

            //if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV)// && instruction.operand_count >= 2)
            {
                if (instruction.Instruction.operands[0].reg.value == ZYDIS_REGISTER_CR3 ||
                    instruction.Instruction.operands[1].reg.value == ZYDIS_REGISTER_CR3)
                {
                    entry.Offset               = instruction.Address;
                    entry.Instruction          = instruction;
                    entry.FormattedInstruction = m_disassembler->FormatInstruction(instruction);

                    result.Instructions.push_back(entry);
                }
            }
        }

        return result;
    }

    data_types::SuspiciousInstructions
    CheckForCr4(const std::vector<data_types::disassemlber::DisInstruction> & instructions)
    {
        data_types::SuspiciousInstructions result = {};
        data_types::Instruction_t          entry  = {};
        for (auto & instruction : instructions)
        {
            //
            // Can be used with bitwise instructions like BTS ...
            //

            //if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV && instruction.operand_count >= 2)
            {
                if (instruction.Instruction.operands[0].reg.value == ZYDIS_REGISTER_CR4 ||
                    instruction.Instruction.operands[1].reg.value == ZYDIS_REGISTER_CR4)
                {
                    entry.Offset               = instruction.Address;
                    entry.Instruction          = instruction;
                    entry.FormattedInstruction = m_disassembler->FormatInstruction(instruction);

                    result.Instructions.push_back(entry);
                }
            }
        }

        return result;
    }

    data_types::SuspiciousInstructions
    CheckForGs(const std::vector<data_types::disassemlber::DisInstruction> & instructions)
    {
        data_types::SuspiciousInstructions result = {};
        data_types::Instruction_t          entry  = {};
        for (auto & instruction : instructions)
        {
            //
            // dt _KPRCB poi(gs:[0x20]) ProcessorState.SpecialRegisters.Cr3
            //
            // gs:20 points to _KPCRB and can be used to obtain system CR3 (PML4) base address.
            //

            //if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV && instruction.operand_count >= 2)
            {
                if (instruction.Instruction.operands[0].reg.value == ZYDIS_REGISTER_GS ||
                    instruction.Instruction.operands[1].reg.value == ZYDIS_REGISTER_GS)
                {
                    entry.Offset               = instruction.Address;
                    entry.Instruction          = instruction;
                    entry.FormattedInstruction = m_disassembler->FormatInstruction(instruction);

                    result.Instructions.push_back(entry);
                }
            }
        }

        return std::move(result);
    }

    std::optional<std::vector<std::string>> GetImportTable() const
    {
        if (IsPeKernelDriver() == false)
            return std::nullopt;

        if (m_peFile->has_imports() == false)
            return std::nullopt;

        std::vector<std::string> result = {};
        for (const auto fn : m_peFile->imported_functions())
        {
            result.push_back(fn.name());
        }

        return result;
    }

    std::vector<std::string> GetMatchedSuspiciousImports()
    {
        std::vector<std::string> result = {};
        for (const auto & import : import_table_)
        {
            if (std::find(suspicious_properties_.imported_functions.begin(),
                          suspicious_properties_.imported_functions.end(),
                          import) != suspicious_properties_.imported_functions.end())
            {
                //std::clog << "Import " << import << "\n";

                result.push_back(import);
            }
        }
        return result;
    }

    bool
    GetExecutableSectionDisassembly(std::vector<data_types::analyzer::ExecutableSectionDisassembly> & result)
    {
        if (!IsPeKernelDriver())
            return false;

        for (const auto & section : m_peFile->sections())
        {
            if (section.has_characteristic(LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE))
            {
                const std::vector<uint8_t> section_raw_data = section.content();
                if (section_raw_data.size() == 0)
                    continue;

                data_types::disassemlber::DisassmblerOptions disassmbler_options = {};

                auto image_base = m_peFile->optional_header().imagebase();
                auto section_va = section.virtual_address();

                //std::cout << "[+] Section name " << section.name() << "   base va  " << section.virtual_address() << " \n";

                //
                // Base address for the disassembler
                //
                disassmbler_options.BaseRuntimeAddr = (image_base + section_va);

                if (m_peFile->header().machine() == LIEF::PE::MACHINE_TYPES::IMAGE_FILE_MACHINE_AMD64)
                {
                    disassmbler_options.AddressWidth = ZYDIS_ADDRESS_WIDTH_64;
                    disassmbler_options.MachineMode  = ZYDIS_MACHINE_MODE_LONG_64;
                }
                else if (m_peFile->header().machine() == LIEF::PE::MACHINE_TYPES::IMAGE_FILE_MACHINE_I386)
                {
                    disassmbler_options.AddressWidth = ZYDIS_ADDRESS_WIDTH_32;
                    disassmbler_options.MachineMode  = ZYDIS_MACHINE_MODE_LEGACY_32;
                }

                m_disassembler      = std::make_unique<Diassembler>(section_raw_data, disassmbler_options);
                m_disassembledCodes = m_disassembler->GetDisassembledCode();

                data_types::analyzer::ExecutableSectionDisassembly item = {};
                item.Name                                               = section.name();
                item.Instructions                                       = m_disassembledCodes;

                result.push_back(item);
            }
        }

        return true;
    }

    std::vector<data_types::SuspiciousSection> GetSuspiciousSections()
    {
        std::vector<data_types::SuspiciousSection> result = {};

        for (const auto & section : ExecutableSectionDisassembly)
        {
            data_types::SuspiciousSection section_info = {};

            section_info.ApiCalls = GetSuspiciousApiCalls(section.Instructions);

            section_info.Name = section.Name;
            section_info.Cr3  = CheckForCr3(section.Instructions);
            section_info.Cr4  = CheckForCr4(section.Instructions);
            section_info.Msr  = CheckForReadWriteOnMsr(section.Instructions);

            if (section_info.Cr3.Instructions.size() ||
                section_info.Cr4.Instructions.size() || section_info.ApiCalls.size() ||
                section_info.Msr.Instructions.size())
            {
                result.push_back(std::move(section_info));
            }
        }

        return result;
    }

    bool IsSuspicious()
    {
        if (is_analyzed_ == false)
            AnalazeFile();

        const auto &                 suspicious_imports  = GetMatchedSuspiciousImports();
        const auto &                 suspicious_sections = GetSuspiciousSections();
        data_types::SuspiciousDriver driver_score_       = {};

        driver_score_.IatScore = suspicious_imports.size();
        ImportTableRate        = ((suspicious_imports.size() * 100) / suspicious_properties_.imported_functions.size());
        //std::cout << "[*] Import table rate : " << ImportTableRate << "% \n";

        std::for_each(suspicious_sections.begin(), suspicious_sections.end(), [&](const data_types::SuspiciousSection & section_info) {
            driver_score_.Cr3Score += section_info.Cr3.Instructions.size();
            driver_score_.Cr4Score += section_info.Cr4.Instructions.size();
            driver_score_.MsrScore += section_info.Msr.Instructions.size();
            driver_score_.ApiCallScore += section_info.ApiCalls.size();
        });

        if (driver_score_.IatScore ||
            driver_score_.Cr3Score ||
            driver_score_.ApiCallScore ||
            driver_score_.Cr4Score || driver_score_.Sections.size())

        {
            //
            // TODO: Add more meaningful criteria
            //
            return true;
        }

        return false;
    }

    data_types::SuspiciousDriver GetSuspiciousDriver()
    {
        data_types::SuspiciousDriver result = {};

        const auto & suspicious_imports  = GetMatchedSuspiciousImports();
        const auto & suspicious_sections = GetSuspiciousSections();

        result.IatScore = suspicious_imports.size();
        ImportTableRate = ((suspicious_imports.size() * 100) / suspicious_properties_.imported_functions.size());
        //std::cout << "[*] Import table rate : " << ImportTableRate << "% \n";

        std::for_each(suspicious_sections.begin(), suspicious_sections.end(), [&](const data_types::SuspiciousSection & section_info) {
            result.Cr3Score += section_info.Cr3.Instructions.size();
            result.Cr4Score += section_info.Cr4.Instructions.size();
            result.MsrScore += section_info.Msr.Instructions.size();
            result.ApiCallScore += section_info.ApiCalls.size();
        });

        if (result.IatScore ||
            result.Cr3Score ||
            result.Cr4Score ||
            result.ApiCallScore ||
            result.MsrScore)

        {
            result.Imports  = suspicious_imports;
            result.Sections = suspicious_sections;
            result.FileInfo = GetPeFileInfo();
        }

        return result;
    }

    std::vector<data_types::FunctionCall>
    GetSuspiciousApiCalls(const std::vector<data_types::disassemlber::DisInstruction> & instructions)
    {
        data_types::SuspiciousInstructions result = {};
        data_types::Instruction_t          entry  = {};

        std::vector<data_types::FunctionCall> api_calls = {};

        for (size_t inst_index = 0; inst_index < instructions.size(); inst_index++)
        {
            const auto & curr_inst = instructions[inst_index];
            if (curr_inst.Instruction.mnemonic != ZydisMnemonic::ZYDIS_MNEMONIC_CALL)
                continue;

            const ZydisDecodedOperand & first_operand = curr_inst.Instruction.operands[0];
            if (first_operand.type == ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY && first_operand.mem.segment == ZydisRegister::ZYDIS_REGISTER_DS)
            {
                //
                // TODO: add more APIs
                //
                api::MmMapIoSpaceAnalazer mm_map_io(instructions, inst_index);

                ZyanU64 target_fun_addr = 0;
                ZydisCalcAbsoluteAddress(&curr_inst.Instruction,
                                         &first_operand,
                                         curr_inst.Address,
                                         &target_fun_addr);

                const auto image_base = m_peFile->optional_header().imagebase();
                for (auto const & iat_fn : m_peFile->imported_functions())
                {
                    auto iat_func_addr = image_base + iat_fn.address();
                    if (iat_func_addr == target_fun_addr)
                    {
                        if (iat_fn.name() == mm_map_io.Name())
                        {
                            mm_map_io.Analyze(iat_fn.name());

                            //std::cout << mm_map_io.to_string();

                            api_calls.push_back(mm_map_io.GetFunctionCall());
                        }
                    }
                }

                entry.Offset               = curr_inst.Address;
                entry.Instruction          = curr_inst;
                entry.FormattedInstruction = m_disassembler->FormatInstruction(curr_inst);

                result.Instructions.push_back(entry);
            }
        }
        return api_calls;
    }

private:
    inline bool IsInstructionMsrAccess(const data_types::disassemlber::DisInstruction & inst) const
    {
        return inst.Instruction.mnemonic == ZYDIS_MNEMONIC_RDMSR ||
               inst.Instruction.mnemonic == ZYDIS_MNEMONIC_WRMSR;
    }

    inline bool IsInstructionGsAccess(const data_types::disassemlber::DisInstruction & inst) const
    {
        return inst.Instruction.operands[0].reg.value == ZYDIS_REGISTER_GS ||
               inst.Instruction.operands[1].reg.value == ZYDIS_REGISTER_GS;
    }

    inline bool IsInstructionCr3Access(const data_types::disassemlber::DisInstruction & inst) const
    {
        return inst.Instruction.operands[0].reg.value == ZYDIS_REGISTER_CR3 ||
               inst.Instruction.operands[1].reg.value == ZYDIS_REGISTER_CR3;
    }

    inline bool IsInstructionCr4Access(const data_types::disassemlber::DisInstruction & inst) const
    {
        return inst.Instruction.operands[0].reg.value == ZYDIS_REGISTER_CR4 ||
               inst.Instruction.operands[1].reg.value == ZYDIS_REGISTER_CR4;
    }

    bool IsPeKernelDriver() const
    {
        return m_peFile->optional_header().subsystem() == LIEF::PE::SUBSYSTEM::IMAGE_SUBSYSTEM_NATIVE;
    }

    data_types::PeFileInfo GetPeFileInfo()
    {
        data_types::PeFileInfo result = {};

        result.ImagePath = pe_file_name_;
        result.Name      = utils::GetFileName(pe_file_name_);
        result.FileSize  = utils::GeFormattedtFileSize(pe_file_name_);

        // if (m_peFile->has_signature())
        //{
        //     auto sign = m_peFile->signature();
        //}

        if (m_peFile->has_resources() and m_peFile->resources_manager().has_version())
        {
            auto version = m_peFile->resources_manager().version();
            for (auto const & item : version.string_file_info().langcode_items())
            {
                data_types::PeFileVersionInfo versionInfo = {};
                for (const auto /*std::pair<std::u16string, std::u16string>*/ & p : item.items())
                {
                    auto key   = LIEF::u16tou8(p.first);
                    auto value = LIEF::u16tou8(p.second);

                    if (key == "CompanyName")
                        versionInfo.CompanyName = value;
                    else if (key == "FileDescription")
                        versionInfo.FileDescription = value;
                    else if (key == "FileVersion")
                        versionInfo.FileVersion = value;
                    else if (key == "InternalName")
                        versionInfo.InternalName = value;
                    else if (key == "LegalCopyright")
                        versionInfo.LegalCopyright = value;
                    else if (key == "OriginalFileName")
                        versionInfo.OriginalFileName = value;
                    else if (key == "ProductName")
                        versionInfo.ProductName = value;
                    else if (key == "ProductVersion")
                        versionInfo.ProductVersion = value;
                }

                result.Version = versionInfo;
            }
        }

        return result;
    }

private:
    std::string          pe_file_name_;
    SuspiciousProperties suspicious_properties_;

    std::shared_ptr<LIEF::PE::Binary>                     m_peFile;
    std::unique_ptr<Diassembler>                          m_disassembler;
    std::vector<data_types::disassemlber::DisInstruction> m_disassembledCodes;

    std::vector<std::string>                                        import_table_;
    std::vector<data_types::analyzer::ExecutableSectionDisassembly> ExecutableSectionDisassembly;

    uint64_t                 ImportTableRate     = 0;
    uint64_t                 danger_import_count = 0;
    std::vector<std::string> imprted_functions   = {};

    bool is_analyzed_ = false;
};

}  // namespace static_analyzer
}  // namespace driver_analyzer