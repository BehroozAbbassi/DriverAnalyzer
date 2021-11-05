#pragma once

namespace driver_analyzer {

namespace static_analyzer {
namespace api {

class MmMapIoSpaceAnalazer
{
public:
    MmMapIoSpaceAnalazer(const std::vector<data_types::disassemlber::DisInstruction> & instructions,
                         const size_t &                                                call_inst_index) :
        instruction_list_(instructions),
        call_inst_index_(call_inst_index)
    {
    }

    struct Parameters
    {
        data_types::Parameter PhysicalAddress;
        data_types::Parameter NumberOfBytes;
        data_types::Parameter CacheType;
    };

    data_types::FunctionCall GetFunctionCall()
    {
        data_types::FunctionCall result;
        result.Name = Name();

        result.Parameters.push_back(parameters_.PhysicalAddress);
        result.Parameters.push_back(parameters_.NumberOfBytes);
        result.Parameters.push_back(parameters_.CacheType);

        const auto & curr = instruction_list_[call_inst_index_];

        data_types::Instruction_t i;
        i.Offset               = curr.Address;
        i.Instruction          = curr;
        i.FormattedInstruction = m_disassembler->FormatInstruction(curr);

        result.Instruction = i;

        return result;
    }

    std::string to_string() const
    {
        //return fmt::format("MmMapIoSpace (PhysicalAddress : {0}, NumberOfBytes : {1}, CacheType : {2} );",
        //                   parameters_.PhysicalAddress.to_string(),
        //                   parameters_.NumberOfBytes.to_string(),
        //                   parameters_.CacheType.to_string());

        auto s1 = parameters_.PhysicalAddress.to_string();
        auto s2 = parameters_.NumberOfBytes.to_string();
        auto s3 = parameters_.CacheType.to_string();

        //return fmt::format("MmMapIoSpace (PhysicalAddress : {0}, NumberOfBytes : {1}, CacheType : {2} );",
        std::stringstream ss;
        ss << "MmMapIoSpace( ";

        ss << s1 << " ,"
           << s2 << " ," << s3 << " );\n";

        return ss.str();
        return "";
    }

    std::string Name() const
    {
        return "MmMapIoSpace";
    }

    bool Analyze(const std::string & function_name)
    {
        const auto &                curr_inst     = instruction_list_[call_inst_index_];
        const ZydisDecodedOperand & first_operand = curr_inst.Instruction.operands[0];

        parameters_.PhysicalAddress = GetArgumentInfo(call_inst_index_, 1);  // PhysicalAddress

        parameters_.NumberOfBytes = GetArgumentInfo(call_inst_index_, 2);  // NumberOfBytes

        parameters_.CacheType = GetArgumentInfo(call_inst_index_, 3);  // CacheType

        //printf("Call %s  ; %s\n\n", m_disassembler->FormatInstruction(curr_inst).c_str(), function_name.c_str());

        return false;
    }

    data_types::Parameter GetArgumentInfo(size_t   current_index,
                                          uint32_t arg_number);

private:
    std::string GetParamterName(const uint32_t & index)
    {
        switch (index)
        {
        case 1:
            return "PhysicalAddress";
        case 2:
            return "NumberOfBytes";
        case 3:
            return "CacheType";
        default:
            break;
        }

        return "N/A";
    }

    typedef enum _MEMORY_CACHING_TYPE
    {
        MmNonCached,
        MmCached,
        MmWriteCombined,
        MmHardwareCoherentCached,
        MmNonCachedUnordered,
        MmUSWCCached,
        MmMaximumCacheType,
        MmNotMapped
    } MEMORY_CACHING_TYPE;

    std::string GetMmMapIoSpaceCacheType(const data_types::disassemlber::DisInstruction & inst)
    {
        auto & rev_inst = inst.Instruction;

        auto & rev_first_operand  = rev_inst.operands[0];
        auto & rev_second_operand = rev_inst.operands[1];

        uint64_t cache_type = -1;

        auto argument_register = m_disassembler->GetFastCallArgumentRegister(3);

        if (rev_inst.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_XOR ||
            rev_inst.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_MOV ||
            rev_inst.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_SETNZ)
        {
            if (m_disassembler->IsRegXoredByItSelf(rev_inst, argument_register))
            {
                cache_type = 0;
            }

            if (m_disassembler->IsImmMovToReg(rev_inst, argument_register))
            {
                cache_type = rev_second_operand.imm.is_signed ? rev_second_operand.imm.value.s : rev_second_operand.imm.value.u;
            }

            if (m_disassembler->IsRegMovToReg(rev_inst, argument_register))
            {
                //std::cout << "Reg  " << m_disassembler->FormatInstruction(inst) << "\n";
            }

            if (m_disassembler->IsMemMovToReg(rev_inst, argument_register))
            {
                //std::cout << "Mem  " << m_disassembler->FormatInstruction(inst) << "\n";
            }

            switch (cache_type)
            {
            case MEMORY_CACHING_TYPE::MmNonCached:
                return "MmNonCached";
            case MEMORY_CACHING_TYPE::MmCached:
                return "MmCached";
            case MEMORY_CACHING_TYPE::MmWriteCombined:
                return "MmWriteCombined";
            case MEMORY_CACHING_TYPE::MmHardwareCoherentCached:
                return "MmHardwareCoherentCached";
            case MEMORY_CACHING_TYPE::MmNonCachedUnordered:
                return "MmNonCachedUnordered";
            case MEMORY_CACHING_TYPE::MmUSWCCached:
                return "MmUSWCCached";
            case MEMORY_CACHING_TYPE::MmMaximumCacheType:
                return "MmMaximumCacheType";
            case MEMORY_CACHING_TYPE::MmNotMapped:
                return "MmNotMapped";
            default:
                //printf("ccc\n");
                break;
            }
        }

        return "N/A";
    }

private:
    std::string                                           m_fileName;
    std::shared_ptr<LIEF::PE::Binary>                     m_peFile;
    std::unique_ptr<Diassembler>                          m_disassembler;
    std::vector<data_types::disassemlber::DisInstruction> m_disassembledCodes;
    std::vector<data_types::disassemlber::DisInstruction> instruction_list_;
    size_t                                                call_inst_index_;
    Parameters                                            parameters_;
};
}  // namespace api

}  // namespace static_analyzer
}  // namespace driver_analyzer