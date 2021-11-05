#include "pch.h"
#include "data_types.h"
#include "analyzer/disassembler.h"
#include "analyzer/api/MmMapIoSpace.h"

namespace driver_analyzer {

namespace static_analyzer {
namespace api {
data_types::Parameter
MmMapIoSpaceAnalazer::GetArgumentInfo(size_t   current_index,
                                      uint32_t arg_number)
{
    data_types::Parameter result = {};
    result.Index                 = arg_number;
    result.Name                  = GetParamterName(arg_number);

    //
    // Backward travers instruction before Call to find arguments (fastcall)
    //
    auto back_step = current_index + 10;

    //if ((instructions.size() - back_step) < back_step)

    for (size_t rev_index = current_index; rev_index < back_step; rev_index--)
    {
        auto & rev_inst = instruction_list_[rev_index].Instruction;

        auto & rev_first_operand  = rev_inst.operands[0];
        auto & rev_second_operand = rev_inst.operands[1];

        auto argument_register = m_disassembler->GetFastCallArgumentRegister(arg_number);

        if (m_disassembler->IsSameRegister(rev_first_operand.reg.value, argument_register) == false)
            continue;

        if (arg_number == 3)
        {
            result.Value = GetMmMapIoSpaceCacheType(instruction_list_[rev_index]);
            break;
        }

        if (rev_inst.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_XOR)
        {
            if (m_disassembler->IsRegXoredByItSelf(rev_inst, argument_register))
            {
                result.Value = "0x0";
                break;
            }
        }

        if (rev_inst.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_MOV ||
            rev_inst.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_SETNZ)
        {
            if (m_disassembler->IsImmMovToReg(rev_inst, argument_register))
            {
                result.ValueType = data_types::ValueType::kImmediate;
                result.Value     = utils::IntToHex(rev_second_operand.imm.is_signed ? rev_second_operand.imm.value.s : rev_second_operand.imm.value.u);

                break;
            }

            if (m_disassembler->IsRegMovToReg(rev_inst, argument_register))
            {
                result.ValueType = data_types::ValueType::kRegister;
                result.Value     = ZydisRegisterGetString(rev_second_operand.reg.value);

                break;
            }

            if (m_disassembler->IsMemMovToReg(rev_inst, argument_register))
            {
                result.ValueType = data_types::ValueType::kMemoryAddress;
                result.Value     = m_disassembler->FormatOperand(instruction_list_[rev_index], 1);

                break;
            }
        }
    }

    return result;
}
}  // namespace api
}  // namespace static_analyzer
}  // namespace driver_analyzer