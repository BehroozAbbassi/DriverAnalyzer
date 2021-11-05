#include "pch.h"
#include "data_types.h"
#include "analyzer/disassembler.h"

namespace driver_analyzer {

namespace static_analyzer {
std::vector<data_types::disassemlber::DisInstruction>
Diassembler::GetDisassembledCode()
{
    DisassembleCode(reinterpret_cast<uint8_t *>(m_rawData.data()),
                    m_rawData.size(),
                    m_instructions);
    return m_instructions;
}
std::string
Diassembler::FormatInstruction(
    const data_types::disassemlber::DisInstruction & inst)
{
    char           formattedBuffer[MAX_PATH];
    char           address[MAX_PATH];
    ZydisFormatter formatter;
    ZyanU64        runtime_address = inst.Address;
    if (!ZYAN_SUCCESS(
            ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)))
        return "";

    ZydisFormatterSetProperty(
        &formatter,
        ZydisFormatterProperty::ZYDIS_FORMATTER_PROP_FORCE_SEGMENT,
        ZYAN_TRUE);

    memset(formattedBuffer, 0, sizeof(formattedBuffer));
    if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(
            &formatter,
            &inst.Instruction,
            formattedBuffer,
            sizeof(formattedBuffer),
            runtime_address)))
    {
        sprintf_s(address, MAX_PATH, "0x%016" PRIX64 "  %s", runtime_address, formattedBuffer);
    }

    return address;
}
bool
Diassembler::GetPritableDisassembledCode(
    const std::vector<ZydisDecodedInstruction> & instructions,
    std::vector<std::string> &                   result)
{
    char           formattedBuffer[MAX_PATH];
    ZydisFormatter formatter;
    ZyanU64        runtime_address = m_disassmblerOptions.BaseRuntimeAddr;
    if (!ZYAN_SUCCESS(
            ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)))
        return false;

    for (auto && instruction : instructions)
    {
        memset(formattedBuffer, 0, sizeof(formattedBuffer));
        if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(
                &formatter,
                &instruction,
                formattedBuffer,
                sizeof(formattedBuffer),
                runtime_address)))
        {
            char address[MAX_PATH];
            sprintf_s(address, MAX_PATH, "0x%016" PRIX64 "  %s", runtime_address, formattedBuffer);

            result.push_back(address);

            runtime_address += instruction.length;
        }
    }

    return true;
}
bool
Diassembler::IsSameRegister(ZydisRegister a, ZydisRegister b)
{
#define GP_REGISTER_COUNT ((ZYDIS_REGISTER_R15 - ZYDIS_REGISTER_RAX) + 1)
    if (a == b)
    {
        return TRUE;
    }
#undef max
    if (a <= ZYDIS_REGISTER_R15 && a >= ZYDIS_REGISTER_AX)
    {
        for (auto i = ((a - ZYDIS_REGISTER_AX) % GP_REGISTER_COUNT) +
                      ZYDIS_REGISTER_AX;
             i <= std::max(a, b);
             i += GP_REGISTER_COUNT)
        {
            if (b == i)
            {
                return TRUE;
            }
        }
    }

    return FALSE;
}
ZydisRegister
Diassembler::GetFastCallArgumentRegister(uint32_t arg_number)
{
    switch (arg_number)
    {
    case 1:
        return ZydisRegister::ZYDIS_REGISTER_RCX;
    case 2:
        return ZydisRegister::ZYDIS_REGISTER_RDX;
    case 3:
        return ZydisRegister::ZYDIS_REGISTER_R8;
    case 4:
        return ZydisRegister::ZYDIS_REGISTER_R9;
    default:
        break;
    }

    return ZydisRegister::ZYDIS_REGISTER_NONE;
}
bool
Diassembler::IsRegXoredByItSelf(const ZydisDecodedInstruction & inst, const ZydisRegister & reg)
{
    if (inst.mnemonic != ZydisMnemonic::ZYDIS_MNEMONIC_XOR)
        return false;

    auto & first_operand = inst.operands[0];
    auto & sec_operand   = inst.operands[1];

    // mov reg, reg
    if ((first_operand.type == ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER &&
         IsSameRegister(first_operand.reg.value, reg)) &&
        (sec_operand.type == first_operand.type &&
         sec_operand.reg.value == first_operand.reg.value))
    {
        return true;
    }

    return false;
}
bool
Diassembler::IsRegMovToReg(const ZydisDecodedInstruction & inst, const ZydisRegister & reg)
{
    if (inst.mnemonic != ZydisMnemonic::ZYDIS_MNEMONIC_MOV)
        return false;

    auto & first_operand = inst.operands[0];
    auto & sec_operand   = inst.operands[1];

    // mov reg, ???
    if (first_operand.type != ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER ||
        !IsSameRegister(first_operand.reg.value, reg))
        return false;

    if (sec_operand.type == ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER)
        return true;
    return false;
}
bool
Diassembler::IsImmMovToReg(const ZydisDecodedInstruction & inst, const ZydisRegister & reg)
{
    if (inst.mnemonic != ZydisMnemonic::ZYDIS_MNEMONIC_MOV)
        return false;

    auto & first_operand = inst.operands[0];
    auto & sec_operand   = inst.operands[1];

    // mov reg, ???
    if (first_operand.type != ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER ||
        !IsSameRegister(first_operand.reg.value, reg))
        return false;

    if (sec_operand.type == ZydisOperandType::ZYDIS_OPERAND_TYPE_IMMEDIATE)
        return true;
    return false;
}
bool
Diassembler::IsMemMovToReg(const ZydisDecodedInstruction & inst, const ZydisRegister & reg)
{
    if (inst.mnemonic != ZydisMnemonic::ZYDIS_MNEMONIC_MOV)
        return false;

    auto & first_operand = inst.operands[0];
    auto & sec_operand   = inst.operands[1];

    // mov reg, ???
    if (first_operand.type != ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER ||
        !IsSameRegister(first_operand.reg.value, reg))
        return false;

    if (sec_operand.type == ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY)
        return true;

    return false;
}
bool
Diassembler::DisassembleCode(const uint8_t * pRawData, const size_t rawDataSize, std::vector<data_types::disassemlber::DisInstruction> & result)
{
    if (pRawData == nullptr || rawDataSize <= 0)
        return false;

    ZydisDecodedInstruction instruction = {};
    ZydisDecoder            decoder;
    ZyanStatus              status              = ZYAN_STATUS_SUCCESS;
    size_t                  offset              = 0;
    ZyanU64                 instruction_address = m_disassmblerOptions.BaseRuntimeAddr;

    if (not ZYAN_SUCCESS(ZydisDecoderInit(&decoder,
                                          m_disassmblerOptions.MachineMode,
                                          m_disassmblerOptions.AddressWidth)))
        return false;

    while (offset < rawDataSize)
    {
        status = ZydisDecoderDecodeBuffer(&decoder, pRawData + offset, rawDataSize - offset, &instruction);
        if (ZYAN_SUCCESS(status))
        {
            // printf("0x%016" PRIX64 "\n", instruction_address);

            result.push_back({instruction_address, instruction});

            offset += instruction.length;
            instruction_address += instruction.length;
        }
        else
        {
            // printf("%" PRIXPTR "\n", pRawData[offset]);
            offset++;
            instruction_address++;
        }
    }

    return true;
}
}  // namespace static_analyzer
}  // namespace driver_analyzer