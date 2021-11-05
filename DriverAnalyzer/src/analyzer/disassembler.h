#pragma once

namespace driver_analyzer {

namespace static_analyzer {

class Diassembler
{
public:
    Diassembler(
        const std::vector<uint8_t> &                         raw_data,
        const data_types::disassemlber::DisassmblerOptions & disassmbler_options) :
        m_rawData(raw_data), m_disassmblerOptions(disassmbler_options) {}

    std::vector<data_types::disassemlber::DisInstruction> GetDisassembledCode();

    std::string FormatInstruction(
        const data_types::disassemlber::DisInstruction & inst);

    std::string
    FormatOperand(
        const data_types::disassemlber::DisInstruction & inst,
        const uint8_t &                                  operand_index)
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
        if (ZYAN_SUCCESS(ZydisFormatterFormatOperand(
                &formatter,
                &inst.Instruction,
                operand_index,
                formattedBuffer,
                sizeof(formattedBuffer),
                runtime_address)))
        {
            sprintf_s(address, MAX_PATH, "%s", formattedBuffer);
        }

        return address;
    }

    bool GetPritableDisassembledCode(
        const std::vector<ZydisDecodedInstruction> & instructions,
        std::vector<std::string> &                   result);

    bool IsSameRegister(ZydisRegister a, ZydisRegister b);

    ZydisRegister GetFastCallArgumentRegister(uint32_t arg_number);

    bool IsRegXoredByItSelf(const ZydisDecodedInstruction & inst,
                            const ZydisRegister &           reg);

    bool IsRegMovToReg(const ZydisDecodedInstruction & inst,
                       const ZydisRegister &           reg);

    bool IsImmMovToReg(const ZydisDecodedInstruction & inst,
                       const ZydisRegister &           reg);

    bool IsMemMovToReg(const ZydisDecodedInstruction & inst,
                       const ZydisRegister &           reg);

private:
    std::vector<uint8_t>                                  m_rawData;
    std::vector<data_types::disassemlber::DisInstruction> m_instructions;
    data_types::disassemlber::DisassmblerOptions          m_disassmblerOptions;

    bool DisassembleCode(
        const uint8_t *                                         pRawData,
        const size_t                                            rawDataSize,
        std::vector<data_types::disassemlber::DisInstruction> & result);
};

}  // namespace static_analyzer
}  // namespace driver_analyzer