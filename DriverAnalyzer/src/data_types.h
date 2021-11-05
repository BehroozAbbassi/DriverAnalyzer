#pragma once

namespace data_types {

namespace disassemlber {

struct DisassmblerOptions
{
    ZydisAddressWidth AddressWidth;
    ZydisMachineMode  MachineMode;
    uint64_t          BaseRuntimeAddr;
};

struct DisInstruction
{
    uint64_t                Address;
    ZydisDecodedInstruction Instruction;

    // bool operator==(const DisInstruction & left, const DisInstruction & right)
    //{
    //    return &left == &right;
    //}
};
}  // namespace disassemlber

namespace analyzer {

struct ExecutableSectionDisassembly
{
    std::string                               Name;
    std::vector<disassemlber::DisInstruction> Instructions;
};

}  // namespace analyzer

struct PeFileVersionInfo
{
    std::string CompanyName;
    std::string FileDescription;
    std::string FileVersion;
    std::string InternalName;
    std::string LegalCopyright;
    std::string OriginalFileName;
    std::string ProductName;
    std::string ProductVersion;

    template <class Archive>
    void serialize(Archive & ar)
    {
        ar(CEREAL_NVP(CompanyName),
           CEREAL_NVP(FileDescription),
           CEREAL_NVP(FileVersion),
           CEREAL_NVP(InternalName),
           CEREAL_NVP(LegalCopyright),
           CEREAL_NVP(OriginalFileName),
           CEREAL_NVP(ProductName),
           CEREAL_NVP(ProductVersion));
    }
};

struct PeFileInfo
{
    std::string Name;
    std::string ImagePath;
    std::string FileSize;

    PeFileVersionInfo Version;

    template <class Archive>
    void serialize(Archive & ar)
    {
        ar(CEREAL_NVP(Name),
           CEREAL_NVP(ImagePath),
           CEREAL_NVP(FileSize),
           CEREAL_NVP(Version));
    }
};

struct Instruction_t
{
    std::uint64_t                Offset = 0;
    disassemlber::DisInstruction Instruction;
    std::string                  FormattedInstruction;

    template <class Archive>
    void serialize(Archive & ar)
    {
        ar(CEREAL_NVP(Offset),
           // CEREAL_NVP(Instruction),
           CEREAL_NVP(FormattedInstruction));
    }
};

struct SuspiciousInstructions
{
    std::vector<Instruction_t> Instructions;
    std::uint64_t              Count = 0;

    template <class Archive>
    void serialize(Archive & ar)
    {
        ar(CEREAL_NVP(Instructions),
           CEREAL_NVP(Count));
    }
};

enum class ValueType : uint8_t
{
    kImmediate,
    kRegister,
    kMemoryAddress
};

struct Parameter
{
    std::string   Name;
    std::uint32_t Index;
    std::string   Value;
    ValueType     ValueType;

    std::string to_string() const
    {
        std::stringstream ss;

        ss << Name << "= " << Value;

        return ss.str();
    }

    template <class Archive>
    void serialize(Archive & ar)
    {
        ar(CEREAL_NVP(Name),
           CEREAL_NVP(Index),
           CEREAL_NVP(Value));
    }
};

struct FunctionCall
{
    std::string               Name;
    std::vector<Parameter>    Parameters;
    data_types::Instruction_t Instruction;

    template <class Archive>
    void serialize(Archive & ar)
    {
        ar(CEREAL_NVP(Name),
           CEREAL_NVP(Instruction),
           CEREAL_NVP(Parameters));
    }
};

struct SuspiciousSection
{
    std::string Name;

    SuspiciousInstructions Cr3;
    SuspiciousInstructions Cr4;
    SuspiciousInstructions Msr;

    std::vector<FunctionCall> ApiCalls;

    template <class Archive>
    void serialize(Archive & ar)
    {
        ar(CEREAL_NVP(Name),
           CEREAL_NVP(Cr3),
           CEREAL_NVP(Cr4),
           CEREAL_NVP(Msr),
           CEREAL_NVP(ApiCalls));
    }
};

struct SuspiciousDriver
{
    PeFileInfo                     FileInfo;
    uint32_t                       IatScore     = 0;
    uint32_t                       Cr3Score     = 0;
    uint32_t                       Cr4Score     = 0;
    uint32_t                       MsrScore     = 0;
    uint32_t                       ApiCallScore = 0;
    std::vector<std::string>       Imports;
    std::vector<SuspiciousSection> Sections;

    template <class Archive>
    void serialize(Archive & ar)
    {
        ar(CEREAL_NVP(FileInfo),
           CEREAL_NVP(IatScore),
           CEREAL_NVP(Cr3Score),
           CEREAL_NVP(Cr4Score),
           CEREAL_NVP(MsrScore),
           CEREAL_NVP(Imports),
           CEREAL_NVP(Sections));
    }
};

}  // namespace data_types