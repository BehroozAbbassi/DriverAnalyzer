#include "pch.h"
#include "utils/utils.h"
#include "analyzer/analyzer.h"

namespace driver_analyzer {
namespace options {
struct CommandLineOptions
{
    std::string input_directory_path;
    std::string backup_directory_path;
    std::string json_report_file_name;
};

namespace detail {
std::optional<CommandLineOptions>
ParseCommandLine(int argc, char * argv[])
{
    cxxopts::Options options("Vulnerable Driver Scanner", "");

    options.add_options()("i,input", "Path of directory that contains Driver files (*.sys)", cxxopts::value<std::string>());
    options.add_options()("o,output", "Full name of JSON report", cxxopts::value<std::string>());
    options.add_options()("b,backup",
                          "Path of backup directory to have a copy of suspicious driver files",
                          cxxopts::value<std::string>());

    auto cmd_result = options.parse(argc, argv);

    CommandLineOptions commandline_options = {};

    try
    {
        commandline_options.input_directory_path =
            cmd_result["input"].as<std::string>();
        commandline_options.json_report_file_name =
            cmd_result["output"].as<std::string>();
        commandline_options.backup_directory_path =
            cmd_result["backup"].as<std::string>();

        return commandline_options;
    }
    catch (...)
    {
        std::cout << options.help();
        return std::nullopt;
    }
}

}  // namespace detail
}  // namespace options

namespace program {

static_analyzer::SuspiciousProperties suspicious_properties;

enum class AnalyzeSeverity
{
    kRestrict,
    kHigh,
    kMedium,
    kLow,

    kOnlyReadCr3,
    kOnlyWriteCr3,
    kReadWriteCr3,

    kOnlyReadCr4,
    kOnlyWriteCr4,
    kReadWriteCr4,

    kOnlyRdmsr,
    kOnlyWrmsr,
    kRdmsrWrmsr,
    kAll
};

enum class FilterCriteria
{
    kImportTable,
    kControlRegister3,
    kControlRegister4,
    kReadMsr,
    kWriteMsr,
};

bool
StringVectorContains(const std::vector<std::string> & v, std::string entry)
{
    return (std::find(v.begin(), v.end(), entry) != v.end());
}

bool
RestrictCheck(const data_types::SuspiciousDriver & driver_file)
{
    bool status = false;

    //
    // Ioctl handler (IRP)
    //
    if (not StringVectorContains(driver_file.Imports, "IoCreateDevice") &&
        not StringVectorContains(driver_file.Imports, "IoCreateSymbolicLink") &&
        not StringVectorContains(driver_file.Imports, "IofCompleteRequest"))
    {
        status = false;
        return status;
    }

    //
    // We need read/write to cr3 for physical address translation
    //
    if (not driver_file.Cr3Score)
    {
        status = false;
        return status;
    }

    //
    // Memory management
    //
    if (StringVectorContains(driver_file.Imports, "MmMapIoSpace") ||
        StringVectorContains(driver_file.Imports, "MmMapIoSpaceEx") ||
        StringVectorContains(driver_file.Imports, "MmGetPhysicalAddress"))
    {
        status = true;
    }

    //for (const auto & section : driver_file.ImportantSections)
    //{
    //    for (const auto & cr3 : section.Cr3.Instructions)
    //    {
    //        //
    //        // mov cr3 , ???
    //        //
    //        if (cr3.Instruction.Instruction.operands[0].reg.value == ZYDIS_REGISTER_CR3)
    //    }
    //}

    return status;
}

bool
BackupFiles(const std::vector<data_types::SuspiciousDriver> & important_driver_list,
            const std::string &                               backup_dir,
            AnalyzeSeverity                                   severity)
{
    if (backup_dir.empty())
        return false;

    fs::path backup_dir_path(backup_dir);

    if (!fs::is_directory(backup_dir_path))
        fs::create_directory(backup_dir_path);

    if (fs::is_directory(backup_dir_path))
    {
        for (const auto & file : important_driver_list)
        {
            auto dest_path = backup_dir_path / file.FileInfo.Name;
            try
            {
                //
                // Only copy files with dangerous imported APIs and Control Register/MSR modifications
                //
                if (severity == AnalyzeSeverity::kRestrict)
                {
                    if (RestrictCheck(file))
                    {
                        printf("[+] Found [%s] \n", file.FileInfo.Name.c_str());
                        fs::copy_file(file.FileInfo.ImagePath, dest_path, fs::copy_options::update_existing);
                    }
                }
                else if (severity == AnalyzeSeverity::kHigh)
                {
                    if (file.Imports.size() >= 2 && file.Cr3Score && file.MsrScore)
                    {
                        fs::copy_file(file.FileInfo.ImagePath, dest_path, fs::copy_options::update_existing);
                    }
                }
                else if (severity == AnalyzeSeverity::kMedium)
                {
                    if (file.Imports.size() >= 2 && file.Cr3Score && file.MsrScore)
                    {
                        fs::copy_file(file.FileInfo.ImagePath, dest_path, fs::copy_options::update_existing);
                    }
                }
                else if (severity == AnalyzeSeverity::kLow)
                {
                    //if (file.ImportantImports.size() >= 2 && file.Cr3Score && file.MsrScore)
                    {
                        fs::copy_file(file.FileInfo.ImagePath, dest_path, fs::copy_options::update_existing);
                    }
                }
                else if (severity == AnalyzeSeverity::kAll)
                {
                    fs::copy_file(file.FileInfo.ImagePath, dest_path, fs::copy_options::update_existing);
                }
            }
            catch (fs::filesystem_error & e)
            {
                std::cout << "\nCopy File ERROR: " << e.what() << '\n';
                continue;
            }
        }
    }

    return true;
}

class DirectoryScan
{
public:
    DirectoryScan(const std::string & directory_path) :
        directory_path_(directory_path)
    {
    }

    bool Scan()
    {
        if (fs::exists(directory_path_) == false || fs::is_directory(directory_path_) == false)
            return false;

        const auto normalized_path = fs::path(directory_path_).string() + "\\";

        try
        {
            const auto dir_iterator = fs::recursive_directory_iterator(
                directory_path_,
                fs::directory_options::skip_permission_denied);

            for (const auto & file : dir_iterator)
            {
                try
                {
                    if (fs::is_regular_file(file) &&
                        utils::str_tolower(file.path().extension().string()) == kKernelDriverFileExtension)
                    {
                        const auto file_path = file.path().string();

                        try
                        {
                            static_analyzer::Vulnerability vs(file_path,
                                                              suspicious_properties);
                            vs.AnalazeFile();
                            if (vs.IsSuspicious())
                            {
                                suspicious_drivers_.push_back(vs.GetSuspiciousDriver());
                            }
                        }
                        catch (const LIEF::exception & err)
                        {
                            std::cerr << err.what() << std::endl;
                        }

                        std::cout << "[!] Analyzing file: " << file_path << "\n";
                        analyzed_file_count_++;
                    }
                }
                catch (const std::exception & err)
                {
                    std::wcerr << L"Error: " << err.what() << std::endl;
                    continue;
                }
            }
        }
        catch (std::filesystem::filesystem_error & err)

        {
            std::wcerr << L"Error: " << err.what() << std::endl;
            return false;
        }

        return true;
    }

    std::uint32_t GetAnalyzedFileCount() const { return analyzed_file_count_; }

    std::vector<data_types::SuspiciousDriver> GetSuspiciousDrivers() const
    {
        return suspicious_drivers_;
    }

private:
    std::string                               directory_path_;
    std::vector<data_types::SuspiciousDriver> suspicious_drivers_;
    std::uint32_t                             analyzed_file_count_       = 0;
    const char *                              kKernelDriverFileExtension = ".sys";
};

bool
main(int argc, char * argv[])
{
    const auto parsed_options = options::detail::ParseCommandLine(argc, argv);
    if (parsed_options.has_value() == false)
        return false;

    options::CommandLineOptions commandline_options = parsed_options.value();

    utils::Chrono chrono;
    chrono.Start();

    //
    // TODO: read from config file
    //
    suspicious_properties.imported_functions = {

        //
        // Memory management
        //
        "MmMapIoSpace",
        "MmMapIoSpaceEx",
        "MmUnmapIoSpace",
        "MmMapLockedPages",
        "MmGetPhysicalAddress",
        "MmMapLockedPagesSpecifyCache",
        "MmMapLockedPagesWithReservedMapping",

        //
        // Ioctl / Create Device Name
        //
        "IoCreateDevice",
        "IoCreateSymbolicLink",
        "IofCompleteRequest",

        //
        // The function verifies that the sender of an IRP_MJ_DEVICE_CONTROL or IRP_MJ_FILE_SYSTEM_CONTROL
        // IRP has the specified access to the device object.
        //
        "IoValidateDeviceIoControlAccess",
        "WdmlibIoValidateDeviceIoControlAccess",

    };

    // AnalyzeFilesInDirectory(commandline_options.input_directory_path);

    std::vector<data_types::SuspiciousDriver> suspicious_drivers = {};

    DirectoryScan directory_scan(commandline_options.input_directory_path);
    if (directory_scan.Scan())
    {
        suspicious_drivers = directory_scan.GetSuspiciousDrivers();
        //
        // Create Json report
        //
        {
            std::ofstream             outStr(commandline_options.json_report_file_name);
            cereal::JSONOutputArchive archive(outStr);
            archive(CEREAL_NVP(suspicious_drivers));
        }

        //
        // Copy all important/vaulnerable files to desired directory
        //

        if (commandline_options.backup_directory_path.empty() == false)
        {
            BackupFiles(suspicious_drivers, commandline_options.backup_directory_path, AnalyzeSeverity::kAll);
        }
    }

    std::cout << "\n---------------------------------------------------\n";

    std::cout << "[!] Analyzed file count   : " << directory_scan.GetAnalyzedFileCount() << std::endl;
    std::cout << "[!] Suspicious file count : " << suspicious_drivers.size() << std::endl;
    std::cout << "[!] Json report saved in  : " << commandline_options.json_report_file_name << std::endl;
    std::cout << "[!] Backup path           : " << commandline_options.backup_directory_path << std::endl;

    std::cout << "\n---------------------------------------------------\n";

    chrono.Stop();
    std::cout << "[!] Finished!\n"
              << "[!] Elapsed time: " << chrono.GetElapsedTime() << "s\n";
    return true;
}
}  // namespace program
}  // namespace driver_analyzer

int
main(int argc, char * argv[])
{
    driver_analyzer::program::main(argc, argv);
}
