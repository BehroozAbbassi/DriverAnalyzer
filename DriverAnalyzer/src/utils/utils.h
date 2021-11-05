#pragma once

namespace utils {
struct Chrono
{
    Chrono() :
        start(std::chrono::system_clock::now())
    {
    }

    void Start()
    {
        start = std::chrono::system_clock::now();
    }

    void Stop()
    {
        end = std::chrono::system_clock::now();
    }

    uint32_t GetElapsedTime() const
    {
        return std::chrono::duration_cast<std::chrono::seconds>(end - start).count();
    }

    void PrintElapsedTime()
    {
        int         elapsed_seconds = GetElapsedTime();
        std::time_t end_time        = std::chrono::system_clock::to_time_t(end);

        std::cout << "finished computation at " << std::ctime(&end_time)
                  << "elapsed time: " << elapsed_seconds << "s\n";
    }

    ~Chrono()
    {
    }

private:
    std::chrono::time_point<std::chrono::system_clock> start, end;
};

inline std::string
FormatFileSize(const size_t fileSize)
{
    const int MAX_FILE_SIZE_BUFFER = 255;
    char      szFileSize[MAX_FILE_SIZE_BUFFER];
    StrFormatByteSizeA(fileSize,
                       szFileSize,
                       MAX_FILE_SIZE_BUFFER);

    return szFileSize;
}

inline std::string
GetFileName(const std::string & filePath)
{
    std::filesystem::path path(filePath);
    return path.filename().string();
}

inline std::string
GeFormattedtFileSize(const std::string & filePath)
{
    auto fileSize = std::filesystem::file_size(filePath);
    return std::to_string(fileSize) + " (" + utils::FormatFileSize(fileSize) + ")";
}

template <typename T>
std::string
IntToHex(T i)
{
    std::stringstream stream;
    stream << "0x"
           << std::setfill('0') << std::setw(sizeof(T) * 2)
           << std::hex << i;
    return stream.str();
}

inline std::string
str_tolower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); }  // correct
    );
    return s;
}

}  // namespace utils