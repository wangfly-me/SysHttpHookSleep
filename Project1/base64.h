#pragma once
#include<string>
namespace ko {
    class Base64 {
    private:
        static const std::string baseString;
    public:
        static std::string encode(const std::string& s);
        static std::string decode(const std::string& s);
    };
}
