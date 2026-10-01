// Unit: what port-forwarder.exe needs from the system at load time, read from its PE import
// table (a small reader written here, bounds-checked at every step).
//
//   * The reader is alive: it finds imports the exe is known to make (KERNEL32.dll!CreateFileW,
//     WS2_32.dll!WSASocketW). A reader that returned nothing would make every other check pass.
//   * Static CRT (/MT): no VCRUNTIME*, MSVCP*, CONCRT*, ucrtbase or api-ms-win-crt-* import. The
//     plugin runs on machines without the Visual C++ redistributable; with /MD the host's spawn
//     would end in a loader dialog nobody sees and a "plugin crashed" in Ghost.
//   * Every imported DLL is on a short list of system DLLs. A new dependency must be added here
//     on purpose.
//   * Windows 10 1607 is the floor: none of the listed APIs newer than it is a load-time import
//     (a missing entry point makes the loader refuse to start the process at all). This is a
//     list, not an audit of every import -- a new call to a newer API needs a new row.
//
// Prints every imported DLL and function, so the test log is the inventory.
//
// argv[1] = path of port-forwarder.exe.

#include "test_support.h"

#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace {

struct Import {
    std::string dll;   // as written in the image
    std::string name;  // function name, or "#<ordinal>"
};

std::string Lower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

class PeImage {
public:
    bool Load(const std::wstring& path, std::string* why) {
        FILE* f = nullptr;
        if (_wfopen_s(&f, path.c_str(), L"rb") != 0 || !f) {
            *why = "cannot open the file";
            return false;
        }
        char buf[65536];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0) bytes_.append(buf, n);
        fclose(f);

        IMAGE_DOS_HEADER dos;
        if (!Read(0, &dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) return Fail(why, "no MZ header");
        const size_t nt = static_cast<size_t>(dos.e_lfanew);
        DWORD sig = 0;
        if (!Read(nt, &sig) || sig != IMAGE_NT_SIGNATURE) return Fail(why, "no PE signature");
        IMAGE_FILE_HEADER fh;
        if (!Read(nt + 4, &fh)) return Fail(why, "truncated file header");
        if (fh.Machine != IMAGE_FILE_MACHINE_AMD64) return Fail(why, "not an x64 image");
        const size_t opt = nt + 4 + sizeof(IMAGE_FILE_HEADER);
        IMAGE_OPTIONAL_HEADER64 oh;
        if (fh.SizeOfOptionalHeader < sizeof(oh) || !Read(opt, &oh) || oh.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            return Fail(why, "not a PE32+ optional header");
        }
        if (oh.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT) return Fail(why, "no import directory slot");
        importDir_ = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (oh.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) {
            delayDir_ = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
        }
        const size_t secs = opt + fh.SizeOfOptionalHeader;
        for (WORD i = 0; i < fh.NumberOfSections; ++i) {
            IMAGE_SECTION_HEADER sh;
            if (!Read(secs + i * sizeof(sh), &sh)) return Fail(why, "truncated section table");
            sections_.push_back(sh);
        }
        return true;
    }

    // The load-time imports. False if the table cannot be walked.
    bool Imports(std::vector<Import>* out, std::string* why) const {
        if (importDir_.VirtualAddress == 0) return true;  // imports nothing
        size_t desc = 0;
        if (!Offset(importDir_.VirtualAddress, &desc)) return Fail(why, "import directory outside every section");
        for (int i = 0; i < 4096; ++i) {
            IMAGE_IMPORT_DESCRIPTOR d;
            if (!Read(desc + i * sizeof(d), &d)) return Fail(why, "truncated import descriptor");
            if (d.Name == 0 && d.FirstThunk == 0) return true;  // the all-zero terminator
            std::string dll;
            if (!StringAt(d.Name, &dll)) return Fail(why, "bad DLL name");
            const DWORD thunks = d.OriginalFirstThunk ? d.OriginalFirstThunk : d.FirstThunk;
            if (!Thunks(thunks, dll, out, why)) return false;
        }
        return Fail(why, "no terminator after 4096 descriptors");
    }

    // DLL names of the delay-loaded imports (not resolved at load time; listed for the record).
    bool DelayDlls(std::vector<std::string>* out, std::string* why) const {
        if (delayDir_.VirtualAddress == 0) return true;
        size_t desc = 0;
        if (!Offset(delayDir_.VirtualAddress, &desc)) return Fail(why, "delay import directory outside every section");
        for (int i = 0; i < 4096; ++i) {
            IMAGE_DELAYLOAD_DESCRIPTOR d;
            if (!Read(desc + i * sizeof(d), &d)) return Fail(why, "truncated delay descriptor");
            if (d.DllNameRVA == 0) return true;
            std::string dll;
            if (!StringAt(d.DllNameRVA, &dll)) return Fail(why, "bad delay DLL name");
            out->push_back(dll);
        }
        return Fail(why, "no delay terminator");
    }

private:
    static bool Fail(std::string* why, const char* what) {
        *why = what;
        return false;
    }

    template <typename T>
    bool Read(size_t off, T* out) const {
        if (off > bytes_.size() || bytes_.size() - off < sizeof(T)) return false;
        std::memcpy(out, bytes_.data() + off, sizeof(T));
        return true;
    }

    bool Offset(DWORD rva, size_t* off) const {
        for (const auto& s : sections_) {
            const DWORD size = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
            if (rva >= s.VirtualAddress && rva - s.VirtualAddress < size && rva - s.VirtualAddress < s.SizeOfRawData) {
                *off = static_cast<size_t>(s.PointerToRawData) + (rva - s.VirtualAddress);
                return *off < bytes_.size();
            }
        }
        return false;
    }

    bool StringAt(DWORD rva, std::string* out) const {
        size_t off = 0;
        if (!Offset(rva, &off)) return false;
        out->clear();
        for (size_t i = off; i < bytes_.size() && i - off < 512; ++i) {
            if (bytes_[i] == '\0') return !out->empty();
            out->push_back(bytes_[i]);
        }
        return false;
    }

    bool Thunks(DWORD rva, const std::string& dll, std::vector<Import>* out, std::string* why) const {
        size_t off = 0;
        if (!Offset(rva, &off)) return Fail(why, "thunk table outside every section");
        for (int i = 0; i < 65536; ++i) {
            ULONGLONG t = 0;
            if (!Read(off + i * sizeof(t), &t)) return Fail(why, "truncated thunk table");
            if (t == 0) return true;
            Import imp;
            imp.dll = dll;
            if (t & IMAGE_ORDINAL_FLAG64) {
                imp.name = "#" + std::to_string(t & 0xffff);
            } else {
                // IMAGE_IMPORT_BY_NAME: a 2-byte hint, then the name.
                if (!StringAt(static_cast<DWORD>(t & 0x7fffffff) + 2, &imp.name)) return Fail(why, "bad import name");
            }
            out->push_back(imp);
        }
        return Fail(why, "no thunk terminator");
    }

    std::string bytes_;
    IMAGE_DATA_DIRECTORY importDir_ = {};
    IMAGE_DATA_DIRECTORY delayDir_ = {};
    std::vector<IMAGE_SECTION_HEADER> sections_;
};

bool Has(const std::vector<Import>& imports, const char* dll, const char* fn) {
    for (const auto& i : imports) {
        if (Lower(i.dll) == Lower(dll) && i.name == fn) return true;
    }
    return false;
}

bool StartsWith(const std::string& s, const char* prefix) { return s.compare(0, std::strlen(prefix), prefix) == 0; }

// The C/C++ runtime DLLs a /MD build imports.
bool IsCrtDll(const std::string& dll) {
    const std::string d = Lower(dll);
    return StartsWith(d, "vcruntime") || StartsWith(d, "msvcp") || StartsWith(d, "concrt") ||
           StartsWith(d, "vccorlib") || StartsWith(d, "ucrtbase") || StartsWith(d, "api-ms-win-crt-");
}

// System DLLs the plugin may import. Each is present on every Windows 10 1607+ x64 install.
const std::set<std::string>& AllowedDlls() {
    static const std::set<std::string> allowed = {
        "kernel32.dll", "advapi32.dll", "bcrypt.dll",   "iphlpapi.dll", "ole32.dll",
        "shell32.dll",  "user32.dll",   "winhttp.dll",  "ws2_32.dll",   "mswsock.dll",
    };
    return allowed;
}

// APIs newer than Windows 10 1607 (build 14393) that a Windows networking tool might reach
// for, with the release that added them. A load-time import of any of them keeps the plugin
// from starting on 1607.
const std::map<std::string, const char*>& TooNew() {
    static const std::map<std::string, const char*> rows = {
        {"SetProcessDpiAwarenessContext", "1703"},
        {"IsWow64Process2", "1709"},
        {"GetSystemDpiForProcess", "1803"},
        {"SetThreadDpiHostingBehavior", "1803"},
        {"VirtualAlloc2", "1803"},
        {"MapViewOfFile3", "1803"},
        {"CreatePseudoConsole", "1809"},
        {"GetMachineTypeAttributes", "Windows 11"},
        {"GetTempPath2W", "Windows 11 / Server 2022"},
        {"GetTempPath2A", "Windows 11 / Server 2022"},
        {"CreateFile3", "Windows 11 24H2"},
    };
    return rows;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: test_imports <port-forwarder.exe>\n");
        return 2;
    }
    PeImage pe;
    std::string why;
    const bool loaded = pe.Load(argv[1], &why);
    CHECK_MSG(loaded, why.c_str());
    std::vector<Import> imports;
    const bool walked = loaded && pe.Imports(&imports, &why);
    CHECK_MSG(walked, why.c_str());
    std::vector<std::string> delay;
    CHECK_MSG(!loaded || pe.DelayDlls(&delay, &why), why.c_str());

    // The reader is alive.
    CHECK_MSG(Has(imports, "KERNEL32.dll", "CreateFileW"), "the reader finds KERNEL32.dll!CreateFileW");
    CHECK_MSG(Has(imports, "WS2_32.dll", "WSASocketW"), "the reader finds WS2_32.dll!WSASocketW");
    CHECK(imports.size() >= 20);

    std::map<std::string, std::vector<std::string>> byDll;
    for (const auto& i : imports) byDll[i.dll].push_back(i.name);
    for (const auto& kv : byDll) {
        std::printf("%s (%zu):", kv.first.c_str(), kv.second.size());
        for (const auto& n : kv.second) std::printf(" %s", n.c_str());
        std::printf("\n");
        CHECK_MSG(!IsCrtDll(kv.first), ("a C runtime DLL is imported -- not /MT: " + kv.first).c_str());
        CHECK_MSG(AllowedDlls().count(Lower(kv.first)) == 1,
                  ("an imported DLL that is not on the system list: " + kv.first).c_str());
    }
    for (const auto& d : delay) {
        std::printf("delay-load: %s\n", d.c_str());
        CHECK_MSG(!IsCrtDll(d), ("a delay-loaded C runtime DLL: " + d).c_str());
    }
    for (const auto& i : imports) {
        const auto it = TooNew().find(i.name);
        CHECK_MSG(it == TooNew().end(),
                  (i.dll + "!" + i.name + " is a load-time import newer than Windows 10 1607 (" +
                   (it == TooNew().end() ? "" : it->second) + ")")
                      .c_str());
    }
    return pf_test::TestExitCode();
}
