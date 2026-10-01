// Where the plugin keeps its files, and the standalone single-instance lock.
//
// Hosted, the data directory is the handshake's dataDir: Ghost creates it and deletes it on
// uninstall. Standalone, it is %LOCALAPPDATA%\<plugin id>\ -- never Ghost's
// plugins\<id>\.data\ (spec-host-protocol.md 3.0) -- or the --data-dir given on the command
// line (tests use that).
#pragma once

#include <string>

namespace pf {

// %LOCALAPPDATA%\com.qtvz.xieyos.port-forwarder ("" if the known folder cannot be read).
std::wstring DefaultStandaloneDataDir();

// The full path of `dir` (GetFullPathNameW), without a trailing separator; "" on failure.
std::wstring FullPath(const std::wstring& dir);

// Creates `dir` if it does not exist (its parent must). True when it exists as a directory
// afterwards; otherwise `error` says why.
bool EnsureDirectory(const std::wstring& dir, std::string* error);

// The standalone single-instance mutex: Local\com.qtvz.xieyos.port-forwarder.standalone for
// the default data directory; for another one (--data-dir) the same name with "." and 16
// hex digits of a hash of its lower-cased full path -- one instance per rules file, so a
// test's instance in a temporary directory never collides with the user's own.
std::wstring StandaloneMutexName(const std::wstring& dataDir, bool isDefaultDir);

}  // namespace pf
