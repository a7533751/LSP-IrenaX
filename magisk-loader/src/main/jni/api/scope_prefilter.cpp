#include "scope_prefilter.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#include <mutex>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <utility>

#include "zygisk.h"

namespace lspd {
namespace {

constexpr std::uint8_t kProtocolVersion = 2;
constexpr std::uint32_t kMaxPackageNameLength = 256;
constexpr int kPerUserRange = 100000;
constexpr long kSocketTimeoutMicros = 250000;

constexpr size_t kProtocolVersionOffset = 0;
constexpr size_t kPackageNameLengthOffset =
        kProtocolVersionOffset + sizeof(kProtocolVersion);
constexpr size_t kUserIdOffset = kPackageNameLengthOffset + sizeof(std::uint32_t);
constexpr size_t kRequestHeaderSize = kUserIdOffset + sizeof(std::int32_t);
constexpr size_t kMaxRequestSize = kRequestHeaderSize + kMaxPackageNameLength;

constexpr int kSqliteOk = 0;
constexpr int kSqliteRow = 100;
constexpr int kSqliteDone = 101;
constexpr int kSqliteOpenReadOnly = 0x00000001;

struct sqlite3;
struct sqlite3_stmt;

bool ConfigureReceiveTimeout(int fd) {
    timeval timeout{};
    timeout.tv_usec = kSocketTimeoutMicros;
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0;
}

ssize_t ReadFully(int fd, void *buffer, size_t size) {
    auto *cursor = static_cast<std::uint8_t *>(buffer);
    size_t consumed = 0;
    while (consumed < size) {
        ssize_t result = read(fd, cursor + consumed, size - consumed);
        if (result < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (result == 0) return static_cast<ssize_t>(consumed);
        consumed += static_cast<size_t>(result);
    }
    return static_cast<ssize_t>(consumed);
}

ssize_t WriteFully(int fd, const void *buffer, size_t size) {
    const auto *cursor = static_cast<const std::uint8_t *>(buffer);
    size_t consumed = 0;
    while (consumed < size) {
        ssize_t result = send(fd, cursor + consumed, size - consumed, MSG_NOSIGNAL);
        if (result < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (result == 0) return -1;
        consumed += static_cast<size_t>(result);
    }
    return static_cast<ssize_t>(consumed);
}

std::string GetUtf8String(JNIEnv *env, jstring value) {
    if (value == nullptr) return {};
    const char *chars = env->GetStringUTFChars(value, nullptr);
    if (chars == nullptr) return {};
    std::string result(chars);
    env->ReleaseStringUTFChars(value, chars);
    return result;
}

std::string PackageNameFromDataDir(std::string data_dir) {
    while (!data_dir.empty() && data_dir.back() == '/') data_dir.pop_back();
    if (data_dir.empty()) return {};

    const auto separator = data_dir.find_last_of('/');
    std::string package_name = separator == std::string::npos
                                   ? std::move(data_dir)
                                   : data_dir.substr(separator + 1);
    if (package_name.empty() || package_name.size() > kMaxPackageNameLength ||
        package_name.find('/') != std::string::npos) {
        return {};
    }
    return package_name;
}

class ScopeDatabase {
public:
    ScopeDecision Query(const std::string &package_name, int user_id) {
        std::lock_guard lock(mutex_);
        if (!EnsureReady()) return ScopeDecision::Unknown;

        if (api_.reset(statement_) != kSqliteOk ||
            api_.clear_bindings(statement_) != kSqliteOk ||
            api_.bind_text(statement_, 1, package_name.c_str(),
                           static_cast<int>(package_name.size()), nullptr) != kSqliteOk ||
            api_.bind_text(statement_, 2, package_name.c_str(),
                           static_cast<int>(package_name.size()), nullptr) != kSqliteOk ||
            api_.bind_int(statement_, 3, user_id) != kSqliteOk) {
            CloseDatabase();
            return ScopeDecision::Unknown;
        }

        const int result = api_.step(statement_);
        if (result == kSqliteRow) return ScopeDecision::Targeted;
        if (result == kSqliteDone) return ScopeDecision::NotTargeted;

        CloseDatabase();
        return ScopeDecision::Unknown;
    }

    ~ScopeDatabase() {
        CloseDatabase();
        if (api_.library != nullptr) dlclose(api_.library);
    }

private:
    struct SQLiteApi {
        void *library = nullptr;
        int (*open_v2)(const char *, sqlite3 **, int, const char *) = nullptr;
        int (*prepare_v2)(sqlite3 *, const char *, int, sqlite3_stmt **, const char **) = nullptr;
        int (*bind_text)(sqlite3_stmt *, int, const char *, int, void (*)(void *)) = nullptr;
        int (*bind_int)(sqlite3_stmt *, int, int) = nullptr;
        int (*step)(sqlite3_stmt *) = nullptr;
        int (*reset)(sqlite3_stmt *) = nullptr;
        int (*clear_bindings)(sqlite3_stmt *) = nullptr;
        int (*finalize)(sqlite3_stmt *) = nullptr;
        int (*close_v2)(sqlite3 *) = nullptr;

        bool Load() {
            if (library != nullptr) return true;
            library = dlopen("libsqlite.so", RTLD_NOW | RTLD_LOCAL);
            if (library == nullptr) library = dlopen("libsqlite3.so", RTLD_NOW | RTLD_LOCAL);
            if (library == nullptr) return false;

            open_v2 = reinterpret_cast<decltype(open_v2)>(dlsym(library, "sqlite3_open_v2"));
            prepare_v2 = reinterpret_cast<decltype(prepare_v2)>(
                    dlsym(library, "sqlite3_prepare_v2"));
            bind_text = reinterpret_cast<decltype(bind_text)>(dlsym(library, "sqlite3_bind_text"));
            bind_int = reinterpret_cast<decltype(bind_int)>(dlsym(library, "sqlite3_bind_int"));
            step = reinterpret_cast<decltype(step)>(dlsym(library, "sqlite3_step"));
            reset = reinterpret_cast<decltype(reset)>(dlsym(library, "sqlite3_reset"));
            clear_bindings = reinterpret_cast<decltype(clear_bindings)>(
                    dlsym(library, "sqlite3_clear_bindings"));
            finalize = reinterpret_cast<decltype(finalize)>(dlsym(library, "sqlite3_finalize"));
            close_v2 = reinterpret_cast<decltype(close_v2)>(dlsym(library, "sqlite3_close_v2"));

            if (open_v2 != nullptr && prepare_v2 != nullptr && bind_text != nullptr &&
                bind_int != nullptr && step != nullptr && reset != nullptr &&
                clear_bindings != nullptr && finalize != nullptr && close_v2 != nullptr) {
                return true;
            }

            dlclose(library);
            *this = SQLiteApi{};
            return false;
        }
    } api_;

    bool EnsureReady() {
        if (database_ != nullptr && statement_ != nullptr) return true;
        if (!api_.Load()) return false;

        constexpr const char *database_path = "/data/adb/lspd/config/modules_config.db";
        if (api_.open_v2(database_path, &database_, kSqliteOpenReadOnly, nullptr) != kSqliteOk ||
            database_ == nullptr) {
            CloseDatabase();
            return false;
        }

        constexpr const char *query =
                "SELECT 1 FROM modules "
                "WHERE module_pkg_name = ?1 AND enabled = 1 "
                "UNION ALL "
                "SELECT 1 FROM modules AS m "
                "WHERE m.enabled = 1 AND EXISTS ("
                "SELECT 1 FROM scope AS s WHERE s.mid = m.mid "
                "AND s.app_pkg_name = ?2 AND s.user_id = ?3) LIMIT 1";
        if (api_.prepare_v2(database_, query, -1, &statement_, nullptr) != kSqliteOk ||
            statement_ == nullptr) {
            CloseDatabase();
            return false;
        }
        return true;
    }

    void CloseDatabase() {
        if (statement_ != nullptr && api_.finalize != nullptr) api_.finalize(statement_);
        statement_ = nullptr;
        if (database_ != nullptr && api_.close_v2 != nullptr) api_.close_v2(database_);
        database_ = nullptr;
    }

    std::mutex mutex_;
    sqlite3 *database_ = nullptr;
    sqlite3_stmt *statement_ = nullptr;
};

ScopeDatabase &GetScopeDatabase() {
    static ScopeDatabase database;
    return database;
}

}  // namespace

ScopeDecision QueryScopeBeforeSpecialize(zygisk::Api *api, JNIEnv *env, jint uid,
                                         jstring nice_name, jstring app_data_dir) {
    const std::string process_name = GetUtf8String(env, nice_name);
    if (process_name == "org.lsposed.manager" || process_name == "com.android.shell") {
        return ScopeDecision::Targeted;
    }

    const std::string package_name = PackageNameFromDataDir(GetUtf8String(env, app_data_dir));
    if (package_name.empty()) return ScopeDecision::Unknown;

    const int client = api->connectCompanion();
    if (client < 0) return ScopeDecision::Unknown;
    if (!ConfigureReceiveTimeout(client)) {
        close(client);
        return ScopeDecision::Unknown;
    }

    const std::uint32_t package_name_length = static_cast<std::uint32_t>(package_name.size());
    const std::int32_t user_id = uid / kPerUserRange;
    std::array<std::uint8_t, kMaxRequestSize> request{};
    request[kProtocolVersionOffset] = kProtocolVersion;
    std::memcpy(request.data() + kPackageNameLengthOffset, &package_name_length,
                sizeof(package_name_length));
    std::memcpy(request.data() + kUserIdOffset, &user_id, sizeof(user_id));
    std::memcpy(request.data() + kRequestHeaderSize, package_name.data(), package_name.size());
    const size_t request_size = kRequestHeaderSize + package_name.size();
    if (WriteFully(client, request.data(), request_size) !=
        static_cast<ssize_t>(request_size)) {
        close(client);
        return ScopeDecision::Unknown;
    }

    ScopeDecision decision = ScopeDecision::Unknown;
    const ssize_t received = ReadFully(client, &decision, sizeof(decision));
    close(client);
    if (received != static_cast<ssize_t>(sizeof(decision)) ||
        (decision != ScopeDecision::Targeted && decision != ScopeDecision::NotTargeted)) {
        return ScopeDecision::Unknown;
    }
    return decision;
}

void HandleScopeQuery(int client) {
    ScopeDecision decision = ScopeDecision::Unknown;
    std::array<std::uint8_t, kRequestHeaderSize> request_header{};
    if (ReadFully(client, request_header.data(), request_header.size()) ==
                static_cast<ssize_t>(request_header.size()) &&
        request_header[kProtocolVersionOffset] == kProtocolVersion) {
        std::uint32_t package_name_length = 0;
        std::int32_t user_id = 0;
        std::memcpy(&package_name_length,
                    request_header.data() + kPackageNameLengthOffset,
                    sizeof(package_name_length));
        std::memcpy(&user_id, request_header.data() + kUserIdOffset, sizeof(user_id));
        if (package_name_length == 0 || package_name_length > kMaxPackageNameLength) {
            WriteFully(client, &decision, sizeof(decision));
            close(client);
            return;
        }

        std::string package_name(package_name_length, '\0');
        if (ReadFully(client, package_name.data(), package_name.size()) ==
                    static_cast<ssize_t>(package_name.size())) {
            decision = GetScopeDatabase().Query(package_name, user_id);
        }
    }

    WriteFully(client, &decision, sizeof(decision));
    close(client);
}

}  // namespace lspd
