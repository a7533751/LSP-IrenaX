/*
 * This file is part of LSPosed.
 *
 * LSPosed is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LSPosed is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with LSPosed.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2021 - 2022 LSPosed Contributors
 */

#include <sys/socket.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <mutex>
#include <string>
#include <string_view>

#include "zygisk.h"
#include "logging.h"
#include "loader.h"
#include "config_impl.h"
#include "magisk_loader.h"
#include "symbol_cache.h"
#include "utils.h"

static bool is_targeted_by_any_module(const char *package_name, int user_id);

namespace lspd {

static ssize_t write_all(int fd, const void *buf, size_t count) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t written = 0;
    while (written < count) {
        ssize_t w = write(fd, p + written, count - written);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        written += (size_t)w;
    }
    return (ssize_t)written;
}

static ssize_t read_all(int fd, void *buf, size_t count) {
    uint8_t *p = (uint8_t *)buf;
    size_t read_bytes = 0;
    while (read_bytes < count) {
        ssize_t r = read(fd, p + read_bytes, count - read_bytes);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return (ssize_t)read_bytes; // EOF
        read_bytes += (size_t)r;
    }
    return (ssize_t)read_bytes;
}

static constexpr int PER_USER_RANGE = 100000;
static constexpr uid_t kAidInjected = INJECTED_AID;

static bool is_manager_process(uid_t uid, std::string_view name) {
    return uid == kAidInjected && name == "org.lsposed.manager";
}

static bool is_shell_process(std::string_view name) {
    return name == "com.android.shell";
}

static std::string package_name_from_app_data_dir(std::string_view app_data_dir) {
    const auto last_separator = app_data_dir.rfind('/');
    if (last_separator == std::string_view::npos || last_separator + 1 >= app_data_dir.size()) {
        return {};
    }
    return std::string(app_data_dir.substr(last_separator + 1));
}

static bool should_bypass_native_prefilter(uid_t uid, std::string_view name) {
    if (is_shell_process(name) || is_manager_process(uid, name)) return true;
    return GetAndroidApiLevel() <= __ANDROID_API_P__;
}

static bool is_process_targeted_by_any_module(std::string_view process_name,
                                              std::string_view package_name,
                                              int user_id) {
    if (!package_name.empty() && ::is_targeted_by_any_module(package_name.data(), user_id)) {
        return true;
    }
    if (!process_name.empty() && process_name != package_name &&
        ::is_targeted_by_any_module(process_name.data(), user_id)) {
        return true;
    }
    return false;
}

    int allow_unload = 0;
    int *allowUnload = &allow_unload;

    class ZygiskModule : public zygisk::ModuleBase {
        JNIEnv *env_;
        zygisk::Api *api_;
        bool should_ignore_ = false;

        void onLoad(zygisk::Api *api, JNIEnv *env) override {
            env_ = env;
            api_ = api;
            MagiskLoader::Init();
            ConfigImpl::Init();
        }

        void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
            should_ignore_ = false;
            allow_unload = 0;
            if (args->is_child_zygote && *args->is_child_zygote) {
                should_ignore_ = true;
                api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
                return;
            }
            if (!args->app_data_dir) {
                should_ignore_ = true;
                api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
                return;
            }

            const char *name = env_->GetStringUTFChars(args->nice_name, nullptr);
            if (!name) {
                LOGE("Failed to get process name");

                should_ignore_ = true;
                api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);

                return;
            }

            if (!should_bypass_native_prefilter(args->uid, name)) {
                int cfd = api_->connectCompanion();
                if (cfd < 0) {
                    LOGW("Failed to connect to companion, falling back to daemon filter: {}", strerror(errno));
                } else {
                    const char *app_data_dir = env_->GetStringUTFChars(args->app_data_dir, nullptr);
                    std::string package_name = app_data_dir ?
                            package_name_from_app_data_dir(app_data_dir) : std::string{};
                    if (app_data_dir) {
                        env_->ReleaseStringUTFChars(args->app_data_dir, app_data_dir);
                    }

                    uint8_t req_type = 1;
                    uint32_t process_name_len = (uint32_t)strlen(name);
                    uint32_t package_name_len = (uint32_t)package_name.size();
                    int32_t scope_user_id = static_cast<int32_t>(args->uid / PER_USER_RANGE);

                    if (write_all(cfd, &req_type, sizeof(req_type)) < 0 ||
                        write_all(cfd, &process_name_len, sizeof(process_name_len)) < 0 ||
                        write_all(cfd, name, process_name_len) != static_cast<ssize_t>(process_name_len) ||
                        write_all(cfd, &package_name_len, sizeof(package_name_len)) < 0 ||
                        (package_name_len > 0 &&
                         write_all(cfd, package_name.data(), package_name_len) != static_cast<ssize_t>(package_name_len)) ||
                        write_all(cfd, &scope_user_id, sizeof(scope_user_id)) < 0) {
                        LOGW("Failed to write to companion socket, falling back to daemon filter: {}", strerror(errno));
                    } else {
                        uint8_t target_byte = 1;
                        ssize_t r = read_all(cfd, &target_byte, sizeof(target_byte));
                        if (r <= 0) {
                            LOGW("Failed to read is_targeted from companion socket, falling back to daemon filter: {}", strerror(errno));
                        } else if (!target_byte) {
                            env_->ReleaseStringUTFChars(args->nice_name, name);
                            close(cfd);
                            should_ignore_ = true;
                            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);

                            return;
                        }
                    }

                    close(cfd);
                }
            }

            env_->ReleaseStringUTFChars(args->nice_name, name);

            MagiskLoader::GetInstance()->OnNativeForkAndSpecializePre(
            	env_, args->uid, args->gids, args->nice_name,
            	args->is_child_zygote ? *args->is_child_zygote : false, args->app_data_dir);
        }

        void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
            if (should_ignore_) {
                api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
                return;
            }

            MagiskLoader::GetInstance()->OnNativeForkAndSpecializePost(env_, args->nice_name, args->app_data_dir);
            if (*allowUnload) api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
        }

        void preServerSpecialize([[maybe_unused]] zygisk::ServerSpecializeArgs *args) override {
            should_ignore_ = false;
            allow_unload = 0;
            LOGD("zygisk system_server pre callback");
            MagiskLoader::GetInstance()->OnNativeForkSystemServerPre(env_);
        }

        void postServerSpecialize([[maybe_unused]] const zygisk::ServerSpecializeArgs *args) override {
            LOGD("zygisk system_server post callback");
            if (__system_property_find("ro.vendor.product.ztename")) {
                auto *process = env_->FindClass("android/os/Process");
                auto *set_argv0 = env_->GetStaticMethodID(process, "setArgV0",
                                                          "(Ljava/lang/String;)V");
                auto *name = env_->NewStringUTF("system_server");
                env_->CallStaticVoidMethod(process, set_argv0, name);
                env_->DeleteLocalRef(name);
                env_->DeleteLocalRef(process);
            }
            MagiskLoader::GetInstance()->OnNativeForkSystemServerPost(env_);
            if (*allowUnload) api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
        }
    };
} //namespace lspd

/* Load libsqlite once per companion lifetime to avoid dlopen/dlclose on every process spawn. */
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;

static bool is_targeted_by_any_module(const char *package_name, int user_id) {
  static void *lib = nullptr;
  static int (*sqlite3_initialize)(void) = nullptr;
  static int (*sqlite3_open_v2)(const char *, sqlite3 **, int, const char *) = nullptr;
  static int (*sqlite3_prepare_v2)(sqlite3 *, const char *, int, sqlite3_stmt **, const char **) = nullptr;
  static int (*sqlite3_bind_text)(sqlite3_stmt *, int, const char *, int, void (*)(void *)) = nullptr;
  static int (*sqlite3_bind_int)(sqlite3_stmt *, int, int) = nullptr;
  static int (*sqlite3_step)(sqlite3_stmt *) = nullptr;
  static int (*sqlite3_reset)(sqlite3_stmt *) = nullptr;
  static int (*sqlite3_clear_bindings)(sqlite3_stmt *) = nullptr;
  static int (*sqlite3_finalize)(sqlite3_stmt *) = nullptr;
  static int (*sqlite3_close_v2)(sqlite3 *) = nullptr;

  static sqlite3 *db = nullptr;
  static sqlite3_stmt *stmt = nullptr;
  static std::mutex sqlite_init_mutex;

  // Use a single lock for both initialization and usage to ensure thread-safety of the cached handle
  std::lock_guard<std::mutex> lock(sqlite_init_mutex);

  if (!lib) {
    lib = dlopen("libsqlite.so", RTLD_NOW | RTLD_LOCAL);
    if (!lib) lib = dlopen("libsqlite3.so", RTLD_NOW | RTLD_LOCAL);
    if (!lib) {
      LOGE("Failed to dlopen sqlite: %s", dlerror());

      return false;
    }

    sqlite3_initialize     = reinterpret_cast<decltype(sqlite3_initialize)> (dlsym(lib, "sqlite3_initialize"));
    sqlite3_open_v2        = reinterpret_cast<decltype(sqlite3_open_v2)> (dlsym(lib, "sqlite3_open_v2"));
    sqlite3_prepare_v2     = reinterpret_cast<decltype(sqlite3_prepare_v2)> (dlsym(lib, "sqlite3_prepare_v2"));
    sqlite3_bind_text      = reinterpret_cast<decltype(sqlite3_bind_text)> (dlsym(lib, "sqlite3_bind_text"));
    sqlite3_bind_int       = reinterpret_cast<decltype(sqlite3_bind_int)> (dlsym(lib, "sqlite3_bind_int"));
    sqlite3_step           = reinterpret_cast<decltype(sqlite3_step)> (dlsym(lib, "sqlite3_step"));
    sqlite3_reset          = reinterpret_cast<decltype(sqlite3_reset)> (dlsym(lib, "sqlite3_reset"));
    sqlite3_clear_bindings = reinterpret_cast<decltype(sqlite3_clear_bindings)> (dlsym(lib, "sqlite3_clear_bindings"));
    sqlite3_finalize       = reinterpret_cast<decltype(sqlite3_finalize)> (dlsym(lib, "sqlite3_finalize"));
    sqlite3_close_v2       = reinterpret_cast<decltype(sqlite3_close_v2)> (dlsym(lib, "sqlite3_close_v2"));

    if (!sqlite3_open_v2 || !sqlite3_prepare_v2 || !sqlite3_bind_text || !sqlite3_bind_int || !sqlite3_step || !sqlite3_finalize || !sqlite3_close_v2 || !sqlite3_reset || !sqlite3_clear_bindings) {
      LOGE("Missing sqlite symbols");

      dlclose(lib);

      lib = nullptr; // Reset to allow retry if needed
      return false;
    }

    // Explicitly initialize SQLite internals while holding the global lock
    if (sqlite3_initialize) {
      sqlite3_initialize();
    }
  }

  if (!db) {
    const char *db_path = "/data/adb/lspd/config/modules_config.db";
    if (sqlite3_open_v2(db_path, &db, 1, nullptr) != 0 || !db) {
      LOGE("Failed to open sqlite db: {}", db_path);

      if (db) {
        sqlite3_close_v2(db);
        db = nullptr;
      }
      return false;
    }
  }

  if (!stmt) {
    const char *sql = "SELECT 1 FROM scope INNER JOIN modules ON scope.mid = modules.mid WHERE scope.app_pkg_name = ? AND scope.user_id = ? AND modules.enabled = 1 LIMIT 1;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != 0) {
      LOGE("Failed to prepare sqlite statement");
      return false;
    }
  }

  sqlite3_reset(stmt);
  sqlite3_clear_bindings(stmt);

  bool is_targeted = false;

  if (sqlite3_bind_text(stmt, 1, package_name, static_cast<int>(strlen(package_name)), nullptr) != 0) {
    LOGE("Failed to bind package name");
  } else if (sqlite3_bind_int(stmt, 2, user_id) != 0) {
    LOGE("Failed to bind user id");
  } else {
    is_targeted = (sqlite3_step(stmt) == 100); // SQLITE_ROW
  }

  return is_targeted;
}

void relsposed_companion(int lib_fd) {
  #define CLEAN_EXIT() \
    close(lib_fd);     \
                       \
    return

  uint8_t req_type = 0;
  if (lspd::read_all(lib_fd, &req_type, sizeof(req_type)) != sizeof(req_type)) {
    LOGE("Failed to read request type from companion socket: {}", strerror(errno));

    CLEAN_EXIT();
  }
  
  if (req_type != 1) {
    LOGE("Unsupported request type: {}", req_type);

    CLEAN_EXIT();
  }
  
  uint32_t name_len = 0;
  if (lspd::read_all(lib_fd, &name_len, sizeof(name_len)) != sizeof(name_len)) {
    LOGE("Failed to read name length from companion socket: {}", strerror(errno));

    CLEAN_EXIT();
  }

  if (name_len == 0 || name_len > 4096) {
    LOGE("Invalid name length: %u", name_len);

    CLEAN_EXIT();
  }
  
  std::string name;
  name.resize(name_len);
  if (lspd::read_all(lib_fd, &name[0], name_len) != name_len) {
    LOGE("Failed to read name from companion socket: {}", strerror(errno));

    CLEAN_EXIT();
  }

  uint32_t package_name_len = 0;
  if (lspd::read_all(lib_fd, &package_name_len, sizeof(package_name_len)) != sizeof(package_name_len)) {
    LOGE("Failed to read package name length from companion socket: {}", strerror(errno));

    CLEAN_EXIT();
  }

  if (package_name_len > 4096) {
    LOGE("Invalid package name length: %u", package_name_len);

    CLEAN_EXIT();
  }

  std::string package_name;
  package_name.resize(package_name_len);
  if (package_name_len > 0 &&
      lspd::read_all(lib_fd, &package_name[0], package_name_len) != package_name_len) {
    LOGE("Failed to read package name from companion socket: {}", strerror(errno));

    CLEAN_EXIT();
  }
  
  int32_t user_id = 0;
  if (lspd::read_all(lib_fd, &user_id, sizeof(user_id)) != sizeof(user_id)) {
    LOGE("Failed to read user id from companion socket: {}", strerror(errno));
    
    CLEAN_EXIT();
  }
  
  bool targeted = lspd::is_process_targeted_by_any_module(name, package_name, user_id);
  uint8_t targeted_b = targeted ? 1 : 0;
  if (targeted) {
    LOGD("Process '{}' package '{}' (user_id={}) is targeted by any module",
         name.c_str(), package_name.c_str(), user_id);
  }
  if (lspd::write_all(lib_fd, &targeted_b, sizeof(targeted_b)) < 0) {
    LOGE("Failed to write to companion socket: {}", strerror(errno));
  }

  CLEAN_EXIT();
}

REGISTER_ZYGISK_MODULE(lspd::ZygiskModule);
REGISTER_ZYGISK_COMPANION(relsposed_companion);
