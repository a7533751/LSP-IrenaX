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
 * Copyright (C) 2020 EdXposed Contributors
 * Copyright (C) 2021 LSPosed Contributors
 */

#pragma once

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-string-literal-operator-template"

#include <string>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <filesystem>
#include <api/system_properties.h>
#include <unistd.h>
#include <sys/stat.h>
#include "logging.h"

namespace lspd {
    using namespace std::literals::string_literals;

    inline int GetSystemProperty(const char *name, char *value) {
        using SystemPropertyGet = int (*)(const char *, char *);
        static auto system_property_get = []() -> SystemPropertyGet {
            if (auto libc = dlopen("libc.so", RTLD_NOW | RTLD_LOCAL)) {
                return reinterpret_cast<SystemPropertyGet>(dlsym(libc, "__system_property_get"));
            }
            return nullptr;
        }();
        if (system_property_get) {
            if (auto len = system_property_get(name, value); len > 0) {
                return len;
            }
        }
        static auto properties_initialized = __system_properties_init() == 0;
        if (properties_initialized) {
            return __system_property_get(name, value);
        }
        value[0] = '\0';
        return 0;
    }

    inline int32_t GetAndroidApiLevel() {
        static int32_t api_level = []() {
            char prop_value[PROP_VALUE_MAX]{};
            int base = 0;
            if (GetSystemProperty("ro.build.version.sdk", prop_value) > 0) {
                base = atoi(prop_value);
            }
            int preview = 0;
            if (GetSystemProperty("ro.build.version.preview_sdk", prop_value) > 0) {
                preview = atoi(prop_value);
            }
            char codename[PROP_VALUE_MAX]{};
            if (preview > 0 &&
                GetSystemProperty("ro.build.version.codename", codename) > 0 &&
                strcmp(codename, "REL") != 0) {
                return base + preview;
            }
            return base;
        }();
        return api_level;
    }

    inline std::string JavaNameToSignature(std::string s) {
        std::replace(s.begin(), s.end(), '.', '/');
        return "L" + s;
    }
}

#pragma clang diagnostic pop
