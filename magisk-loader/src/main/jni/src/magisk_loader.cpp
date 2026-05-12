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
 * Copyright (C) 2021 - 2022 LSPosed Contributors
 */

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/mman.h>
#include <array>
#include <string_view>

#include "config_impl.h"
#include "elf_util.h"
#include "loader.h"
#include "magisk_loader.h"
#include "native_util.h"
#include "service.h"
#include "symbol_cache.h"
#include "utils/jni_helper.hpp"

using namespace lsplant;

static_assert(FS_IOC_SETFLAGS == LP_SELECT(0x40046602, 0x40086602));

namespace lspd {
    extern int *allowUnload;
    jboolean is_parasitic_manager = JNI_FALSE;

    constexpr int FIRST_ISOLATED_UID = 99000;
    constexpr int LAST_ISOLATED_UID = 99999;
    constexpr int FIRST_APP_ZYGOTE_ISOLATED_UID = 90000;
    constexpr int LAST_APP_ZYGOTE_ISOLATED_UID = 98999;
    constexpr int SHARED_RELRO_UID = 1037;
    constexpr int PER_USER_RANGE = 100000;

    static constexpr uid_t kAidInjected = INJECTED_AID;
    static constexpr uid_t kAidInet = 3003;

    static constexpr std::array<std::string_view, 8> kAndroid9BypassedSystemServerArtHooks{
            "_ZN3art6mirror5Class9SetStatusENS_6HandleIS1_EENS_11ClassStatusEPNS_6ThreadE",
            "_ZN3art6mirror5Class9SetStatusENS_6HandleIS1_EENS1_6StatusEPNS_6ThreadE",
            "_ZN3art6mirror5Class9SetStatusENS1_6StatusEPNS_6ThreadE",
            "_ZN3art7Runtime20SetRuntimeDebugStateENS0_17RuntimeDebugStateE",
            "_ZN3art3jit3Jit27EnqueueOptimizedCompilationEPNS_9ArtMethodEPNS_6ThreadE",
            "_ZN3art3jit3Jit14AddCompileTaskEPNS_6ThreadEPNS_9ArtMethodENS_15CompilationKindEb",
            "_ZN3art3jit12JitCodeCache19GarbageCollectCacheEPNS_6ThreadE",
            "_ZN3art3jit12JitCodeCache12DoCollectionEPNS_6ThreadE",
    };

    bool ShouldBypassAndroid9SystemServerArtHook(std::string_view symbol) {
        for (auto bypassed_symbol: kAndroid9BypassedSystemServerArtHooks) {
            if (symbol == bypassed_symbol) return true;
        }
        return false;
    }

    struct Android9SystemServerArtHookState {
        void *target = nullptr;
        bool enabled = false;
        bool bypass = false;
    };

    void RecordAndroid9SystemServerArtHook(Android9SystemServerArtHookState &state,
                                           std::string_view symbol, void *target) {
        auto enabled = state.enabled;
        state = {
                .target = target,
                .enabled = enabled,
                .bypass = enabled && target != nullptr &&
                          ShouldBypassAndroid9SystemServerArtHook(symbol),
        };
        if (state.bypass) {
            LOGW("bypass Android 9 system_server art inline hook symbol {}", symbol);
        }
    }

    void MagiskLoader::LoadDex(JNIEnv *env, PreloadedDex &&dex) {
        auto classloader = JNI_FindClass(env, "java/lang/ClassLoader");
        auto getsyscl_mid = JNI_GetStaticMethodID(
                env, classloader, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
        auto sys_classloader = JNI_CallStaticObjectMethod(env, classloader, getsyscl_mid);
        if (!sys_classloader) [[unlikely]] {
            LOGE("getSystemClassLoader failed!!!");
            return;
        }
        auto in_memory_classloader = JNI_FindClass(env, "dalvik/system/InMemoryDexClassLoader");
        auto initMid = JNI_GetMethodID(env, in_memory_classloader, "<init>",
                                       "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
        auto byte_buffer_class = JNI_FindClass(env, "java/nio/ByteBuffer");
        auto dex_buffer = env->NewDirectByteBuffer(dex.data(), dex.size());
        if (auto my_cl = JNI_NewObject(env, in_memory_classloader, initMid,
                                       dex_buffer, sys_classloader)) {
            inject_class_loader_ = JNI_NewGlobalRef(env, my_cl);
        } else {
            LOGE("InMemoryDexClassLoader creation failed!!!");
            return;
        }

        env->DeleteLocalRef(dex_buffer);
    }

    std::string GetEntryClassName() {
        const auto &obfs_map = ConfigBridge::GetInstance()->obfuscation_map();
        static auto signature = obfs_map.at("org.lsposed.lspd.core.") + "Main";
        return signature;
    }

    void MagiskLoader::SetupEntryClass(JNIEnv *env) {
        if (auto entry_class = FindClassFromLoader(env, GetCurrentClassLoader(),
                                                   GetEntryClassName())) {
            entry_class_ = JNI_NewGlobalRef(env, entry_class);
        }
    }

    void
    MagiskLoader::OnNativeForkSystemServerPre(JNIEnv *env) {
        LOGI("system_server pre-specialize start on Android {}", GetAndroidApiLevel());
        Service::instance()->InitService(env);
        setAllowUnload(skip_);
        LOGI("system_server pre-specialize done");
    }

    void
    MagiskLoader::OnNativeForkSystemServerPost(JNIEnv *env) {
        if (!skip_) {
            LOGI("system_server post-specialize start on Android {}", GetAndroidApiLevel());
            auto *instance = Service::instance();
            auto system_server_binder = instance->RequestSystemServerBinder(env);
            if (!system_server_binder) {
                LOGF("Failed to get system server binder, system server initialization failed.");
                return;
            }

            auto application_binder = instance->RequestApplicationBinderFromSystemServer(env, system_server_binder);

            // Call application_binder directly if application binder is available,
            // or we proxy the request from system server binder
            auto &&next_binder = application_binder ? application_binder : system_server_binder;
            const auto [dex_fd, size] = instance->RequestLSPDex(env, next_binder);
            auto obfs_map = instance->RequestObfuscationMap(env, next_binder);
            ConfigBridge::GetInstance()->obfuscation_map(std::move(obfs_map));
            LoadDex(env, PreloadedDex(dex_fd, size));
            close(dex_fd);
            auto use_direct_system_server_bridge = GetAndroidApiLevel() <= __ANDROID_API_P__;
            LOGI("system_server dex loaded, direct_bridge={}", BoolToString(use_direct_system_server_bridge));
            if (!use_direct_system_server_bridge) {
                instance->HookBridge(*this, env);
            }

            // always inject into system server
            Android9SystemServerArtHookState android9_art_hook_state{
                    .enabled = use_direct_system_server_bridge &&
                               GetAndroidApiLevel() == __ANDROID_API_P__,
            };
            lsplant::InitInfo initInfo{
                .inline_hooker = [&android9_art_hook_state](auto t, auto r) {
                    if (android9_art_hook_state.bypass && android9_art_hook_state.target == t) [[unlikely]] {
                        return t;
                    }
                    void* bk = nullptr;
                    return HookFunction(t, r, &bk) == RS_SUCCESS ? bk : nullptr;
                },
                .inline_unhooker = [](auto t) {
                    return UnhookFunction(t) == RT_SUCCESS ;
                },
                .art_symbol_resolver = [&android9_art_hook_state](auto symbol) {
                    auto target = GetArt()->getSymbAddress(symbol);
                    RecordAndroid9SystemServerArtHook(android9_art_hook_state, symbol, target);
                    return target;
                },
                .art_symbol_prefix_resolver = [&android9_art_hook_state](auto symbol) {
                    auto target = GetArt()->getSymbPrefixFirstAddress(symbol);
                    RecordAndroid9SystemServerArtHook(android9_art_hook_state, symbol, target);
                    return target;
                },
            };
            InitArtHooker(env, initInfo);
            LOGI("system_server lsplant init done");
            InitHooks(env);
            LOGI("system_server native bridge init done");
            SetupEntryClass(env);
            LOGI("system_server entry class ready");
            if (use_direct_system_server_bridge) {
                LOGI("using direct system server bridge on Android {}", GetAndroidApiLevel());
                auto lsp_binder = instance->RequestLSPosedBinderFromSystemServer(env, system_server_binder);
                if (lsp_binder) {
                    FindAndCall(env, "initSystemServerBridge",
                                "(Landroid/os/IBinder;)V",
                                lsp_binder);
                } else {
                    LOGW("skip Android 9 direct system bridge: LSPosed binder is null");
                }
            }
            if (!application_binder) {
                LOGW("skip system server xposed bootstrap: application binder is null");
                return;
            }
            FindAndCall(env, "forkCommon",
                        "(ZLjava/lang/String;Ljava/lang/String;Landroid/os/IBinder;)V",
                        JNI_TRUE, JNI_NewStringUTF(env, "system"),
                        JNI_NewStringUTF(env, "system"), application_binder);
            LOGI("system_server forkCommon done");
            GetArt(true);
        }
    }

    void MagiskLoader::OnNativeForkAndSpecializePre(JNIEnv *env,
                                               jint uid,
                                               jintArray &gids,
                                               jstring &nice_name,
                                               jboolean is_child_zygote,
                                               jstring app_data_dir) {
        jboolean is_manager = JNI_FALSE;
        if (uid == kAidInjected) {
            const JUTFString name(env, nice_name);
            if (name.get() == "org.lsposed.manager"sv) {
                int array_size = gids ? env->GetArrayLength(gids) : 0;
                auto region = std::make_unique<jint[]>(array_size + 1);
                auto *new_gids = env->NewIntArray(array_size + 1);
                if (gids) env->GetIntArrayRegion(gids, 0, array_size, region.get());
                region.get()[array_size] = kAidInet;
                env->SetIntArrayRegion(new_gids, 0, array_size + 1, region.get());
                if (gids) env->SetIntArrayRegion(gids, 0, 1, region.get() + array_size);
                gids = new_gids;
                nice_name = JNI_NewStringUTF(env, "com.android.shell").release();
                is_manager = JNI_TRUE;
            }
        }
        is_parasitic_manager = is_manager;
        Service::instance()->InitService(env);
        const auto app_id = uid % PER_USER_RANGE;
        JUTFString process_name(env, nice_name);
        skip_ = false;
        if (!skip_ && !app_data_dir) {
            LOGD("skip injecting into {} because it has no data dir", process_name.get());
            skip_ = true;
        }
        if (!skip_ && is_child_zygote) {
            skip_ = true;
            LOGD("skip injecting into {} because it's a child zygote", process_name.get());
        }

        if (!skip_ && ((app_id >= FIRST_ISOLATED_UID && app_id <= LAST_ISOLATED_UID) ||
                       (app_id >= FIRST_APP_ZYGOTE_ISOLATED_UID &&
                        app_id <= LAST_APP_ZYGOTE_ISOLATED_UID) ||
                       app_id == SHARED_RELRO_UID)) {
            skip_ = true;
            LOGI("skip injecting into {} because it's isolated", process_name.get());
        }
        setAllowUnload(skip_);
    }

    void
    MagiskLoader::OnNativeForkAndSpecializePost(JNIEnv *env, jstring nice_name, jstring app_dir) {
        const JUTFString process_name(env, nice_name);
        auto *instance = Service::instance();
        if (is_parasitic_manager) nice_name = JNI_NewStringUTF(env, "org.lsposed.manager").release();
        auto binder = skip_ ? ScopedLocalRef<jobject>{env, nullptr}
                            : instance->RequestBinder(env, nice_name);
        if (binder) {
            lsplant::InitInfo initInfo{
                    .inline_hooker = [](auto t, auto r) {
                        void* bk = nullptr;
                        return HookFunction(t, r, &bk) == RS_SUCCESS ? bk : nullptr;
                    },
                    .inline_unhooker = [](auto t) {
                        return UnhookFunction(t) == RT_SUCCESS;
                    },
                    .art_symbol_resolver = [](auto symbol){
                        return GetArt()->getSymbAddress(symbol);
                    },
                    .art_symbol_prefix_resolver = [](auto symbol) {
                        return GetArt()->getSymbPrefixFirstAddress(symbol);
                    },
            };
            auto [dex_fd, size] = instance->RequestLSPDex(env, binder);
            auto obfs_map = instance->RequestObfuscationMap(env, binder);
            ConfigBridge::GetInstance()->obfuscation_map(std::move(obfs_map));
            LoadDex(env, PreloadedDex(dex_fd, size));
            close(dex_fd);
            InitArtHooker(env, initInfo);
            InitHooks(env);
            SetupEntryClass(env);
            LOGD("Done prepare");
            FindAndCall(env, "forkCommon",
                        "(ZLjava/lang/String;Ljava/lang/String;Landroid/os/IBinder;)V",
                        JNI_FALSE, nice_name, app_dir, binder);
            LOGD("injected xposed into {}", process_name.get());
            setAllowUnload(false);
            GetArt(true);
        } else {
            auto context = Context::ReleaseInstance();
            auto service = Service::ReleaseInstance();
            GetArt(true);
            LOGD("skipped {}", process_name.get());
            setAllowUnload(true);
        }
    }

    void MagiskLoader::setAllowUnload(bool unload) {
        if (allowUnload) {
            *allowUnload = unload ? 1 : 0;
        }
    }
}  // namespace lspd
