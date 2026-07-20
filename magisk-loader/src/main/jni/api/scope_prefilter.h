#ifndef LSPOSED_SCOPE_PREFILTER_H
#define LSPOSED_SCOPE_PREFILTER_H

#include <cstdint>

#include <jni.h>

namespace zygisk {
struct Api;
}

namespace lspd {

enum class ScopeDecision : std::uint8_t {
    Unknown = 0,
    Targeted = 1,
    NotTargeted = 2,
};

ScopeDecision QueryScopeBeforeSpecialize(zygisk::Api *api, JNIEnv *env, jint uid,
                                         jstring nice_name, jstring app_data_dir);

void HandleScopeQuery(int client);

}  // namespace lspd

#endif  // LSPOSED_SCOPE_PREFILTER_H
