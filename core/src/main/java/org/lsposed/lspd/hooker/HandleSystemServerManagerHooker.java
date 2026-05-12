package org.lsposed.lspd.hooker;

import org.lsposed.lspd.util.Hookers;

import io.github.libxposed.api.XposedInterface;

public class HandleSystemServerManagerHooker implements XposedInterface.Hooker {
    public static void after() {
        Hookers.logD("ZygoteInit#handleSystemServerProcess() manager starts");
        try {
            HandleSystemServerProcessHooker.systemServerCL = Thread.currentThread().getContextClassLoader();
            var callback = HandleSystemServerProcessHooker.callback;
            if (callback != null) callback.onSystemServerLoaded(HandleSystemServerProcessHooker.systemServerCL);
        } catch (Throwable t) {
            Hookers.logE("error when hooking systemMain for manager", t);
        }
    }
}
