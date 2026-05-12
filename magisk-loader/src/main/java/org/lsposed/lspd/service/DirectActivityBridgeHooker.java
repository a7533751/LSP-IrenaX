package org.lsposed.lspd.service;

import android.os.IBinder;
import android.os.Parcel;

import org.lsposed.lspd.impl.LSPosedHelper;
import org.lsposed.lspd.util.Utils;

import java.util.concurrent.atomic.AtomicBoolean;

import io.github.libxposed.api.XposedInterface;

public class DirectActivityBridgeHooker implements XposedInterface.Hooker {
    private static final AtomicBoolean started = new AtomicBoolean(false);
    private static final int TRANSACTION_CODE = ('_' << 24) | ('L' << 16) | ('S' << 8) | 'P';

    public static void start() {
        if (!started.compareAndSet(false, true)) return;
        try {
            LSPosedHelper.hookMethod(DirectActivityBridgeHooker.class, android.os.Binder.class,
                    "execTransact", int.class, long.class, long.class, int.class);
            Utils.logI("Android 9 direct activity bridge hook installed");
        } catch (Throwable t) {
            Utils.logE("failed to install Android 9 direct activity bridge hook", t);
        }
    }

    public static void before(XposedInterface.BeforeHookCallback callback) {
        try {
            var args = callback.getArgs();
            if ((int) args[0] != TRANSACTION_CODE) return;

            var self = callback.getThisObject();
            if (!(self instanceof IBinder binder)) return;

            String descriptor;
            try {
                descriptor = binder.getInterfaceDescriptor();
            } catch (Throwable ignored) {
                return;
            }
            if (!"android.app.IActivityManager".equals(descriptor)
                    && !"com.sonymobile.hookservice.HookActivityService".equals(descriptor)) {
                return;
            }

            var data = ParcelUtils.fromNativePointer((long) args[1]);
            var reply = ParcelUtils.fromNativePointer((long) args[2]);
            if (data == null || reply == null) return;

            var handled = BridgeService.onTransact(data, reply, (int) args[3]);
            if (handled) callback.returnAndSkip(true);
        } catch (Throwable t) {
            Utils.logE("Android 9 direct activity bridge hook error", t);
        }
    }
}
