package org.lsposed.lspd.service;

import android.annotation.SuppressLint;
import android.os.Build;
import android.os.Process;

import java.io.File;

public class LogcatService implements Runnable {
    @SuppressLint("UnsafeDynamicallyLoadedCode")
    public LogcatService() {
        String classPath = System.getProperty("java.class.path");
        var abi = Process.is64Bit() ? Build.SUPPORTED_64_BIT_ABIS[0] : Build.SUPPORTED_32_BIT_ABIS[0];
        System.load(classPath + "!/lib/" + abi + "/" + System.mapLibraryName("daemon"));
        ConfigFileManager.moveLogDir();
    }

    @Override
    public void run() {
    }

    public boolean isRunning() {
        return false;
    }

    public void start() {
    }

    public void startVerbose() {
    }

    public void stopVerbose() {
    }

    public void refresh(boolean isVerboseLog) {
    }

    public File getVerboseLog() {
        return null;
    }

    public File getModulesLog() {
        return null;
    }

    public void checkLogFile() {
    }
}
