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

package org.lsposed.lspd.service;

import static org.lsposed.lspd.service.ServiceManager.TAG;
import static org.lsposed.lspd.service.ServiceManager.toGlobalNamespace;

import android.content.res.AssetManager;
import android.content.res.Resources;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.os.RemoteException;
import android.os.SELinux;
import android.os.SharedMemory;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import org.lsposed.lspd.util.Log;

import androidx.annotation.Nullable;

import org.lsposed.daemon.BuildConfig;
import org.lsposed.lspd.models.PreLoadedApk;
import org.lsposed.lspd.util.InstallerVerifier;
import org.lsposed.lspd.util.Utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.zip.Deflater;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import hidden.HiddenApiBridge;

public class ConfigFileManager {
    static final Path basePath = Paths.get("/data/adb/lspd");
    static final Path modulePath = basePath.resolve("modules");
    static final Path daemonApkPath = Paths.get(System.getProperty("java.class.path", null));
    static final Path managerApkPath = daemonApkPath.getParent().resolve("manager.apk");
    static final File magiskDbPath = new File("/data/adb/magisk.db");
    private static final Path lockPath = basePath.resolve("lock");
    private static final Path configDirPath = basePath.resolve("config");
    static final File dbPath = configDirPath.resolve("modules_config.db").toFile();
    @SuppressWarnings("FieldCanBeLocal")
    private static FileLocker locker = null;
    private static Resources res = null;
    private static ParcelFileDescriptor fd = null;
    private static SharedMemory preloadDex = null;

    static {
        try {
            Files.createDirectories(basePath);
            SELinux.setFileContext(basePath.toString(), "u:object_r:system_file:s0");
            Files.createDirectories(configDirPath);
            Path path = modulePath;
            if (Files.isDirectory(path)) {
                Files.walkFileTree(path, new SimpleFileVisitor<>() {
                    public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                        Path relative = path.relativize(dir);
                        if (relative.getNameCount() >= 2) {
                            SELinux.setFileContext(dir.toString(), "u:object_r:lsposed_file:s0");
                        }
                        return FileVisitResult.CONTINUE;
                    }

                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs){
                        Path relative = path.relativize(file);
                        if (relative.getNameCount() >= 2) {
                            SELinux.setFileContext(file.toString(), "u:object_r:lsposed_file:s0");
                        }
                        return FileVisitResult.CONTINUE;
                    }
                });
            }
        } catch (IOException e) {
            Log.e(TAG, Log.getStackTraceString(e));
        }
    }

    public static Resources getResources() {
        loadRes();
        return res;
    }

    private static void loadRes() {
        if (res != null) return;
        try {
            var am = AssetManager.class.newInstance();
            //noinspection JavaReflectionMemberAccess DiscouragedPrivateApi
            Method addAssetPath = AssetManager.class.getDeclaredMethod("addAssetPath", String.class);
            addAssetPath.setAccessible(true);
            //noinspection ConstantConditions
            if ((int) addAssetPath.invoke(am, daemonApkPath.toString()) > 0) {
                //noinspection deprecation
                res = new Resources(am, null, null);
            }
        } catch (Throwable e) {
            Log.e(TAG, Log.getStackTraceString(e));
        }
    }

    static void reloadConfiguration() {
        loadRes();
        try {
            var conf = ActivityManagerService.getConfiguration();
            if (conf != null)
                //noinspection deprecation
                res.updateConfiguration(conf, res.getDisplayMetrics());
        } catch (Throwable e) {
            Log.e(TAG, "reload configuration", e);
        }
    }

    static ParcelFileDescriptor getManagerApk() throws IOException {
        if (fd != null) return fd.dup();
        InstallerVerifier.verifyInstallerSignature(managerApkPath.toString());

        SELinux.setFileContext(managerApkPath.toString(), "u:object_r:system_file:s0");
        fd = ParcelFileDescriptor.open(managerApkPath.toFile(), ParcelFileDescriptor.MODE_READ_ONLY);
        return fd.dup();
    }

    static void deleteFolderIfExists(Path target) throws IOException {
        if (Files.notExists(target)) return;
        Files.walkFileTree(target, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
                    throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException e)
                    throws IOException {
                if (e == null) {
                    Files.delete(dir);
                    return FileVisitResult.CONTINUE;
                } else {
                    throw e;
                }
            }
        });
    }

    public static boolean chattr0(Path path) {
        try {
            var dir = Os.open(path.toString(), OsConstants.O_RDONLY, 0);
            HiddenApiBridge.Os_ioctlInt(dir, Process.is64Bit() ? 0x40086602 : 0x40046602, 0);
            Os.close(dir);
            return true;
        } catch (Throwable e) {
            Log.d(TAG, "chattr 0", e);
            return false;
        }
    }

    static void moveLogDir() {
    }

    static void getLogs(ParcelFileDescriptor zipFd) throws IllegalStateException {
        try (zipFd; var os = new ZipOutputStream(new FileOutputStream(zipFd.getFileDescriptor()))) {
            os.setComment("");
            os.setLevel(Deflater.NO_COMPRESSION);
        } catch (Throwable e) {
            Log.w(TAG, "get log", e);
            throw new IllegalStateException(e);
        }
    }

    private static SharedMemory readDex(InputStream in, boolean obfuscate) throws IOException, ErrnoException {
        var memory = SharedMemory.create(null, in.available());
        var byteBuffer = memory.mapReadWrite();
        Channels.newChannel(in).read(byteBuffer);
        SharedMemory.unmap(byteBuffer);
        if (obfuscate) {
            var newMemory = ObfuscationManager.obfuscateDex(memory);
            if (memory != newMemory) {
                memory.close();
                memory = newMemory;
            }
        }
        memory.setProtect(OsConstants.PROT_READ);
        return memory;
    }

    private static void readDexes(ZipFile apkFile, List<SharedMemory> preLoadedDexes,
                                  boolean obfuscate) {
        int secondary = 2;
        for (var dexFile = apkFile.getEntry("classes.dex"); dexFile != null;
             dexFile = apkFile.getEntry("classes" + secondary + ".dex"), secondary++) {
            try (var is = apkFile.getInputStream(dexFile)) {
                preLoadedDexes.add(readDex(is, obfuscate));
            } catch (IOException | ErrnoException e) {
                Log.w(TAG, "Can not load " + dexFile + " in " + apkFile, e);
            }
        }
    }

    private static void readName(ZipFile apkFile, String initName, List<String> names) {
        var initEntry = apkFile.getEntry(initName);
        if (initEntry == null) return;
        try (var in = apkFile.getInputStream(initEntry)) {
            var reader = new BufferedReader(new InputStreamReader(in));
            String name;
            while ((name = reader.readLine()) != null) {
                name = name.trim();
                if (name.isEmpty() || name.startsWith("#")) continue;
                names.add(name);
            }
        } catch (IOException | OutOfMemoryError e) {
            Log.e(TAG, "Can not open " + initEntry, e);
        }
    }

    @Nullable
    static PreLoadedApk loadModule(String path, boolean obfuscate) {
        if (path == null) return null;
        var file = new PreLoadedApk();
        var preLoadedDexes = new ArrayList<SharedMemory>();
        var moduleClassNames = new ArrayList<String>(1);
        var moduleLibraryNames = new ArrayList<String>(1);
        try (var apkFile = new ZipFile(toGlobalNamespace(path))) {
            readDexes(apkFile, preLoadedDexes, obfuscate);
            readName(apkFile, "META-INF/xposed/java_init.list", moduleClassNames);
            if (moduleClassNames.isEmpty()) {
                file.legacy = true;
                readName(apkFile, "assets/xposed_init", moduleClassNames);
                readName(apkFile, "assets/native_init", moduleLibraryNames);
            } else {
                file.legacy = false;
                readName(apkFile, "META-INF/xposed/native_init.list", moduleLibraryNames);
            }
        } catch (IOException e) {
            Log.e(TAG, "Can not open " + path, e);
            return null;
        }
        if (preLoadedDexes.isEmpty()) return null;
        if (moduleClassNames.isEmpty()) return null;

        if (obfuscate) {
            var signatures = ObfuscationManager.getSignatures();
            for (int i = 0; i < moduleClassNames.size(); i++) {
                var s = moduleClassNames.get(i);
                for (var entry : signatures.entrySet()) {
                    if (s.startsWith(entry.getKey())) {
                        moduleClassNames.add(i, s.replace(entry.getKey(), entry.getValue()));
                    }
                }
            }
        }

        file.preLoadedDexes = preLoadedDexes;
        file.moduleClassNames = moduleClassNames;
        file.moduleLibraryNames = moduleLibraryNames;
        return file;
    }

    static boolean tryLock() {
        var openOptions = new HashSet<OpenOption>();
        openOptions.add(StandardOpenOption.CREATE);
        openOptions.add(StandardOpenOption.WRITE);
        var p = PosixFilePermissions.fromString("rw-------");
        var permissions = PosixFilePermissions.asFileAttribute(p);

        try {
            var lockChannel = FileChannel.open(lockPath, openOptions, permissions);
            locker = new FileLocker(lockChannel);
            return locker.isValid();
        } catch (Throwable e) {
            return false;
        }
    }

    synchronized static SharedMemory getPreloadDex(boolean obfuscate) {
        if (preloadDex == null) {
            try (var is = new FileInputStream("framework/lspd.dex")) {
                preloadDex = readDex(is, obfuscate);
            } catch (Throwable e) {
                Log.e(TAG, "preload dex", e);
            }
        }
        return preloadDex;
    }

    static void ensureModuleFilePath(String path) throws RemoteException {
        if (path == null || path.indexOf(File.separatorChar) >= 0 || ".".equals(path) || "..".equals(path)) {
            throw new RemoteException("Invalid path: " + path);
        }
    }

    static Path resolveModuleDir(String packageName, String dir, int userId, int uid) throws IOException {
        var path = modulePath.resolve(String.valueOf(userId)).resolve(packageName).resolve(dir).normalize();
        if (uid != -1) {
            if (path.toFile().mkdirs()) {
                try {
                    SELinux.setFileContext(path.toString(), "u:object_r:lsposed_file:s0");
                    Os.chown(path.toString(), uid, uid);
                    Os.chmod(path.toString(), 493);
                } catch (ErrnoException e) {
                    throw new IOException(e);
                }
            }
        }
        return path;
    }

    private static class FileLocker {
        private final FileChannel lockChannel;
        private final FileLock locker;

        FileLocker(FileChannel lockChannel) throws IOException {
            this.lockChannel = lockChannel;
            this.locker = lockChannel.tryLock();
        }

        boolean isValid() {
            return this.locker != null && this.locker.isValid();
        }

        @Override
        protected void finalize() throws Throwable {
            this.locker.release();
            this.lockChannel.close();
        }
    }
}
