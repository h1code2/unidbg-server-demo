package com.crack;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import unicorn.Unicorn;

import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.ConsoleHandler;

public class SouGouSign extends AbstractJni {
    public final AndroidEmulator emulator;
    public final VM vm;
    public final Module module;

    private Pointer buffer;

    public SouGouSign() {
        // 创建模拟器实例,进程名建议依照实际进程名填写，可以规避针对进程名的校验
        emulator = AndroidEmulatorBuilder.for32Bit().setProcessName("com.sogou.activity.src").build();
        // 获取模拟器的内存操作接口
        final Memory memory = emulator.getMemory();
        // 设置系统类库解析
        memory.setLibraryResolver(new AndroidResolver(23));
        // 创建Android虚拟机,传入APK，Unidbg可以替我们做部分签名校验的工作
        vm = emulator.createDalvikVM(new File("src/main/resources/demo/sou/sougou.apk"));
        // 加载目标SO
        DalvikModule dm = vm.loadLibrary(new File("src/main/resources/demo/sou/libSCoreTools.so"), true); // 加载so到虚拟内存

        //获取本SO模块的句柄,后续需要用它
        module = dm.getModule();
        vm.setJni(this); // 设置JNI
        vm.setVerbose(true); // 打印日志
    }

    public static void main(String[] args) {
        SouGouSign sign = new SouGouSign();
        sign.hookByUnicorn();
        System.out.printf("sign obj %s%n", sign);
        List<Object> objects = new ArrayList<>(5);
        objects.add(sign.vm.getJNIEnv());
        objects.add(0);
        DvmObject<?> context = sign.vm.resolveClass("android/content/Context").newObject(null);
        objects.add(sign.vm.addLocalObject(context));
        sign.module.callFunction(sign.emulator, 0x9565, objects.toArray());

        String text = "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";
        byte[] bytes = sign.decrypt(text);
        print(String.format("bytes %s", bytes));
    }

    public void destroy() throws IOException {
        emulator.close();
    }

    public void hookByUnicorn() {
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
//                if (address == module.base + 0x9d24) {
                if (address == module.base + 0x9dd2) {
                    print("hook by unicorn");
                    RegisterContext registerContext = emulator.getContext();
                    Pointer pointer = registerContext.getPointerArg(0);
                    Pointer pointer2 = registerContext.getPointerArg(1);
                    Pointer pointer3 = registerContext.getPointerArg(2);
                    print(String.format("pointer %s", pointer.getString(0)));
                    print(String.format("pointer2 %s", pointer2.getString(0)));
                    print(String.format("pointer3 %s", pointer3.getString(0)));
                    buffer = registerContext.getPointerArg(3);
                }
//                if (address == module.base + 0x9d28) {
                if (address == module.base + 0x9dd8) {
                    Inspector.inspect(buffer.getByteArray(0, 0x100), "hook by unicorn");
                }
            }

            @Override
            public void onAttach(Unicorn.UnHook unHook) {

            }

            @Override
            public void detach() {

            }
        }, module.base + 0x9d24, module.base + 0x9d28, null);
    }

    public String encrypt(String query) {
        StringObject strObj = new StringObject(vm, "http://app.weixin.sogou.com/api/searchapp");
        StringObject str2Obj = new StringObject(vm, String.format("type=2&ie=utf8&page=1&query=%s&select_count=1&tsn=1&usip=", query));
        StringObject str3Obj = new StringObject(vm, "lilac");

        List<Object> objectList = new ArrayList<>(5);
        objectList.add(vm.getJNIEnv());
        objectList.add(0);
        objectList.add(vm.addLocalObject(strObj));
        objectList.add(vm.addLocalObject(str2Obj));
        objectList.add(vm.addLocalObject(str3Obj));
        Number number = module.callFunction(emulator, 0x9ca1, objectList.toArray())[0];
        Object object = vm.getObject(number.intValue());
        return object.toString();
    }

    public byte[] decrypt(String text) {
        List<Object> objectList = new ArrayList<>(5);
        objectList.add(vm.getJNIEnv());
        objectList.add(0);
        objectList.add(vm.addLocalObject(new StringObject(vm, text)));
        Number number = module.callFunction(emulator, 0x9da1, objectList.toArray())[0];
        int value = number.intValue();
        if (value <= 0) {
            return null;
        }
        print(String.format("number.iniValue %s", value));
        ByteArray byteArray = vm.getObject(value);
        return byteArray.getValue();
    }

    public static void print(String message) {
        System.out.print(String.format("[SouGouSign] ======= %s", message));
    }
}
