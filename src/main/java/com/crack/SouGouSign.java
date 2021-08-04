package com.crack;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import unicorn.Unicorn;

import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.ConsoleHandler;

public class SouGouSign extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;

    private Pointer buffer;

    public SouGouSign() {
        // 创建模拟器实例,进程名建议依照实际进程名填写，可以规避针对进程名的校验
        emulator = AndroidEmulatorBuilder.for32Bit().setProcessName("com.sina.oasis").build();
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
//        vm.setVerbose(true); // 打印日志
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
        String query = "";
        StringObject strObj = new StringObject(sign.vm, "http://app.weixin.sogou.com/api/searchapp");
        StringObject str2Obj = new StringObject(sign.vm, String.format("type=2&ie=utf8&page=1&query=%s&select_count=1&tsn=1&usip=", query));
        StringObject str3Obj = new StringObject(sign.vm, "lilac");

        List<Object> objectList = new ArrayList<>(5);
        objectList.add(sign.vm.getJNIEnv());
        objectList.add(0);
        objectList.add(sign.vm.addLocalObject(strObj));
        objectList.add(sign.vm.addLocalObject(str2Obj));
        objectList.add(sign.vm.addLocalObject(str3Obj));
        Number number = sign.module.callFunction(sign.emulator, 0x9ca1, objectList.toArray())[0];
        Object object = sign.vm.getObject(number.intValue());
        String k = object.toString();
        System.out.println(String.format("k %s", k));
    }

    public void destroy() throws IOException {
        emulator.close();
    }

    public void hookByUnicorn() {
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                if (address == module.base + 0x9d24) {
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
                if (address == module.base + 0x9d28) {
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

    public String getSign(String query) {
        List<Object> objects = new ArrayList<>(5);
        objects.add(vm.getJNIEnv());
        objects.add(0);
        DvmObject<?> context = vm.resolveClass("android/content/Context").newObject(null);
        objects.add(vm.addLocalObject(context));
        module.callFunction(emulator, 0x9565, objects.toArray());
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

    private void print(String message) {
        System.out.print(String.format("[SouGouSign] ======= %s", message));
    }
}
