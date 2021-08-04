package com.worker;

import com.crack.SouGouSign;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.worker.Worker;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SouWorker implements Worker {
    SouGouSign souGouSign;

    public SouWorker() {
        souGouSign = new SouGouSign();
        List<Object> objects = new ArrayList<>(5);
        objects.add(souGouSign.vm.getJNIEnv());
        objects.add(0);
        DvmObject<?> context = souGouSign.vm.resolveClass("android/content/Context").newObject(null);
        objects.add(souGouSign.vm.addLocalObject(context));
        souGouSign.module.callFunction(souGouSign.emulator, 0x9565, objects.toArray());
    }

    @Override
    public void close() throws IOException {
        souGouSign.destroy();
    }

    public String encrypt(String query) {
        return souGouSign.encrypt(query);
    }

    public byte[] decrypt(String text) {
        return souGouSign.decrypt(text);
    }
}
