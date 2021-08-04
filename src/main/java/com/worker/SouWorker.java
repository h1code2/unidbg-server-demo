package com.worker;

import com.crack.SouGouSign;
import com.github.unidbg.worker.Worker;

import java.io.IOException;

public class SouWorker implements Worker {
    SouGouSign souGouSign;

    public SouWorker() {
        souGouSign = new SouGouSign();
    }

    @Override
    public void close() throws IOException {
        souGouSign.destroy();
    }

    public String worker(String query) {
        return souGouSign.getSign(query);
    }
}
