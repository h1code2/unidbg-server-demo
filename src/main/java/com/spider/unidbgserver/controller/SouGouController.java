package com.spider.unidbgserver.controller;

import com.github.unidbg.worker.WorkerPool;
import com.github.unidbg.worker.WorkerPoolFactory;
import com.worker.SouWorker;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.concurrent.*;

@Controller
@RequestMapping("/sou")
public class SouGouController {
    final int processors = Runtime.getRuntime().availableProcessors() / 2 + 2;
    final WorkerPool souPool = WorkerPoolFactory.create(SouWorker::new, processors);
    final static ExecutorService executor = new ThreadPoolExecutor(10, 20, 0L, TimeUnit.MILLISECONDS, new ArrayBlockingQueue(10), new ThreadPoolExecutor.CallerRunsPolicy());

    @RequestMapping(value = "sign", method = {RequestMethod.GET})
    @ResponseBody
    public String sign(@RequestParam("text") String text, @RequestParam("type") String type) {
        try {
            Future<String> k = executor.submit(() -> {
                SouWorker worker = souPool.borrow(1, TimeUnit.MINUTES);
                if (worker != null) {
                    try {
                        if (type.equals("encrypt")) {
                            return worker.encrypt(text);
                        } else {
                            byte[] result = worker.decrypt(text);
                            return new String(result);
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    } finally {
                        souPool.release(worker);
                    }
                } else {
                    System.err.println("SouWorker Borrow failed");
                }
                return null;
            });
            String sign = k.get();
            return sign;
        } catch (Throwable throwable) {
            throwable.printStackTrace();
            return null;
        }
    }
}
