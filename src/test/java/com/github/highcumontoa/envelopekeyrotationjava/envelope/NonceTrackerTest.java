package com.github.highcumontoa.envelopekeyrotationjava.envelope;

import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.InMemoryNonceTracker;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** 同一版本并发提交相同 nonce：恰好一个成功登记，另一个必须检测为复用。 */
class NonceTrackerTest {

    private static final Logger log = LoggerFactory.getLogger(NonceTrackerTest.class);

    @Test
    void parallelSameNonceExactlyOneAccepted() throws InterruptedException {
        InMemoryNonceTracker tracker = new InMemoryNonceTracker();
        byte[] nonce = new byte[12];
        int threads = 16;
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger accepted = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        ExecutorService pool = Executors.newFixedThreadPool(threads);

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    if (tracker.registerIfAbsent(7, nonce.clone())) {
                        accepted.incrementAndGet();
                    } else {
                        rejected.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        pool.awaitTermination(10, TimeUnit.SECONDS);

        log.info("[TEST-JUDGE] scenario=parallel-nonce threads={} accepted={} reusedRejected={}",
                threads, accepted.get(), rejected.get());
        assertEquals(1, accepted.get(), "相同 nonce 只能登记成功一次");
        assertEquals(threads - 1, rejected.get(), "其余并发提交必须全部判为复用");
    }
}
