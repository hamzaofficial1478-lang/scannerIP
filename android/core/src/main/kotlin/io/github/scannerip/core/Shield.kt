package io.github.scannerip.core

import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

data class RotationEvent(val exit: ExitInfo, val identity: IdentitySnapshot)

/** Runs the rotator on a timer and rolls the identity along with it. */
class Shield(
    val rotator: Rotator,
    val vault: IdentityVault,
    intervalSeconds: Int? = null,
    @Volatile var onRotate: ((RotationEvent) -> Unit)? = null,
    @Volatile var onError: ((Exception) -> Unit)? = null,
    private val historySize: Int = 50,
) {
    /** Time between shifts, never below what the rotator allows. */
    @Volatile
    var intervalMillis: Long = maxOf(intervalSeconds ?: rotator.defaultIntervalSeconds, rotator.minIntervalSeconds) * 1000L

    private val lock = ReentrantLock()
    private val historyList = ArrayDeque<RotationEvent>()
    private val sleepLock = ReentrantLock()
    private val wakeUp = sleepLock.newCondition()
    @Volatile private var stopped = true
    @Volatile private var thread: Thread? = null
    @Volatile private var nextAtNanos: Long? = null
    @Volatile private var generation = 0

    @Volatile
    var current: RotationEvent? = null
        private set

    val history: List<RotationEvent> get() = synchronized(historyList) { historyList.toList() }
    val running: Boolean get() = thread?.isAlive == true

    fun rotateNow(): RotationEvent {
        val event = lock.withLock {
            val exit = rotator.rotate()
            RotationEvent(exit, vault.rotate(exit.ip)).also { ev ->
                current = ev
                synchronized(historyList) {
                    historyList.addLast(ev)
                    while (historyList.size > historySize) historyList.removeFirst()
                }
            }
        }
        onRotate?.invoke(event)
        return event
    }

    /** Where to send traffic right now. Waits if a shift is half-way through. */
    fun route(): Route = lock.withLock { rotator.route() }

    fun secondsLeft(): Double? = nextAtNanos?.let { maxOf(0.0, (it - System.nanoTime()) / 1e9) }

    /** Start shifting on the timer, beginning with a shift straight away. Safe to call after [stop]. */
    @Synchronized
    fun start() {
        if (running && !stopped) return
        stopped = false
        // A timer stopped a moment ago may still be finishing a shift. The new
        // generation number tells it to bow out instead of carrying on too.
        val mine = ++generation
        thread = Thread({ run(mine) }, "ip-shield").apply { isDaemon = true; start() }
    }

    private fun run(mine: Int) {
        fun live() = !stopped && mine == generation
        while (live()) {
            try {
                rotateNow()
            } catch (e: Exception) {
                onError?.invoke(e)
            }
            var left = TimeUnit.MILLISECONDS.toNanos(intervalMillis)
            if (mine == generation) nextAtNanos = System.nanoTime() + left
            sleepLock.withLock {
                while (live() && left > 0) left = wakeUp.awaitNanos(left)
            }
        }
        if (mine == generation) nextAtNanos = null
    }

    /** Stop the timer. Waits up to [waitMillis] for a shift in progress; 0 means don't wait. */
    fun stop(waitMillis: Long = 5000) {
        stopped = true
        nextAtNanos = null
        sleepLock.withLock { wakeUp.signalAll() }
        val worker = thread
        if (waitMillis > 0 && worker != null && worker !== Thread.currentThread()) worker.join(waitMillis)
        thread = null
    }

    fun close(waitMillis: Long = 1000) {
        stop(waitMillis)
        rotator.close()
    }
}
