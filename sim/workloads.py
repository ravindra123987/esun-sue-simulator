"""Workloads for the SUE-T endpoint: collectives made of 256 B loads and stores (plan.md M3).

A workload is pulled, not pushed: an endpoint asks `next_txn(xpu, now)` whenever its XPU
command interface is free and its transmit buffer has room, so back-pressure reaches the XPU
as in SUE-T §7.3. The workload learns about progress through `on_receive` (a request reached
the target XPU) and `on_done` (the issuing XPU got its ACK or response).
"""

import itertools
import random
from collections import deque

from .suet import Txn


class Workload:
    def __init__(self):
        self.ids = itertools.count(1)
        self.fabric = None
        self.finished = None
        self.n_done = self.n_failed = 0
        self.timeline = []                      # (t, bytes) for every successful completion

    def attach(self, fabric):
        self.fabric = fabric

    def on_receive(self, xpu, t, now):
        pass

    def on_done(self, t: Txn, now):
        self.n_done += 1
        self.n_failed += not t.ok
        if t.ok:
            self.timeline.append((now, t.size))
        if self.n_done == self.total:
            self.finished = now

    def done(self):
        return self.finished is not None


class AllToAll(Workload):
    """Every XPU sends `bytes_per_peer` to every other XPU as `size`-byte transactions, destinations
    round robin, starting after a random offset of up to `jitter_ns`."""

    def __init__(self, n, bytes_per_peer=16384, size=256, op="store", tc=0, jitter_ns=0.0, seed=1, senders=None):
        """`senders`: the XPUs that send (default all); the others only receive and acknowledge."""
        super().__init__()
        rng = random.Random(seed)
        self.n, self.size, self.op, self.tc = n, size, op, tc
        per = bytes_per_peer // size
        senders = set(range(n)) if senders is None else set(senders)
        self.todo = {i: deque((i + 1 + k) % n for _ in range(per) for k in range(n - 1)) if i in senders else deque()
                     for i in range(n)}
        self.t0 = {i: rng.uniform(0, jitter_ns) if jitter_ns else 0.0 for i in range(n)}
        self.total = per * (n - 1) * len(senders)

    def attach(self, fabric):
        super().attach(fabric)
        for i, t0 in self.t0.items():
            if t0 > 0:
                fabric.sim.at(t0, fabric.eps[i].kick_xpu)

    def next_txn(self, xpu, now):
        if now < self.t0[xpu] or not self.todo[xpu]:
            return None
        return Txn(next(self.ids), xpu, self.todo[xpu].popleft(), self.op, self.size, self.tc, t_issue=now)


class RingAllReduce(Workload):
    """Ring all-reduce of `total_bytes`: n-1 reduce-scatter steps (stores to the next XPU) then n-1
    all-gather steps (loads from the previous XPU). A step at XPU i starts when its own previous step
    completed and the data it needs has arrived: all of XPU i-1's stores of that step (reduce-scatter)
    or XPU i-1 having finished the step (all-gather). Completion time is the last XPU's last step."""

    def __init__(self, n, total_bytes=1 << 20, size=256, tc=0, jitter_ns=0.0, seed=1):
        super().__init__()
        rng = random.Random(seed)
        self.n, self.size, self.tc = n, size, tc
        self.per = max(1, (total_bytes // n) // size)        # transactions per step per XPU
        self.steps = 2 * (n - 1)
        self.step = {i: 0 for i in range(n)}                 # current step
        self.fin = {i: 0 for i in range(n)}                  # steps whose transactions all completed
        self.issued = {i: 0 for i in range(n)}
        self.completed = {i: 0 for i in range(n)}
        self.recv = {i: [0] * self.steps for i in range(n)}  # stores received per step
        self.step_of: dict[int, int] = {}                    # txn id -> step
        self.t0 = {i: rng.uniform(0, jitter_ns) if jitter_ns else 0.0 for i in range(n)}
        self.total = self.per * self.steps * n

    def attach(self, fabric):
        super().attach(fabric)
        for i, t0 in self.t0.items():
            if t0 > 0:
                fabric.sim.at(t0, fabric.eps[i].kick_xpu)

    def _is_store(self, s):
        return s < self.n - 1

    def _has_data(self, i, s):
        """Does XPU i hold the chunk a neighbour wants after step s? Stores of step s brought it in
        (reduce-scatter); loads of step s fetched it (all-gather)."""
        return self.recv[i][s] >= self.per if self._is_store(s) else self.fin[i] > s

    def _can_start(self, i, s):
        if s == 0:
            return True
        return self._has_data(i, s - 1) if self._is_store(s) else self._has_data((i - 1) % self.n, s - 1)

    def next_txn(self, xpu, now):
        if now < self.t0[xpu]:
            return None
        s = self.step[xpu]
        if s >= self.steps:
            return None
        if self.issued[xpu] >= self.per:                      # this step fully issued: can we advance?
            if self.fin[xpu] <= s or not self._can_start(xpu, s + 1):
                return None
            self.step[xpu] = s = s + 1
            self.issued[xpu] = self.completed[xpu] = 0
            if s >= self.steps:
                return None
        if not self._can_start(xpu, s):
            return None
        self.issued[xpu] += 1
        if self._is_store(s):
            t = Txn(next(self.ids), xpu, (xpu + 1) % self.n, "store", self.size, self.tc, t_issue=now)
        else:
            t = Txn(next(self.ids), xpu, (xpu - 1) % self.n, "load", self.size, self.tc, t_issue=now)
        self.step_of[t.id] = s
        return t

    def _wake(self, i):
        if self.fabric is not None:
            self.fabric.sim.after(0.0, self.fabric.eps[i].kick_xpu)

    def on_receive(self, xpu, t, now):
        if t.op == "store":
            self.recv[xpu][self.step_of[t.id]] += 1
            self._wake(xpu)

    def on_done(self, t, now):
        self.completed[t.src] += 1
        if self.completed[t.src] >= self.per:
            self.fin[t.src] = self.step_of[t.id] + 1
            self._wake(t.src)
            self._wake((t.src + 1) % self.n)                  # the next XPU may be waiting to load from us
        super().on_done(t, now)
