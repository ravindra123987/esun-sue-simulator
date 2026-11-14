"""A minimal discrete-event engine. Time is in nanoseconds (float)."""

import heapq
import itertools


class Sim:
    def __init__(self):
        self.now = 0.0
        self._q = []
        self._n = itertools.count()

    def at(self, t: float, fn, *args):
        heapq.heappush(self._q, (t, next(self._n), fn, args))

    def after(self, dt: float, fn, *args):
        self.at(self.now + dt, fn, *args)

    def run(self, until: float):
        while self._q and self._q[0][0] <= until:
            t, _, fn, args = heapq.heappop(self._q)
            self.now = t
            fn(*args)
        self.now = until
