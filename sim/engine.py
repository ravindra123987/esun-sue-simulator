"""A minimal discrete-event engine. Time is in nanoseconds (float)."""

import heapq
import itertools


class Sim:
    def __init__(self):
        self.now = 0.0
        self._q = []
        self._n = itertools.count()
        self.trace = None           # list of event dicts when tracing (see sim/trace.py)
        self.after_event = None     # called after every event while tracing (state snapshots)

    def log(self, ev: str, **kw):
        kw["ev"], kw["t"] = ev, round(self.now, 3)
        self.trace.append(kw)

    def at(self, t: float, fn, *args):
        heapq.heappush(self._q, (t, next(self._n), fn, args))

    def after(self, dt: float, fn, *args):
        self.at(self.now + dt, fn, *args)

    def run(self, until: float):
        while self._q and self._q[0][0] <= until:
            t, _, fn, args = heapq.heappop(self._q)
            self.now = t
            fn(*args)
            if self.after_event is not None:
                self.after_event()
        self.now = until
