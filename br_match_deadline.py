"""Per-attempt BR squad deadline; local fallback, never server-end evidence.

All methods run on one asyncio event loop. The monotonic deadline starts once,
when all expected members have a parsed assignment in this attempt. Packet
traffic cannot refresh it. Only accepted cmd103 for every member disarms it.
"""
import asyncio
from collections import UserDict
from datetime import datetime
import math
import uuid

BR_MATCH_END_FALLBACK_SECONDS = 11 * 60 + 30
# Private contract between the one-attempt worker and its BR frontend.
BR_MATCH_FALLBACK_EXIT_CODE = 75


class BrMatchDeadlineExpired(RuntimeError):
    """The local timer expired; sessions were cleaned up, end is unconfirmed."""


class BrMatchEndDeadline:
    def __init__(self, seconds=BR_MATCH_END_FALLBACK_SECONDS, *, loop=None):
        if (isinstance(seconds, bool) or not isinstance(seconds, (int, float))
                or not math.isfinite(seconds) or seconds <= 0):
            raise ValueError('BR match-end fallback must be finite positive seconds')
        self.loop = loop if loop is not None else asyncio.get_running_loop()
        self.seconds = float(seconds)
        # Diagnostic only: not an account, session token or server match ID.
        self.attempt_id = uuid.uuid4().hex[:12]
        self.expired = self.loop.create_future()
        self.expected = frozenset()
        self.assigned = set()
        self.accepted_ends = set()
        self.started_at = None
        self.deadline = None
        self.confirmed = False
        self.cleanup_started = False
        self._timer = None
        self._finished = False
        self._closed = False

    def expect(self, tags):
        if self._closed or self.started_at is not None or self.assigned or self._finished:
            raise RuntimeError('Cannot change BR squad members after an attempt starts')
        tags = tuple(tags)
        if not tags or len(tags) != len(set(tags)):
            raise ValueError('BR deadline needs unique local squad tags')
        self.expected = frozenset(tags)

    def assignment(self, tag):
        """Record one expected assignment; arm only after the whole squad has one."""
        if (self._closed or self._finished or self.started_at is not None
                or tag not in self.expected):
            return False
        self.assigned.add(tag)
        if self.assigned != self.expected:
            return False
        self.started_at = self.loop.time()
        self.deadline = self.started_at + self.seconds
        self._timer = self.loop.call_at(self.deadline, self._expire)
        return True

    def _expire(self):
        if self._closed or self._finished or self.confirmed or self.expired.done():
            return
        # Some event loops may deliver a timer up to one clock resolution early.
        if self.loop.time() < self.deadline:
            self._timer = self.loop.call_at(self.deadline, self._expire)
            return
        self._timer = None
        self.expired.set_result(None)

    def accepted_end_103(self, tag):
        """Record only a receiver-accepted 103; exactly at the deadline is late."""
        if (self._closed or self._finished or self.started_at is None
                or self.confirmed or self.expired.done() or tag not in self.expected):
            return False
        if self.loop.time() >= self.deadline:
            self._expire()
            return False
        self.accepted_ends.add(tag)
        if self.accepted_ends == self.expected:
            self.confirmed = True
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
        return True

    def finish_attempt(self):
        """Stop a completed attempt's timer, but do not hide an overdue expiry."""
        if self._finished:
            return
        if (not self._closed and not self.confirmed and self.deadline is not None
                and self.loop.time() >= self.deadline):
            self._expire()
        self._finished = True
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def close(self):
        self._closed = True
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        if not self.expired.done():
            self.expired.cancel()


class BrMatchAssignments(UserDict):
    """Arm the current attempt only after every expected assignment is present."""
    def __init__(self, deadline, *, on_started=None):
        self.match_deadline = deadline
        self.on_started = on_started
        super().__init__()

    def __setitem__(self, tag, assignment):
        self.data[tag] = assignment
        clock = self.match_deadline
        # Do not arm from a partial/unknown/None entry. No await occurs here,
        # so the last valid assignment and the timer start are atomic on this
        # worker's event loop. Duplicate/later updates never reset the clock.
        if (clock.started_at is not None or not clock.expected or
                any(self.data.get(t) is None for t in clock.expected)):
            return
        for member in clock.expected:
            if clock.assignment(member):
                stamp = datetime.now().strftime('%H:%M:%S')
                message = (f'Attempt {clock.attempt_id}: all {len(clock.expected)} BR assignments received; '
                           f'{clock.seconds:g}-second end-confirmation fallback started.')
                print(f'  [{stamp}] {message}', flush=True)
                if self.on_started is not None:
                    self.on_started(message)
