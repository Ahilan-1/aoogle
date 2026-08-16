"""ModelRouter — rate-limit + token-budget aware model routing middleware.

Tracks live RPM / RPD / TPM / TPD usage for every model in the lineup and
routes each request to the next model that still has headroom. When every
model is exhausted it returns a "wait" estimate so callers can either tell the
user to retry shortly or show a graceful notice instead of a 429 crash.

Design notes:
  * Budget windows are rolling: RPM/TPM look back 60s, RPD/TPD look back 24h.
  * The router never blocks a request thread — it *recommends* a model. Callers
    call `pick()` before a request and `record()` after it completes.
  * On a 429/5xx/overload the caller calls `mark_failure(model, error)` and the
    router applies an exponential cooldown so the broken model is skipped for a
    while instead of being retried on every request.
  * `status()` returns a JSON-friendly snapshot for the admin dashboard graph.
"""
from __future__ import annotations

import threading
import time


class ModelRouter:
    def __init__(self, budgets=None, order=None, now=None):
        self.budgets = dict(budgets or {})
        self.order = list(order or [])
        self._lock = threading.RLock()
        self._now = now or time.time
        # usage history: model -> list of (ts, tokens)
        self._usage = {m: [] for m in self.budgets}
        self._cooldown_until = {}      # model -> wall time it may be used again
        self._fail_streak = {}         # model -> consecutive failures
        self._last_used = {}           # model -> ts
        self._counters = {             # model -> cumulative stats
            m: {'requests': 0, 'tokens': 0, 'failures': 0, 'successes': 0}
            for m in self.budgets
        }
        self.created_ts = self._now()

    # ── window math ──────────────────────────────────────────────────────────
    @staticmethod
    def _window(hist, span_s, now):
        cutoff = now - span_s
        return [h for h in hist if h[0] >= cutoff]

    def _rpm(self, model, now):
        return len(self._window(self._usage.get(model, []), 60, now))

    def _rpd(self, model, now):
        return len(self._window(self._usage.get(model, []), 86400, now))

    def _tpm(self, model, now):
        return sum(t for _, t in self._window(self._usage.get(model, []), 60, now))

    def _tpd(self, model, now):
        return sum(t for _, t in self._window(self._usage.get(model, []), 86400, now))

    # ── public API ───────────────────────────────────────────────────────────
    def pick(self, est_tokens=0, prefer=None):
        """Return the best model for est_tokens, or None if all are exhausted.

        A model is only returned when it has real headroom right now
        (recovery == 0). Models that are merely "closest to recovering" but
        still over budget are NOT returned — the caller treats a None result
        as "all models busy" and surfaces a wait/retry hint instead of firing
        a request that would 429 and escalate cooldowns.

        `prefer` (optional) is a model to try first even if it is not at the
        top of self.order (used to keep a chat on the same model).
        """
        now = self._now()
        with self._lock:
            order = list(self.order)
            if prefer and prefer in order:
                order.remove(prefer)
                order.insert(0, prefer)
            for model in order:
                if model not in self.budgets:
                    continue
                if self._cooldown_until.get(model, 0) > now:
                    continue
                budget = self.budgets[model]
                # allow headroom for the tokens we're about to send
                tpm = self._tpm(model, now) + est_tokens
                tpd = self._tpd(model, now) + est_tokens
                rpm = self._rpm(model, now) + 1
                rpd = self._rpd(model, now) + 1
                if rpm <= budget.get('rpm', 1 << 30) and \
                        rpd <= budget.get('rpd', 1 << 30) and \
                        tpm <= budget.get('tpm', 1 << 30) and \
                        tpd <= budget.get('tpd', 1 << 30):
                    return model
            return None

    def _recovery_s(self, model, budget, now, est_tokens=0):
        """Seconds until the limiting window slides far enough to free up."""
        wait = 0.0
        hist = self._usage.get(model, [])
        rpm = self._rpm(model, now)
        tpm = self._tpm(model, now)
        if rpm + 1 > budget.get('rpm', 1 << 30):
            # oldest of the newest rpm+1 requests must age out
            need = rpm - budget['rpm'] + 2
            if len(hist) >= need:
                wait = max(wait, 60 - (now - hist[-need][0]))
        tpm_est = tpm + est_tokens
        if tpm_est > budget.get('tpm', 1 << 30):
            need = 1
            for i in range(len(hist) - 1, -1, -1):
                tpm_est -= hist[i][1]
                if tpm_est <= budget['tpm']:
                    need = i
                    break
            if need < len(hist):
                wait = max(wait, 60 - (now - hist[need][0]))
        cooldown = self._cooldown_until.get(model, 0)
        if cooldown > now:
            wait = max(wait, cooldown - now)
        return wait

    def _fits(self, model, budget, est_tokens, now):
        """True if `model` has headroom for a request of est_tokens right now."""
        rpm = self._rpm(model, now)
        rpd = self._rpd(model, now)
        tpm = self._tpm(model, now) + est_tokens
        tpd = self._tpd(model, now) + est_tokens
        return rpm + 1 <= budget.get('rpm', 1 << 30) and \
            rpd + 1 <= budget.get('rpd', 1 << 30) and \
            tpm <= budget.get('tpm', 1 << 30) and \
            tpd <= budget.get('tpd', 1 << 30)

    def record(self, model, tokens=0, success=True):
        """Record a completed request. Call after the model call resolves."""
        now = self._now()
        with self._lock:
            if model in self._usage:
                self._usage[model].append((now, max(0, int(tokens))))
                # prune history beyond 24h to bound memory
                cutoff = now - 86400
                self._usage[model] = [h for h in self._usage[model] if h[0] >= cutoff]
            self._last_used[model] = now
            c = self._counters.setdefault(model, {'requests': 0, 'tokens': 0,
                                                  'failures': 0, 'successes': 0})
            c['requests'] += 1
            c['tokens'] += max(0, int(tokens))
            if success:
                c['successes'] += 1
                self._fail_streak[model] = 0
            else:
                c['failures'] += 1
                self._fail_streak[model] = self._fail_streak.get(model, 0) + 1

    def mark_failure(self, model, error=''):
        """Cooldown a model after a 429/overload/5xx so it is skipped a while."""
        now = self._now()
        with self._lock:
            streak = self._fail_streak.get(model, 0) + 1
            self._fail_streak[model] = streak
            c = self._counters.setdefault(model, {'requests': 0, 'tokens': 0,
                                                  'failures': 0, 'successes': 0})
            c['failures'] += 1
            # exponential backoff: 15s, 60s, 4m, 16m ... capped at 30m
            backoff = min(1800, 15 * (4 ** (streak - 1)))
            self._cooldown_until[model] = now + backoff
            return backoff

    def clear_failure(self, model):
        with self._lock:
            self._cooldown_until[model] = 0
            self._fail_streak[model] = 0

    def cooldown(self, model):
        """Remaining cooldown seconds for a model (0 = usable)."""
        now = self._now()
        return max(0.0, self._cooldown_until.get(model, 0) - now)

    def recovery(self, model, est_tokens=0):
        """Seconds until `model` has real headroom again (0 = usable now).

        Accounts for both rate-limit cooldown (from mark_failure) and rolling
        window pressure (RPM/RPD/TPM/TPD). est_tokens lets callers ask "will
        this request fit?" instead of a zero-size probe.
        """
        now = self._now()
        with self._lock:
            if model not in self.budgets:
                return 0.0
            budget = self.budgets[model]
            return self._recovery_s(model, budget, now, est_tokens=est_tokens)

    def wait(self, est_tokens=0):
        """Shortest wait (s) until ANY model can take a request (0 = ready now).

        The router's best answer to "when can I send work again?" — used for
        the busy/retry hint instead of a generic message.
        """
        now = self._now()
        with self._lock:
            best = float('inf')
            for model in self.order:
                if model not in self.budgets:
                    continue
                if self._cooldown_until.get(model, 0) <= now and \
                        self._fits(model, self.budgets[model], est_tokens, now):
                    return 0.0
                rec = self._recovery_s(model, self.budgets[model], now, est_tokens=est_tokens)
                if rec < best:
                    best = rec
            return 0.0 if best == float('inf') else best

    def usage(self, model):
        now = self._now()
        with self._lock:
            b = self.budgets.get(model) or {}
            return {
                'model': model,
                'rpm': self._rpm(model, now),
                'rpm_limit': b.get('rpm'),
                'rpd': self._rpd(model, now),
                'rpd_limit': b.get('rpd'),
                'tpm': self._tpm(model, now),
                'tpm_limit': b.get('tpm'),
                'tpd': self._tpd(model, now),
                'tpd_limit': b.get('tpd'),
                'cooldown_s': round(self.cooldown(model), 1),
                'fail_streak': self._fail_streak.get(model, 0),
                'counters': dict(self._counters.get(model, {})),
            }

    def status(self):
        """JSON-friendly snapshot for the admin dashboard / architecture graph."""
        return {
            'created_ts': self.created_ts,
            'models': [self.usage(m) for m in self.order if m in self.budgets],
            'healthy': [m for m in self.order
                        if m in self.budgets and self.cooldown(m) == 0
                        and self._window(self._usage.get(m, []), 60, self._now())],
        }


# ── default instances are configured by main.py at import time ─────────────
_default = None


def set_router(router):
    global _default
    _default = router


def get_router():
    return _default
