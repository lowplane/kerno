# complete code
import time
import random

class RateLimiter:
    def __init__(self, budget, interval):
        self.budget = budget
        self.interval = interval
        self.tokens = budget
        self.last_update = time.time()

    def update(self):
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(self.tokens + (elapsed / self.interval) * self.budget, self.budget)
        self.last_update = now

    def is_allowed(self):
        self.update()
        return self.tokens > 0

class Sampler:
    def __init__(self, target_overhead_pct):
        self.target_overhead_pct = target_overhead_pct
        self.sample_rate = 1.0 / target_overhead_pct

    def sample(self):
        return random.random() < self.sample_rate

class RateLimiterAndSampler:
    def __init__(self, rate_limiter, sampler):
        self.rate_limiter = rate_limiter
        self.sampler = sampler

    def is_allowed(self):
        return self.rate_limiter.is_allowed() or self.sampler.sample()