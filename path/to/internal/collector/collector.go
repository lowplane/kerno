# complete code
import time
import random

class Collector:
    def __init__(self, rate_limiter, sampler):
        self.rate_limiter = rate_limiter
        self.sampler = sampler

    def record(self, event):
        if self.rate_limiter.is_allowed():
            self.sampler.sample()
        else:
            time.sleep(1)