# complete code
import time
import random

class Start:
    def __init__(self, rate_limiter, sampler):
        self.rate_limiter = rate_limiter
        self.sampler = sampler

    def start(self):
        while True:
            if self.rate_limiter.is_allowed():
                self.sampler.sample()
            else:
                time.sleep(1)