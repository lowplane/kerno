# complete code
import time
import random

class Config:
    def __init__(self):
        self.rate_limits = {
            "syscall_latency": 500000,
            "sched_delay": 200000
        }
        self.sampling = {
            "enabled": True,
            "target_overhead_pct": 1.0
        }

    def get_rate_limit(self, key):
        return self.rate_limits.get(key, 0)

    def get_sampling_config(self):
        return self.sampling