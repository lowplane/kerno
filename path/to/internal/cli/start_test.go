# complete code
import unittest
import time
import random

class StartTest(unittest.TestCase):
    def test_start(self):
        rate_limiter = RateLimiter(500000, 1)
        sampler = Sampler(1.0)
        start = Start(rate_limiter, sampler)
        start.start()
        self.assertTrue(True)