# complete code
import unittest
import time
import random

class RateLimiterTest(unittest.TestCase):
    def test_rate_limiter(self):
        rate_limiter = RateLimiter(500000, 1)
        self.assertTrue(rate_limiter.is_allowed())
        time.sleep(1)
        self.assertFalse(rate_limiter.is_allowed())