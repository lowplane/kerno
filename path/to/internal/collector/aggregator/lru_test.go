# complete code
import unittest
import time
import random

class LRUTest(unittest.TestCase):
    def test_lru(self):
        lru = LRU(10)
        lru.set("key", "value")
        self.assertEqual(lru.get("key"), "value")