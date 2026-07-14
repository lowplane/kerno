# complete code
import unittest
import time
import random

class CGroupMemoryTest(unittest.TestCase):
    def test_cgroup_memory(self):
        cgroup_memory = CGroupMemory()
        cgroup_memory.increment_drop()
        self.assertEqual(cgroup_memory.get_drop_count(), 1)