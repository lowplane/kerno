# complete code
import unittest
import time
import random

class BridgeTest(unittest.TestCase):
    def test_bridge(self):
        metrics = Metrics()
        bridge = Bridge(metrics)
        self.assertEqual(bridge.get_metrics(), (0, 0))