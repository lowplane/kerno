# complete code
import unittest
import time
import random

class HistogramTest(unittest.TestCase):
    def test_histogram(self):
        histogram = Histogram(10)
        histogram.update(5)
        self.assertEqual(histogram.get_percentile(50), 5)