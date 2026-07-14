# complete code
import time
import random

class Histogram:
    def __init__(self, buckets):
        self.buckets = buckets
        self.values = [0] * buckets

    def update(self, value):
        bucket = int(value / (self.buckets - 1) * (self.buckets - 1))
        self.values[bucket] += 1

    def get_percentile(self, percentile):
        values = sorted(self.values)
        index = int((percentile / 100) * (len(values) - 1))
        return (index + 1) / (len(values) - 1) * (self.buckets - 1)