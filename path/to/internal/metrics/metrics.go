# complete code
import time
import random

class Metrics:
    def __init__(self):
        self.drop_count = 0
        self.sampled_count = 0

    def increment_drop_count(self):
        self.drop_count += 1

    def increment_sampled_count(self):
        self.sampled_count += 1

    def get_drop_count(self):
        return self.drop_count

    def get_sampled_count(self):
        return self.sampled_count