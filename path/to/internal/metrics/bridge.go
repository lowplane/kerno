# complete code
import time
import random

class Bridge:
    def __init__(self, metrics):
        self.metrics = metrics

    def get_metrics(self):
        return self.metrics.get_drop_count(), self.metrics.get_sampled_count()