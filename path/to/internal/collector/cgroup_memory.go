# complete code
import time
import random

class CGroupMemory:
    def __init__(self):
        self.drops = 0

    def increment_drop(self):
        self.drops += 1

    def get_drop_count(self):
        return self.drops