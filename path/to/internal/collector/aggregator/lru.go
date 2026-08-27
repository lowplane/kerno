# complete code
import time
import random

class LRU:
    def __init__(self, capacity):
        self.capacity = capacity
        self.cache = {}

    def get(self, key):
        if key in self.cache:
            value = self.cache[key]
            del self.cache[key]
            self.cache[key] = value
            return value
        return None

    def set(self, key, value):
        if key in self.cache:
            del self.cache[key]
        elif len(self.cache) >= self.capacity:
            random_key = random.choice(list(self.cache.keys()))
            del self.cache[random_key]
        self.cache[key] = value