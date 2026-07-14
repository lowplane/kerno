# complete code
import time
import random

class Spinner:
    def __init__(self):
        self.running = True

    def start(self):
        while self.running:
            time.sleep(1)

    def stop(self):
        self.running = False