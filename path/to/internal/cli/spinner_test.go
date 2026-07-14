# complete code
import unittest
import time
import random

class SpinnerTest(unittest.TestCase):
    def test_spinner(self):
        spinner = Spinner()
        spinner.start()
        time.sleep(1)
        spinner.stop()
        self.assertFalse(spinner.running)