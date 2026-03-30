# Create tests/test_behavior.py

import unittest
from modules.detection.behavior import score_event, aggregate_process_scores

class TestBehaviorScoring(unittest.TestCase):
    
    def test_high_entropy_scoring(self):
        event = {
            "tag": "SNAPSHOT-MOD",
            "details": "File modified: test.docx (entropy=7.9)",
            "entropy": 7.9
        }
        score = score_event(event)
        self.assertGreater(score, 30, "High entropy should trigger significant score")
    
    def test_suspicious_parent_process(self):
        event = {
            "name": "winword.exe",
            "details": "Parent: powershell.exe",
            "tag": "PROCESS"
        }
        score = score_event(event)
        self.assertGreater(score, 20, "Office spawning PowerShell is suspicious")
    
    # Add more tests...

if __name__ == '__main__':
    unittest.main()