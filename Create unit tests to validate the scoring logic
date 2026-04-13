# intel/tests/test_threatfoundry_scoring.py
import unittest
from intel.services.threatfoundry_scoring import ThreatFoundryScorer

class TestThreatFoundryScorer(unittest.TestCase):
    def test_calculate_score(self):
        scorer = ThreatFoundryScorer()
        
        # Mock record data
        record_data = {
            "source_name": "example_source",
            "value_type": "domain",
            "value": "example.com",
            # Other fields...
        }
        
        score = scorer.calculate_score(record_data)
        self.assertIsInstance(score, float)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 100.0)

if __name__ == '__main__':
    unittest.main()
