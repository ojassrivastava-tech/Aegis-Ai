import unittest
from fastapi.testclient import TestClient
from api.ml_service import app

class TestMLService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_root_health_check(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("status", data)
        self.assertIn("model", data)

    def test_predict_endpoint(self):
        payload = {
            "count": 100,
            "serror_rate": 1.0,
            "dst_host_diff_srv_rate": 0.5
        }
        response = self.client.post("/predict", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("prediction", data)
        self.assertIn("confidence", data)
        self.assertIn(data["prediction"], ["Attack", "Normal"])
        if data["prediction"] == "Attack":
            self.assertIn("top_reasons", data)
            self.assertIn("attack_category", data)
            self.assertIn("report", data)
            self.assertIsInstance(data["top_reasons"], list)

if __name__ == "__main__":
    unittest.main()
