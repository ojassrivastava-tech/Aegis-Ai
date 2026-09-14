import unittest

from src import train_model


class TestModelSelection(unittest.TestCase):
    def test_select_best_model_returns_known_candidate(self):
        X = [
            [0, 0, 0], [0, 1, 0], [1, 0, 0], [1, 1, 1],
            [0, 0, 1], [1, 1, 0], [0, 1, 1], [1, 0, 1],
        ]
        y = [0, 0, 0, 1, 0, 1, 1, 1]

        model_name, model = train_model.select_best_model(X, y)

        self.assertIn(model_name, train_model.MODEL_CANDIDATES)
        self.assertIsNotNone(model)
        self.assertGreaterEqual(train_model.evaluate_model(model, X, y)["accuracy"], 0.75)

    def test_build_explainer_supports_non_tree_models(self):
        X = [
            [0.1, 2.0], [0.2, 1.5], [1.0, 0.1], [0.9, 0.2],
            [0.3, 1.8], [1.2, 0.0], [0.8, 0.3], [0.7, 0.5],
        ]
        y = [0, 0, 1, 1, 0, 1, 1, 0]

        from sklearn.linear_model import LogisticRegression

        model = LogisticRegression(max_iter=1000, random_state=42)
        model.fit(X, y)

        explainer = train_model.build_explainer(model, X)
        self.assertIsNotNone(explainer)


if __name__ == "__main__":
    unittest.main()
