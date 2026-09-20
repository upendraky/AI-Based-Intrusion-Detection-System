import joblib

from src.features.live_feature_extractor import LiveFeatureExtractor


class LivePredictor:

    def __init__(self):

        self.model = joblib.load(
            "models/best_ids_model.pkl"
        )

        self.selector = joblib.load(
            "models/feature_selector.pkl"
        )

        self.extractor = LiveFeatureExtractor(
            self.selector.feature_names_in_
        )

    def predict_flow(self, flow):

        df = self.extractor.extract(flow)

        X_selected = self.selector.transform(df)

        prediction = self.model.predict(
            X_selected
        )[0]

        probability = self.model.predict_proba(
            X_selected
        )[0][1]

        return {
            "prediction": int(prediction),
            "probability": float(probability)
        }
