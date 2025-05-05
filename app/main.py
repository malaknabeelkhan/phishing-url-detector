from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import joblib
import numpy as np
import pandas as pd
from app.features import extract_features  # Ensure this exists and works

# Create FastAPI app
app = FastAPI()

# Serve static files from the 'static' directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# Serve index.html on root
@app.get("/")
async def read_index():
    return FileResponse("static/index.html")

# Load your trained XGBoost model
xgboost_best_model = joblib.load(r"C:\Users\intel computer\OneDrive\Desktop\UrlDetectionSystem\new\xgboost_best_model.joblib")

# Input schema
class URLInput(BaseModel):
    url: str

# Prediction function
def classify_url(best_model, features):
    proba = best_model.predict_proba([features])
    phishing_prob = proba[0][1]

    if phishing_prob > 0.50:
        status = "Legitimate"
    else:
        status = "Phishing"

    return status

# Predict endpoint
@app.post("/predict")
async def predict(input_data: URLInput):
    try:
        url = input_data.url.strip()

        # Validate URL format
        if not (url.startswith("http://") or url.startswith("https://")):
            return JSONResponse(status_code=400, content={"status": "error", "message": "Invalid URL format. Must start with http:// or https://"})

        # Extract features and predict
        features = extract_features(url)
        result = classify_url(xgboost_best_model, features)

        return JSONResponse({
            "status": "checking done",
            "prediction": result,
        })

    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print("ERROR:", error_details)  # Print full traceback in terminal
        return JSONResponse({
            "status": "error",
            "message": f"{str(e)}"
        })