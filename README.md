Phishing URL Detection System

This project is a full-stack web application that detects potentially malicious or phishing URLs using a machine learning model. Designed for real-time inference, it integrates a Python-based FastAPI backend with a user-friendly frontend built using HTML, CSS, and JavaScript.

Features
Machine Learning Model trained to classify URLs as safe or phishing.
FastAPI Backend for efficient, asynchronous API handling.
Frontend Interface for user interaction, allowing quick and easy URL checks.
Joblib Model Integration for fast and scalable inference.
Modular Code Design for easy maintenance and extension.

Tech Stack
Backend: Python, FastAPI
Frontend: HTML, CSS, JavaScript
ML Model: Scikit-learn, Joblib
Deployment: Uvicorn


How to Run the Project

Follow these steps to set up and run the Phishing URL Detection System locally:

1. Clone the Repository
git clone https://github.com/malaknabeelkhan/phishing-url-detector.git
cd phishing-url-detection-system

2. Install Dependencies
Make sure Python 3.10+ is installed. Then, create a virtual environment (recommended) and install the required packages:

python -m venv venv
venv\Scripts\activate    # On Windows
source venv/bin/activate  # On macOS/Linux

pip install -r requirements.txt

3. Start the Backend Server

Navigate to the app directory and run the FastAPI server:
cd app
uvicorn main:app --reload
This will start the backend at: http://127.0.0.1:8000

You can access the interactive API documentation at:
http://127.0.0.1:8000/docs

4. Launch the Frontend
You can access the interface by visiting:
http://127.0.0.1:8000/

This link will appear in your terminal when you run the command:
uvicorn app.main:app --reload
From there, simply enter a URL in the form to check whether it's Legitimate or Phishing — powered by your trained machine learning model.


![5](https://github.com/user-attachments/assets/94fc9825-c5b1-4193-bf7d-a01f2e5bc714)
![3](https://github.com/user-attachments/assets/77dedc6e-1833-4309-b27b-bf327345d5c9)
![4](https://github.com/user-attachments/assets/c7dcd838-6e18-48cb-8d5e-6539f0090b69)
