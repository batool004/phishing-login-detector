import pandas as pd
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

data = {
    "url": [
        "https://www.google.com",
        "https://www.facebook.com",
        "http://secure-login-bank.xyz",
        "http://fake-paypal-login.xyz",
        "https://github.com"
    ],
    "label": [0, 0, 1, 1, 0]
}

df = pd.DataFrame(data)

def extract_features(url):
    return [
        len(url),
        int("https" in url),
        int("@" in url),
        url.count('.'),
        int("login" in url),
        int("-" in url),
        int(url.count("http") > 1),
        int(len(url.split(".")) > 3)
    ]

X = df["url"].apply(extract_features).tolist()
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

if os.path.exists("model.pkl"):
    print("Loading existing model...")
    model = joblib.load("model.pkl")
else:
    print("Training new model...")
    model = RandomForestClassifier(n_estimators=100)
    model.fit(X_train, y_train)
    joblib.dump(model, "model.pkl")
    print("Model saved!")

predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

print("Accuracy:", accuracy)

def predict_url(url):
    features = extract_features(url)
    result = model.predict([features])

    if result[0] == 1:
        return "Phishing 🚨"
    else:
        return "Legit ✅"

url = input("Enter URL: ")
print(predict_url(url))