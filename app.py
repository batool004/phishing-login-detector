import streamlit as st
import joblib

model = joblib.load("model.pkl")

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

st.title("Phishing URL Detector 🚨")

url = st.text_input("Enter URL:")

if st.button("Check"):
    features = extract_features(url)
    result = model.predict([features])

    if result[0] == 1:
        st.error("Phishing 🚨")
    else:
        st.success("Legit ✅")