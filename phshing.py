import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# تحميل dataset
df = pd.read_csv("phishing_url_dataset.csv")

# استخدام الميزات الموجودة في CSV
feature_columns = [
    "url_length", "valid_url", "at_symbol", "sensitive_words_count",
    "path_length", "isHttps", "nb_dots", "nb_hyphens",
    "nb_and", "nb_or", "nb_www", "nb_com", "nb_underscore"
]

X = df[feature_columns]   # كل الأعمدة اللي تمثل الميزات
y = df["target"]          # العمود الهدف

# تقسيم البيانات
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# الموديل
model = RandomForestClassifier(n_estimators=100)
print("Training model...")
model.fit(X_train, y_train)

# تقييم
predictions = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, predictions))

# حفظ الموديل
joblib.dump(model, "model.pkl")
print("Model saved!")
