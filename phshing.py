import pandas as pd

data = {
    "url": [
        "https://www.google.com",
        "https://www.facebook.com",
        "http://secure-login-bank.xyz",
        "http://fake-paypal-login.xyz",
        "https://github.com"
    ],
    "label": [0, 0, 1, 1, 0]  # 0 = legit, 1 = phishing
}

df = pd.DataFrame(data)
print(df)
def extract_features(url):
    features = []
    
    # طول الرابط
    features.append(len(url))
    
    # هل فيه https
    features.append(1 if "https" in url else 0)
    
    # هل فيه @
    features.append(1 if "@" in url else 0)
    
    # عدد النقاط
    features.append(url.count('.'))
    
    # هل فيه كلمة login
    features.append(1 if "login" in url else 0)
    
    return features
X = df["url"].apply(extract_features).tolist()
y = df["label"]

print(X)
from sklearn.model_selection import train_test_split

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)
from sklearn.tree import DecisionTreeClassifier

model = DecisionTreeClassifier()
model.fit(X_train, y_train)
predictions = model.predict(X_test)

print(predictions)
from sklearn.metrics import accuracy_score

accuracy = accuracy_score(y_test, predictions)
print("Accuracy:", accuracy)
new_url = "http://secure-login-facebook.xyz"
features = extract_features(new_url)

result = model.predict([features])

if result[0] == 1:
    print("Phishing 🚨")
else:
    print("Legit ✅")

import pandas as pd
print(df.head())
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)


model = DecisionTreeClassifier()

model.fit(X_train, y_train)
from sklearn.metrics import accuracy_score

predictions = model.predict(X_test)

print("Accuracy:", accuracy_score(y_test, predictions))
url = input("Enter URL: ")

features = extract_features(url)
result = model.predict([features])

if result[0] == 1:
    print("Phishing 🚨")
else:
    print("Legit ✅")