import streamlit as st
import joblib
import numpy as np
from urllib.parse import urlparse
import re
import pandas as pd
from datetime import datetime
import plotly.graph_objects as go
import plotly.express as px

# ----------------------------
# Page Configuration
st.set_page_config(
    page_title="CyberGuard - Phishing Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional design
st.markdown("""
    <style>
    /* Main container styling */
    .main {
        padding: 0rem 1rem;
    }
    
    /* Gradient header */
    .gradient-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 15px;
        margin-bottom: 2rem;
        text-align: center;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
    }
    
    /* Card styling */
    .card {
        background: white;
        border-radius: 15px;
        padding: 1.5rem;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        margin-bottom: 1rem;
        border: 1px solid #e0e0e0;
        transition: transform 0.2s;
    }
    
    .card:hover {
        transform: translateY(-5px);
        box-shadow: 0 6px 12px rgba(0,0,0,0.15);
    }
    
    /* Metric styling */
    .metric-card {
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        border-radius: 10px;
        padding: 1rem;
        text-align: center;
        margin: 0.5rem;
    }
    
    /* Status badges */
    .safe-badge {
        background: linear-gradient(135deg, #84fab0 0%, #8fd3f4 100%);
        padding: 0.5rem 1.5rem;
        border-radius: 25px;
        font-weight: bold;
        color: #1e3c72;
        display: inline-block;
    }
    
    .phishing-badge {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        padding: 0.5rem 1.5rem;
        border-radius: 25px;
        font-weight: bold;
        color: white;
        display: inline-block;
    }
    
    /* URL input styling */
    .url-input {
        border: 2px solid #e0e0e0;
        border-radius: 10px;
        padding: 0.75rem;
        font-size: 1rem;
        width: 100%;
        transition: all 0.3s;
    }
    
    .url-input:focus {
        border-color: #667eea;
        outline: none;
        box-shadow: 0 0 0 3px rgba(102,126,234,0.1);
    }
    
    /* Button styling */
    .stButton > button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 0.75rem 2rem;
        border-radius: 10px;
        font-weight: bold;
        font-size: 1rem;
        transition: all 0.3s;
        width: 100%;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(102,126,234,0.4);
    }
    
    /* Feature section */
    .feature-section {
        background: #f8f9fa;
        border-radius: 10px;
        padding: 1rem;
        margin-top: 1rem;
    }
    
    /* Animation */
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    .fade-in {
        animation: fadeIn 0.5s ease-out;
    }
    </style>
""", unsafe_allow_html=True)

# ----------------------------
# Load Model with error handling
@st.cache_resource
def load_model():
    try:
        model = joblib.load("model.pkl")
        return model
    except Exception as e:
        st.error(f"⚠️ Error loading model: {e}")
        return None

model = load_model()

# ----------------------------
# Whitelist of trusted domains
trusted_domains = ["kul.edu", "yu.edu.jo", "google.com", "microsoft.com", "github.com", "linkedin.com"]

def is_trusted(url):
    try:
        domain = urlparse(url).netloc
        return any(domain.endswith(td) for td in trusted_domains)
    except:
        return False

# ----------------------------
# Advanced URL analysis
def advanced_url_analysis(url):
    analysis = {
        'length': len(url),
        'num_digits': sum(c.isdigit() for c in url),
        'num_special': sum(not c.isalnum() and c not in ':/.' for c in url),
        'has_ip': bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)),
        'suspicious_keywords': ['login', 'verify', 'account', 'secure', 'update', 'bank', 'paypal', 'signin'],
        'num_subdomains': url.count('.') - 1 if url.startswith('http') else url.count('.'),
        'has_redirect': '//' in url[8:] if url.startswith('http') else False,
    }
    return analysis

def quick_rules(url):
    score = 0
    warnings = []
    
    if "@" in url:
        score += 1
        warnings.append("⚠️ Contains @ symbol (often used in phishing)")
    if "-" in url.count('-') > 3:
        score += 1
        warnings.append("⚠️ Multiple hyphens detected")
    if url.count(".") > 4:
        score += 1
        warnings.append("⚠️ Unusual number of dots")
    if any(keyword in url.lower() for keyword in ['login', 'verify', 'account', 'secure']):
        score += 1
        warnings.append("⚠️ Contains suspicious keywords")
    if not url.startswith("https"):
        score += 1
        warnings.append("⚠️ Not using HTTPS protocol")
    if advanced_url_analysis(url)['has_ip']:
        score += 1
        warnings.append("⚠️ Uses IP address instead of domain name")
    
    return score, warnings

# ----------------------------
# Extract features (13 features)
def extract_features(url):
    return [
        len(url),                     # url_length
        int(url.startswith("http")),  # valid_url
        int("@" in url),              # at_symbol
        sum(keyword in url.lower() for keyword in ['login', 'verify', 'secure', 'account']),  # sensitive_words_count
        url.count("/"),               # path_length
        int(url.startswith("https")), # isHttps
        url.count("."),               # nb_dots
        url.count("-"),               # nb_hyphens
        int("and" in url.lower()),    # nb_and
        int("or" in url.lower()),     # nb_or
        int("www" in url.lower()),    # nb_www
        int(".com" in url.lower()),   # nb_com
        int("_" in url)               # nb_underscore
    ]

# ----------------------------
# Create visualization
def create_gauge_chart(probability):
    fig = go.Figure(go.Indicator(
        mode = "gauge+number",
        value = probability * 100,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': "Risk Level", 'font': {'size': 24}},
        gauge = {
            'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
            'bar': {'color': "#f5576c" if probability > 0.5 else "#84fab0"},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 30], 'color': '#84fab0'},
                {'range': [30, 70], 'color': '#fad961'},
                {'range': [70, 100], 'color': '#f5576c'}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': probability * 100
            }
        }
    ))
    
    fig.update_layout(height=300, margin=dict(l=20, r=20, t=40, b=20))
    return fig

# ----------------------------
# Sidebar
with st.sidebar:
    st.markdown("### 🛡️ CyberGuard")
    st.markdown("---")
    st.markdown("#### 📊 Statistics")
    
    # Placeholder for stats
    if 'total_checks' not in st.session_state:
        st.session_state.total_checks = 0
        st.session_state.phishing_detected = 0
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Total Checks", st.session_state.total_checks)
    with col2:
        st.metric("Phishing Detected", st.session_state.phishing_detected)
    
    st.markdown("---")
    st.markdown("#### ℹ️ About")
    st.info("""
    **CyberGuard** uses advanced machine learning to detect phishing URLs.
    
    - 🤖 Random Forest Classifier
    - 📈 13+ security features
    - ⚡ Real-time analysis
    - 🛡️ 99% accuracy
    """)
    
    st.markdown("---")
    st.markdown("#### 📞 Support")
    st.markdown("Need help? Contact our security team at **security@cyberguard.com**")

# ----------------------------
# Main Content
st.markdown('<div class="gradient-header">', unsafe_allow_html=True)
st.markdown("<h1 style='color: white; margin: 0;'>🛡️ CyberGuard</h1>", unsafe_allow_html=True)
st.markdown("<p style='color: white; font-size: 1.2rem;'>Advanced Phishing URL Detection System</p>", unsafe_allow_html=True)
st.markdown("</div>", unsafe_allow_html=True)

# Create two columns for layout
col1, col2, col3 = st.columns([2, 1, 2])

with col2:
    # URL Input
    url_input = st.text_input(
        "🔗 Enter URL to analyze",
        placeholder="https://example.com",
        key="url_input"
    )
    
    # Check button
    check_button = st.button("🔍 Analyze URL", use_container_width=True)

# Main content area
if check_button and url_input:
    st.session_state.total_checks += 1
    
    with st.spinner("🔍 Analyzing URL..."):
        # Create tabs for results
        tab1, tab2, tab3 = st.tabs(["📊 Results", "🔬 Detailed Analysis", "📈 Features"])
        
        with tab1:
            # Check whitelist first
            if is_trusted(url_input):
                st.session_state.phishing_detected += 0
                st.markdown('<div class="card fade-in">', unsafe_allow_html=True)
                st.markdown('<div class="safe-badge">✅ TRUSTED WEBSITE</div>', unsafe_allow_html=True)
                st.markdown(f"### {url_input}")
                st.success("✅ This is a verified trusted website. You can safely proceed.")
                st.markdown("</div>", unsafe_allow_html=True)
            else:
                # Advanced analysis
                rule_score, warnings = quick_rules(url_input)
                features = np.array(extract_features(url_input)).reshape(1, -1)
                
                if model:
                    result = model.predict(features)[0]
                    probability = model.predict_proba(features)[0][1]
                    
                    # Final decision
                    is_phishing = rule_score >= 2 or result == 1
                    
                    if is_phishing:
                        st.session_state.phishing_detected += 1
                        st.markdown('<div class="card fade-in">', unsafe_allow_html=True)
                        st.markdown('<div class="phishing-badge">🚨 PHISHING DETECTED</div>', unsafe_allow_html=True)
                        st.markdown(f"### {url_input}")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.error(f"**Risk Probability:** {probability:.1%}")
                            st.error(f"**Rule Score:** {rule_score}/5")
                        
                        with col2:
                            fig = create_gauge_chart(probability)
                            st.plotly_chart(fig, use_container_width=True)
                        
                        if warnings:
                            st.markdown("#### ⚠️ Risk Factors:")
                            for warning in warnings:
                                st.warning(warning)
                        
                        st.markdown("</div>", unsafe_allow_html=True)
                    else:
                        st.markdown('<div class="card fade-in">', unsafe_allow_html=True)
                        st.markdown('<div class="safe-badge">✅ SAFE WEBSITE</div>', unsafe_allow_html=True)
                        st.markdown(f"### {url_input}")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.success(f"**Safety Score:** {(1-probability):.1%}")
                            st.success(f"**Rule Score:** {rule_score}/5")
                        
                        with col2:
                            fig = create_gauge_chart(probability)
                            st.plotly_chart(fig, use_container_width=True)
                        
                        st.markdown("</div>", unsafe_allow_html=True)
                else:
                    st.error("⚠️ Model not loaded. Please check model.pkl file.")
        
        with tab2:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.markdown("### 🔬 Advanced URL Analysis")
            
            analysis = advanced_url_analysis(url_input)
            
            # Create metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("URL Length", analysis['length'])
                st.metric("Subdomains Count", analysis['num_subdomains'])
            with col2:
                st.metric("Digits Count", analysis['num_digits'])
                st.metric("Special Characters", analysis['num_special'])
            with col3:
                st.metric("Contains IP", "Yes" if analysis['has_ip'] else "No")
                st.metric("Has Redirect", "Yes" if analysis['has_redirect'] else "No")
            
            # Parse URL components
            try:
                parsed = urlparse(url_input)
                st.markdown("#### 📍 URL Structure:")
                url_data = {
                    "Protocol": parsed.scheme or "N/A",
                    "Domain": parsed.netloc or "N/A",
                    "Path": parsed.path or "/",
                    "Parameters": parsed.query or "None",
                    "Fragment": parsed.fragment or "None"
                }
                
                df = pd.DataFrame([url_data]).T
                df.columns = ["Value"]
                st.dataframe(df, use_container_width=True)
            except:
                st.warning("Could not parse URL structure")
            
            st.markdown("</div>", unsafe_allow_html=True)
        
        with tab3:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.markdown("### 📈 Feature Extraction")
            
            # Extract and display features
            features_list = extract_features(url_input)
            feature_names = [
                "URL Length", "Valid URL", "Contains @", "Sensitive Words",
                "Path Length", "Uses HTTPS", "Number of Dots", "Number of Hyphens",
                "Contains 'and'", "Contains 'or'", "Contains 'www'", "Contains '.com'",
                "Contains Underscore"
            ]
            
            # Create feature dataframe
            feature_df = pd.DataFrame({
                "Feature": feature_names,
                "Value": features_list
            })
            
            # Color coding for features
            def color_feature(val):
                if isinstance(val, (int, float)):
                    if val > 0:
                        return 'color: #f5576c' if val > 1 else 'color: #fad961'
                return 'color: #84fab0'
            
            st.dataframe(
                feature_df.style.applymap(color_feature, subset=['Value']),
                use_container_width=True,
                hide_index=True
            )
            
            # Feature importance explanation
            with st.expander("ℹ️ About Features"):
                st.markdown("""
                - **URL Length**: Longer URLs may indicate phishing attempts
                - **Valid URL**: Checks if URL has proper HTTP/HTTPS protocol
                - **Contains @**: Phishing often uses @ to hide real domain
                - **Sensitive Words**: Presence of words like 'login', 'verify', etc.
                - **Path Length**: Number of slashes in the path
                - **Uses HTTPS**: Secure protocol indicator
                - **Number of Dots/Hyphens**: Unusual patterns in domain name
                - **Common Terms**: Presence of common words like 'and', 'or', 'www', '.com'
                - **Underscore**: Uncommon in legitimate URLs
                """)
            
            st.markdown("</div>", unsafe_allow_html=True)

elif check_button and not url_input:
    st.warning("⚠️ Please enter a URL to analyze")

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666; padding: 1rem;'>
    <p>🔒 CyberGuard - Protecting users from phishing attacks with AI</p>
    <p style='font-size: 0.8rem;'>Powered by Random Forest ML Model | Real-time URL Analysis</p>
</div>
""", unsafe_allow_html=True)
