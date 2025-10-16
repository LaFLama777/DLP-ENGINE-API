import streamlit as st
import pandas as pd
import requests
import os
from dotenv import load_dotenv  # Load from .env file

# Load environment variables from .env file
load_dotenv()

# Set the page title and configure for a cool, comprehensive layout
st.set_page_config(page_title="DLP Remediation Cockpit", layout="wide", initial_sidebar_state="expanded")
st.title('DLP Remediation Cockpit')  # Main title

# Sidebar for controls
st.sidebar.header("Dashboard Settings")
api_url = os.getenv('API_URL')  # Get from environment or .env file
api_url_input = st.sidebar.text_input("Enter API URL (if not set in environment)", value=api_url or "http://localhost:8000")

if not api_url and not api_url_input:
    st.sidebar.error("API_URL is not set. Please enter it above or in your .env file.")
else:
    api_url = api_url_input or api_url  # Use input if available

# Function to fetch data from the API
def fetch_data(url):
    try:
        full_url = f"{url}/incidents"
        response = requests.get(full_url)
        response.raise_for_status()  # Raise error for bad status codes
        data = response.json()  # Assuming the response is a JSON list or object
        return data
    except requests.exceptions.RequestException as e:
        st.error(f"Error fetching data: {e}")
        return None

# Main content
st.header("Incidents Overview")
st.write("This dashboard displays data from your DLP Remediation API. Click 'Refresh Data' to update.")

if st.button('Refresh Data'):
    with st.spinner("Fetching data..."):  # Cool loading indicator
        data = fetch_data(api_url)
        
        if data is not None:
            if isinstance(data, list) and len(data) > 0:
                # Convert to DataFrame and make it comprehensive
                df = pd.DataFrame(data)
                
                # Add comprehensive summaries (KPIs)
                st.subheader("Key Metrics")
                col1, col2, col3 = st.columns(3)
                col1.metric("Total Incidents", len(df))
                if 'timestamp' in df.columns:
                    col2.metric("Most Recent Incident", df['timestamp'].max())
                    col3.metric("Oldest Incident", df['timestamp'].min())
                else:
                    col2.metric("Total Users Involved", df['user_principal_name'].nunique())
                    col3.metric("Unique Incidents", len(df['incident_title'].unique()))
                
                # Display the table with sorting and filtering
                st.subheader("Incidents Table")
                st.dataframe(df, use_container_width=True)  # Full-width, interactive table
                
                # Add a cool chart for visualization (e.g., if timestamps are present)
                if 'timestamp' in df.columns and 'id' in df.columns:
                    st.subheader("Incidents Over Time")
                    df['timestamp'] = pd.to_datetime(df['timestamp'])  # Ensure datetime format
                    chart_data = df.groupby(df['timestamp'].dt.date).size().reset_index(name='count')
                    st.line_chart(chart_data.set_index('timestamp'), height=300)  # Cool line chart
                else:
                    st.info("No timestamp data available for charting.")
            elif isinstance(data, dict):
                st.warning("Received a single object; displaying as table.")
                df = pd.DataFrame([data])
                st.dataframe(df, use_container_width=True)
            else:
                st.warning("No incidents found or invalid data format.")
else:
    st.info("Use the 'Refresh Data' button to load or update the incidents table.")

st.sidebar.caption("Made with Streamlit for a cool and comprehensive experience!")
