import streamlit as st
import pandas as pd
import requests
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

#python -m streamlit run dashboard.py
# Load environment variables
load_dotenv()

# Page configuration
st.set_page_config(
    page_title="DLP Remediation Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #1f2937;
        margin-bottom: 1rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .status-badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.875rem;
        font-weight: 600;
    }
    .status-online {
        background-color: #10b981;
        color: white;
    }
    .status-offline {
        background-color: #ef4444;
        color: white;
    }
</style>
""", unsafe_allow_html=True)

# ============================================================================
# CONFIGURATION
# ============================================================================

# Get API URL
API_URL = os.getenv('API_URL', 'http://localhost:8000')

# Sidebar configuration
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=80)
    st.title("⚙️ Dashboard Settings")
    
    # API URL input
    api_url_input = st.text_input(
        "API URL",
        value=API_URL,
        help="Enter the URL of your DLP Remediation Engine API"
    )
    API_URL = api_url_input
    
    # Refresh interval
    refresh_interval = st.slider(
        "Auto-refresh interval (seconds)",
        min_value=10,
        max_value=300,
        value=30,
        step=10
    )
    
    # Auto-refresh toggle
    auto_refresh = st.checkbox("Enable auto-refresh", value=False)
    
    st.divider()
    
    # Connection status
    st.subheader("📡 Connection Status")
    
    # Manual refresh button
    if st.button("🔄 Refresh Now", use_container_width=True):
        st.rerun()

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

@st.cache_data(ttl=30)
def fetch_health_status(url):
    """Fetch health status from API"""
    try:
        response = requests.get(f"{url}/health", timeout=5)
        if response.status_code == 200:
            return response.json(), True
        return None, False
    except Exception as e:
        st.sidebar.error(f"Connection error: {str(e)}")
        return None, False

@st.cache_data(ttl=30)
def fetch_incidents(url, limit=100):
    """Fetch incidents from API"""
    try:
        response = requests.get(f"{url}/incidents?limit={limit}", timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        st.error(f"Error fetching incidents: {str(e)}")
        return None

@st.cache_data(ttl=30)
def fetch_statistics(url):
    """Fetch statistics from API"""
    try:
        response = requests.get(f"{url}/stats", timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        st.warning(f"Could not fetch statistics: {str(e)}")
        return None

# ============================================================================
# MAIN DASHBOARD
# ============================================================================

# Header
st.markdown('<h1 class="main-header">🛡️ DLP Remediation Dashboard</h1>', unsafe_allow_html=True)

# Check connection status
health_data, is_healthy = fetch_health_status(API_URL)

# Display connection status in sidebar
if is_healthy:
    st.sidebar.success("✅ Connected")
    st.sidebar.json(health_data)
else:
    st.sidebar.error("❌ Disconnected")
    st.error("⚠️ Cannot connect to API. Please check the API URL and ensure the service is running.")
    st.stop()

# Connection status banner
col1, col2, col3 = st.columns([2, 1, 1])
with col1:
    st.metric("System Status", "🟢 Online" if is_healthy else "🔴 Offline")
with col2:
    st.metric("API Version", health_data.get("version", "Unknown"))
with col3:
    st.metric("Database", health_data.get("database", "Unknown"))

st.divider()

# ============================================================================
# KEY METRICS
# ============================================================================

st.subheader("📊 Key Metrics")

# Fetch statistics
stats = fetch_statistics(API_URL)

if stats:
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="Total Incidents",
            value=stats.get("total_incidents", 0),
            delta=None
        )
    
    with col2:
        st.metric(
            label="High Risk",
            value=stats.get("high_risk_incidents", 0),
            delta=None
        )
    
    with col3:
        st.metric(
            label="Unique Users",
            value=stats.get("unique_users", 0),
            delta=None
        )
    
    with col4:
        st.metric(
            label="Today",
            value=stats.get("incidents_today", 0),
            delta=None
        )
else:
    st.info("📊 Statistics not available")

st.divider()

# ============================================================================
# INCIDENTS TABLE
# ============================================================================

st.subheader("📋 Recent Incidents")

# Fetch incidents
incidents_data = fetch_incidents(API_URL, limit=100)

if incidents_data and incidents_data.get("incidents"):
    incidents = incidents_data["incidents"]
    total_count = incidents_data.get("total", len(incidents))
    
    # Convert to DataFrame
    df = pd.DataFrame(incidents)
    
    # Add timestamp parsing
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["date"] = df["timestamp"].dt.date
        df["time"] = df["timestamp"].dt.time
    
    # Display total count
    st.info(f"📊 Showing {len(incidents)} of {total_count} total incidents")
    
    # Filter options
    col1, col2 = st.columns(2)
    
    with col1:
        # Search by user
        search_user = st.text_input("🔍 Search by user", "")
        if search_user:
            df = df[df["user_principal_name"].str.contains(search_user, case=False, na=False)]
    
    with col2:
        # Filter by date range
        if "timestamp" in df.columns and not df.empty:
            min_date = df["timestamp"].min().date()
            max_date = df["timestamp"].max().date()
            
            date_range = st.date_input(
                "📅 Date range",
                value=(min_date, max_date),
                min_value=min_date,
                max_value=max_date
            )
            
            if len(date_range) == 2:
                mask = (df["timestamp"].dt.date >= date_range[0]) & (df["timestamp"].dt.date <= date_range[1])
                df = df[mask]
    
    # Display filtered DataFrame
    if not df.empty:
        # Format the display
        display_df = df[["id", "user_principal_name", "incident_title", "timestamp"]].copy()
        display_df.columns = ["ID", "User", "Incident", "Timestamp"]
        
        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "ID": st.column_config.NumberColumn("ID", format="%d"),
                "Timestamp": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss")
            }
        )
        
        # Download button
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download CSV",
            data=csv,
            file_name=f"dlp_incidents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    else:
        st.warning("No incidents match your filters")
    
    # ============================================================================
    # VISUALIZATIONS
    # ============================================================================
    
    if not df.empty and "timestamp" in df.columns:
        st.divider()
        st.subheader("📈 Analytics")
        
        tab1, tab2, tab3 = st.tabs(["Timeline", "User Distribution", "Trends"])
        
        with tab1:
            # Incidents over time
            st.markdown("#### Incidents Timeline")
            
            # Group by date
            timeline_data = df.groupby(df["timestamp"].dt.date).size().reset_index()
            timeline_data.columns = ["Date", "Count"]
            
            fig_timeline = px.line(
                timeline_data,
                x="Date",
                y="Count",
                title="Incidents Over Time",
                markers=True,
                template="plotly_white"
            )
            fig_timeline.update_traces(line_color="#667eea", line_width=3)
            fig_timeline.update_layout(
                xaxis_title="Date",
                yaxis_title="Number of Incidents",
                hovermode="x unified"
            )
            st.plotly_chart(fig_timeline, use_container_width=True)
        
        with tab2:
            # Top users with incidents
            st.markdown("#### Top Users by Incident Count")
            
            user_counts = df["user_principal_name"].value_counts().head(10)
            
            fig_users = px.bar(
                x=user_counts.index,
                y=user_counts.values,
                title="Top 10 Users with Most Incidents",
                labels={"x": "User", "y": "Incident Count"},
                template="plotly_white"
            )
            fig_users.update_traces(marker_color="#764ba2")
            st.plotly_chart(fig_users, use_container_width=True)
            
            # User statistics table
            st.markdown("#### User Statistics")
            user_stats_df = pd.DataFrame({
                "User": user_counts.index,
                "Incident Count": user_counts.values
            })
            st.dataframe(user_stats_df, use_container_width=True, hide_index=True)
        
        with tab3:
            # Hourly distribution
            st.markdown("#### Incidents by Hour of Day")
            
            if "timestamp" in df.columns:
                hourly_data = df.groupby(df["timestamp"].dt.hour).size().reset_index()
                hourly_data.columns = ["Hour", "Count"]
                
                fig_hourly = px.bar(
                    hourly_data,
                    x="Hour",
                    y="Count",
                    title="Incident Distribution by Hour",
                    template="plotly_white"
                )
                fig_hourly.update_traces(marker_color="#48bb78")
                fig_hourly.update_layout(
                    xaxis_title="Hour of Day",
                    yaxis_title="Number of Incidents",
                    xaxis=dict(tickmode='linear', tick0=0, dtick=1)
                )
                st.plotly_chart(fig_hourly, use_container_width=True)
            
            # Daily average
            if len(df) > 0:
                days_span = (df["timestamp"].max() - df["timestamp"].min()).days + 1
                daily_avg = len(df) / max(days_span, 1)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Daily Average", f"{daily_avg:.1f}")
                with col2:
                    st.metric("Total Days", days_span)
                with col3:
                    peak_day = df.groupby(df["timestamp"].dt.date).size().max()
                    st.metric("Peak Day", peak_day)

else:
    st.info("📭 No incidents found. The system is ready to process alerts.")

# ============================================================================
# RECENT ACTIVITY FEED
# ============================================================================

st.divider()
st.subheader("🕐 Recent Activity")

if stats and stats.get("recent_incidents"):
    recent = stats["recent_incidents"]
    
    for incident in recent[:5]:
        with st.container():
            col1, col2, col3 = st.columns([3, 2, 1])
            
            with col1:
                st.markdown(f"**{incident['title']}**")
            
            with col2:
                st.text(incident['user'])
            
            with col3:
                timestamp = datetime.fromisoformat(incident['timestamp'])
                st.text(timestamp.strftime("%H:%M:%S"))
            
            st.markdown("---")
else:
    st.info("No recent activity")

# ============================================================================
# FOOTER
# ============================================================================

st.divider()

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("**DLP Remediation Engine v1.0.0**")

with col2:
    st.markdown(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

with col3:
    if auto_refresh:
        st.markdown(f"🔄 Auto-refresh: {refresh_interval}s")

# Auto-refresh logic
if auto_refresh:
    import time
    time.sleep(refresh_interval)
    st.rerun()