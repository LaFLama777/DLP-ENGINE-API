import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime, timedelta
import requests
from app.styles import Theme, get_css

# Page Config
st.set_page_config(
    page_title="DLP Remediation Dashboard",
    page_icon="&#128737;&#65039;",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject Custom CSS
st.markdown(get_css(), unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.markdown(f"""
        <div style="text-align: center; padding: 20px 0; border-bottom: 1px solid {Theme.glass_border}; margin-bottom: 20px;">
            <h1 style="color: {Theme.text_primary}; font-size: 20px; margin: 0; letter-spacing: 2px;">&#128737;&#65039; DLP ENGINE</h1>
            <p style="color: {Theme.text_secondary}; font-size: 10px; margin-top: 5px;">PROJECTS</p>
        </div>
    """, unsafe_allow_html=True)
    
    st.markdown(f"""
        <div style="background: linear-gradient(127.09deg, rgba(0, 117, 255, 0.94) 19.41%, rgba(0, 117, 255, 0.49) 76.65%); padding: 20px; border-radius: 16px; margin-top: 20px; color: white;">
            <div style="font-weight: bold; margin-bottom: 5px;">Need Help?</div>
            <div style="font-size: 12px; opacity: 0.8; margin-bottom: 10px;">Check our docs</div>
            <a href="#" style="background: white; color: {Theme.primary}; padding: 6px 12px; border-radius: 8px; text-decoration: none; font-size: 10px; font-weight: bold; display: inline-block;">DOCUMENTATION</a>
        </div>
    """, unsafe_allow_html=True)

# Main Content
st.markdown(f"""
    <div style="margin-bottom: 30px;">
        <h1 style="font-size: 28px; font-weight: 700; margin-bottom: 8px; background: linear-gradient(90deg, #fff, #a5b4fc); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">Dashboard</h1>
        <p style="color: {Theme.text_secondary}; font-size: 14px;">Overview of your data loss prevention status</p>
    </div>
""", unsafe_allow_html=True)

# Metric Cards
col1, col2, col3, col4 = st.columns(4)

def metric_card(label, value, change, icon, color, change_color=Theme.success, delay=""):
    return f"""
    <div class="card fade-in {delay}" style="display: flex; justify-content: space-between; align-items: center;">
        <div>
            <div style="color: {Theme.text_secondary}; font-size: 12px; font-weight: 600; margin-bottom: 4px; letter-spacing: 1px;">{label}</div>
            <div style="color: {Theme.text_primary}; font-size: 24px; font-weight: 700; text-shadow: 0 0 20px {color}40;">
                {value} <span style="color: {change_color}; font-size: 12px; margin-left: 4px; background: {change_color}15; padding: 2px 6px; border-radius: 4px;">{change}</span>
            </div>
        </div>
        <div style="width: 48px; height: 48px; background: {color}20; border: 1px solid {color}40; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 20px; color: {color}; box-shadow: 0 4px 12px {color}30;">
            {icon}
        </div>
    </div>
    """

with col1:
    st.markdown(metric_card("TOTAL INCIDENTS", "150", "+12%", "&#128680;", Theme.primary, delay="delay-1"), unsafe_allow_html=True)
with col2:
    st.markdown(metric_card("USERS MONITORED", "45", "Active", "&#128101;", Theme.info, delay="delay-2"), unsafe_allow_html=True)
with col3:
    st.markdown(metric_card("HIGH RISK USERS", "3", "Action Req.", "&#9888;&#65039;", Theme.danger, Theme.danger, delay="delay-3"), unsafe_allow_html=True)
with col4:
    st.markdown(metric_card("TODAY'S INCIDENTS", "12", "New", "&#128197;", Theme.warning, Theme.warning, delay="delay-3"), unsafe_allow_html=True)

# Charts Row
st.markdown("<div style='height: 32px'></div>", unsafe_allow_html=True)
c1, c2 = st.columns([7, 5])

with c1:
    st.markdown(f"""
    <div class="card fade-in delay-2" style="height: 100%;">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px;">
            <div>
                <h3 style="color: {Theme.text_primary}; font-size: 18px; margin-bottom: 5px;">Incident Trend</h3>
                <p style="color: {Theme.text_secondary}; font-size: 14px;">
                    <span style="color: {Theme.success}; font-weight: 600;">(+5%)</span> increase in 2024
                </p>
            </div>
            <div style="padding: 4px 12px; background: {Theme.primary}15; border: 1px solid {Theme.primary}30; border-radius: 8px; color: {Theme.primary}; font-size: 12px; font-weight: 600;">
                YEARLY VIEW
            </div>
        </div>
    """, unsafe_allow_html=True)
    
    # Plotly Chart
    df = pd.DataFrame({
        'Month': ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
        'Incidents': [30, 40, 35, 50, 49, 60, 70, 91, 125, 100, 140, 150]
    })
    
    fig = px.area(df, x='Month', y='Incidents')
    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_family="Plus Jakarta Sans",
        font_color=Theme.text_secondary,
        margin=dict(l=0, r=0, t=0, b=0),
        height=300,
        xaxis=dict(
            showgrid=False, 
            showline=False,
            tickfont=dict(size=12)
        ),
        yaxis=dict(
            showgrid=True, 
            gridcolor='rgba(255,255,255,0.05)',
            showline=False,
            zeroline=False
        ),
        hovermode="x unified"
    )
    fig.update_traces(
        line_color=Theme.primary,
        line_width=3,
        fill='tozeroy',
        fillcolor='rgba(0, 117, 255, 0.1)',
        hovertemplate='<b>%{x}</b><br>Incidents: %{y}<extra></extra>'
    )
    st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
    st.markdown("</div>", unsafe_allow_html=True)

with c2:
    st.markdown(f"""
    <div class="card fade-in delay-2" style="height: 100%;">
        <h3 style="color: {Theme.text_primary}; font-size: 18px; margin-bottom: 5px;">Violation Types</h3>
        <p style="color: {Theme.text_secondary}; font-size: 14px; margin-bottom: 20px;">
            Distribution by category
        </p>
    """, unsafe_allow_html=True)
    
    # Donut Chart
    df_bar = pd.DataFrame({
        'Type': ['KTP', 'NPWP', 'ID', 'Other'],
        'Count': [45, 30, 15, 10]
    })
    
    fig_bar = px.pie(df_bar, values='Count', names='Type', hole=0.75)
    fig_bar.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_family="Plus Jakarta Sans",
        font_color=Theme.text_secondary,
        margin=dict(l=0, r=0, t=0, b=0),
        height=220,
        showlegend=False,
        annotations=[dict(text='100%', x=0.5, y=0.5, font_size=24, font_color='white', showarrow=False)]
    )
    fig_bar.update_traces(
        textinfo='none',
        marker=dict(colors=[Theme.primary, Theme.success, Theme.warning, Theme.danger]),
        hoverinfo='label+percent+value'
    )
    st.plotly_chart(fig_bar, use_container_width=True, config={'displayModeBar': False})
    
    st.markdown(f"""
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-top: 20px;">
            <div style="text-align: center;">
                <div style="color: {Theme.text_secondary}; font-size: 10px; font-weight: bold; margin-bottom: 4px;">KTP</div>
                <div style="color: {Theme.text_primary}; font-weight: bold; font-size: 16px;">45%</div>
                <div style="width: 100%; height: 3px; background: {Theme.primary}30; border-radius: 2px; margin-top: 6px;"><div style="width: 45%; height: 100%; background: {Theme.primary}; border-radius: 2px;"></div></div>
            </div>
            <div style="text-align: center;">
                <div style="color: {Theme.text_secondary}; font-size: 10px; font-weight: bold; margin-bottom: 4px;">NPWP</div>
                <div style="color: {Theme.text_primary}; font-weight: bold; font-size: 16px;">30%</div>
                <div style="width: 100%; height: 3px; background: {Theme.success}30; border-radius: 2px; margin-top: 6px;"><div style="width: 30%; height: 100%; background: {Theme.success}; border-radius: 2px;"></div></div>
            </div>
            <div style="text-align: center;">
                <div style="color: {Theme.text_secondary}; font-size: 10px; font-weight: bold; margin-bottom: 4px;">ID</div>
                <div style="color: {Theme.text_primary}; font-weight: bold; font-size: 16px;">15%</div>
                <div style="width: 100%; height: 3px; background: {Theme.warning}30; border-radius: 2px; margin-top: 6px;"><div style="width: 15%; height: 100%; background: {Theme.warning}; border-radius: 2px;"></div></div>
            </div>
            <div style="text-align: center;">
                <div style="color: {Theme.text_secondary}; font-size: 10px; font-weight: bold; margin-bottom: 4px;">OTHER</div>
                <div style="color: {Theme.text_primary}; font-weight: bold; font-size: 16px;">10%</div>
                <div style="width: 100%; height: 3px; background: {Theme.danger}30; border-radius: 2px; margin-top: 6px;"><div style="width: 10%; height: 100%; background: {Theme.danger}; border-radius: 2px;"></div></div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

# Recent Incidents Table
st.markdown("<div style='height: 32px'></div>", unsafe_allow_html=True)
st.markdown(f"""
<div class="card fade-in delay-3">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <div>
            <h3 style="color: {Theme.text_primary}; font-size: 18px; margin-bottom: 5px;">Recent Incidents</h3>
            <p style="color: {Theme.text_secondary}; font-size: 14px;">
                <span style="color: {Theme.text_primary}; font-weight: 600;">12 new</span> today
            </p>
        </div>
        <div class="btn-glass" style="cursor: pointer;">
            VIEW ALL
        </div>
    </div>
    <table>
        <thead>
            <tr>
                <th>INCIDENT ID</th>
                <th>USER</th>
                <th>TYPE</th>
                <th>TIME</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <div style="width: 32px; height: 32px; background: {Theme.danger}20; border: 1px solid {Theme.danger}40; border-radius: 8px; display: flex; align-items: center; justify-content: center; color: {Theme.danger}; font-size: 14px;">&#9888;&#65039;</div>
                        <span style="font-weight: 600; color: {Theme.text_primary};">#INC-2024-001</span>
                    </div>
                </td>
                <td>
                    <div style="color: {Theme.text_primary}; font-weight: 500;">user.one@example.com</div>
                    <div style="color: {Theme.text_secondary}; font-size: 12px;">Engineering</div>
                </td>
                <td><span class="badge badge-danger">KTP Data Leak</span></td>
                <td><span style="color: {Theme.text_secondary}; font-weight: 500;">10:45 AM</span></td>
            </tr>
            <tr>
                <td>
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <div style="width: 32px; height: 32px; background: {Theme.warning}20; border: 1px solid {Theme.warning}40; border-radius: 8px; display: flex; align-items: center; justify-content: center; color: {Theme.warning}; font-size: 14px;">&#9888;&#65039;</div>
                        <span style="font-weight: 600; color: {Theme.text_primary};">#INC-2024-002</span>
                    </div>
                </td>
                <td>
                    <div style="color: {Theme.text_primary}; font-weight: 500;">user.two@example.com</div>
                    <div style="color: {Theme.text_secondary}; font-size: 12px;">Sales</div>
                </td>
                <td><span class="badge badge-warning">NPWP Pattern</span></td>
                <td><span style="color: {Theme.text_secondary}; font-weight: 500;">09:30 AM</span></td>
            </tr>
            <tr>
                <td>
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <div style="width: 32px; height: 32px; background: {Theme.danger}20; border: 1px solid {Theme.danger}40; border-radius: 8px; display: flex; align-items: center; justify-content: center; color: {Theme.danger}; font-size: 14px;">&#9888;&#65039;</div>
                        <span style="font-weight: 600; color: {Theme.text_primary};">#INC-2024-003</span>
                    </div>
                </td>
                <td>
                    <div style="color: {Theme.text_primary}; font-weight: 500;">user.three@example.com</div>
                    <div style="color: {Theme.text_secondary}; font-size: 12px;">Marketing</div>
                </td>
                <td><span class="badge badge-danger">Employee ID</span></td>
                <td><span style="color: {Theme.text_secondary}; font-weight: 500;">09:15 AM</span></td>
            </tr>
        </tbody>
    </table>
</div>
""", unsafe_allow_html=True)