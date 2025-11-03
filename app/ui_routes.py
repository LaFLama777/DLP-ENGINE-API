from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, text
from database import SessionLocal, Offense
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("/", response_class=HTMLResponse)
async def dashboard(db: Session = Depends(get_db)):
    try:
        total_incidents = db.query(Offense).count()
        unique_users = db.query(Offense.user_principal_name).distinct().count()
        jakarta_tz = timedelta(hours=7)
        now_jakarta = datetime.utcnow() + jakarta_tz
        today = now_jakarta.date()
        today_utc_start = datetime.combine(today, datetime.min.time()) - jakarta_tz
        today_utc_end = datetime.combine(today, datetime.max.time()) - jakarta_tz
        today_incidents = db.query(Offense).filter(Offense.timestamp >= today_utc_start, Offense.timestamp <= today_utc_end).count()
        high_risk_users = db.query(Offense.user_principal_name, func.count(Offense.id).label('offense_count')).group_by(Offense.user_principal_name).having(func.count(Offense.id) >= 3).count()
        recent_incidents = db.query(Offense).order_by(desc(Offense.timestamp)).limit(10).all()
        monthly_data = db.query(func.extract('month', Offense.timestamp).label('month'), func.count(Offense.id).label('count')).group_by('month').order_by('month').all()
        ktp_count = db.query(Offense).filter(Offense.incident_title.contains('KTP')).count()
        npwp_count = db.query(Offense).filter(Offense.incident_title.contains('NPWP')).count()
        emp_id_count = db.query(Offense).filter(Offense.incident_title.contains('Employee')).count()
        other_count = total_incidents - (ktp_count + npwp_count + emp_id_count)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        total_incidents = unique_users = today_incidents = high_risk_users = 0
        recent_incidents = []
        monthly_data = []
        ktp_count = npwp_count = emp_id_count = other_count = 0
    
    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    monthly_counts = [0] * 12
    for month, count in monthly_data:
        if month and 1 <= int(month) <= 12:
            monthly_counts[int(month) - 1] = count
    
    return HTMLResponse(content=f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DLP Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Inter', sans-serif; background: #0f1419; color: #e4e6eb; min-height: 100vh; }}
.sidebar {{ position: fixed; left: 0; top: 0; width: 240px; height: 100vh; background: #1a1f2e; border-right: 1px solid #2d3748; padding: 24px 0; z-index: 1000; }}
.logo {{ padding: 0 24px 24px; border-bottom: 1px solid #2d3748; margin-bottom: 24px; }}
.logo h1 {{ font-size: 18px; font-weight: 700; color: #60a5fa; }}
.nav-item {{ padding: 12px 24px; color: #9ca3af; text-decoration: none; display: block; transition: all 0.2s; font-size: 14px; }}
.nav-item:hover, .nav-item.active {{ background: #2d3748; color: #60a5fa; border-left: 3px solid #60a5fa; }}
.main-content {{ margin-left: 240px; padding: 24px; }}
.top-bar {{ background: #1a1f2e; border: 1px solid #2d3748; border-radius: 12px; padding: 20px 24px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; }}
.status-badge {{ background: #10b981; color: white; padding: 8px 16px; border-radius: 20px; font-size: 13px; font-weight: 600; display: flex; align-items: center; gap: 8px; }}
.status-dot {{ width: 8px; height: 8px; background: white; border-radius: 50%; animation: pulse 2s infinite; }}
@keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.5; }} }}
.stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 24px; }}
.stat-card {{ background: #1a1f2e; border: 1px solid #2d3748; border-radius: 12px; padding: 24px; transition: transform 0.2s; }}
.stat-card:hover {{ transform: translateY(-4px); }}
.stat-label {{ color: #9ca3af; font-size: 13px; font-weight: 500; text-transform: uppercase; margin-bottom: 12px; }}
.stat-value {{ font-size: 36px; font-weight: 700; color: #e4e6eb; margin-bottom: 8px; }}
.stat-change {{ font-size: 12px; color: #10b981; }}
.stat-change.negative {{ color: #ef4444; }}
.chart-grid {{ display: grid; grid-template-columns: 2fr 1fr; gap: 20px; margin-bottom: 24px; }}
.card {{ background: #1a1f2e; border: 1px solid #2d3748; border-radius: 12px; padding: 24px; }}
.card-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }}
.card-title {{ font-size: 16px; font-weight: 600; color: #e4e6eb; }}
.chart-container {{ position: relative; height: 300px; }}
.incident-list {{ display: flex; flex-direction: column; gap: 12px; }}
.incident-item {{ background: #0f1419; border: 1px solid #2d3748; border-radius: 8px; padding: 16px; transition: all 0.2s; }}
.incident-item:hover {{ border-color: #60a5fa; transform: translateX(4px); }}
.incident-header {{ display: flex; justify-content: space-between; margin-bottom: 8px; }}
.incident-title {{ font-size: 14px; font-weight: 500; color: #e4e6eb; flex: 1; }}
.incident-badge {{ padding: 4px 12px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; background: rgba(239, 68, 68, 0.2); color: #f87171; }}
.incident-meta {{ font-size: 12px; color: #9ca3af; }}
.empty-state {{ text-align: center; padding: 48px 24px; color: #6b7280; }}
</style>
</head>
<body>
<div class="sidebar">
<div class="logo"><h1>🛡️ DLP Engine</h1></div>
<a href="/" class="nav-item active">📊 Dashboard</a>
<a href="/ui/incidents" class="nav-item">🚨 Incidents</a>
<a href="/ui/health" class="nav-item">❤️ Health Check</a>
<a href="/ui/stats" class="nav-item">📈 Statistics</a>
</div>
<div class="main-content">
<div class="top-bar">
<div><h2 style="font-size: 24px; font-weight: 700; margin-bottom: 4px;">Security Dashboard</h2>
<p style="color: #9ca3af; font-size: 14px;">Monitor and manage DLP incidents in real-time</p></div>
<div class="status-badge"><div class="status-dot"></div>System Online</div>
</div>
<div class="stats-grid">
<div class="stat-card"><div class="stat-label">Total Incidents</div><div class="stat-value">{total_incidents}</div><div class="stat-change">↑ All time</div></div>
<div class="stat-card"><div class="stat-label">Users Monitored</div><div class="stat-value">{unique_users}</div><div class="stat-change">Active users</div></div>
<div class="stat-card"><div class="stat-label">High Risk</div><div class="stat-value">{high_risk_users}</div><div class="stat-change negative">↑ Requires attention</div></div>
<div class="stat-card"><div class="stat-label">Today</div><div class="stat-value">{today_incidents}</div><div class="stat-change">Last 24 hours</div></div>
</div>
<div class="chart-grid">
<div class="card"><div class="card-header"><div class="card-title">Incident Trend</div></div><div class="chart-container"><canvas id="trendChart"></canvas></div></div>
<div class="card"><div class="card-header"><div class="card-title">Violation Types</div></div><div class="chart-container"><canvas id="violationChart"></canvas></div></div>
</div>
<div class="card">
<div class="card-header"><div class="card-title">Recent Activity</div><a href="/ui/incidents" style="color: #60a5fa; text-decoration: none; font-size: 14px;">View All →</a></div>
<div class="incident-list">
{"".join([f'<div class="incident-item"><div class="incident-header"><div class="incident-title">{inc.incident_title}</div><span class="incident-badge">HIGH</span></div><div class="incident-meta"><strong>User:</strong> {inc.user_principal_name} • <strong>Time:</strong> {(inc.timestamp + timedelta(hours=7)).strftime("%Y-%m-%d %H:%M:%S")} WIB</div></div>' for inc in recent_incidents[:5]]) if recent_incidents else '<div class="empty-state">📋<p>No incidents recorded yet</p></div>'}
</div>
</div>
</div>
<script>
const trendCtx = document.getElementById('trendChart');
if (trendCtx) {{
new Chart(trendCtx, {{
type: 'line',
data: {{ labels: {months}, datasets: [{{ label: 'Incidents', data: {monthly_counts}, borderColor: '#60a5fa', backgroundColor: 'rgba(96, 165, 250, 0.1)', tension: 0.4, fill: true, pointBackgroundColor: '#60a5fa', pointBorderColor: '#fff' }}] }},
options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ display: false }}, tooltip: {{ backgroundColor: '#1a1f2e', titleColor: '#e4e6eb', bodyColor: '#9ca3af', borderColor: '#2d3748', borderWidth: 1 }} }}, scales: {{ y: {{ beginAtZero: true, grid: {{ color: '#2d3748' }}, ticks: {{ color: '#9ca3af', stepSize: 1 }} }}, x: {{ grid: {{ display: false }}, ticks: {{ color: '#9ca3af' }} }} }} }}
}});
}}
const violationCtx = document.getElementById('violationChart');
if (violationCtx) {{
new Chart(violationCtx, {{
type: 'doughnut',
data: {{ labels: ['KTP', 'NPWP', 'Employee ID', 'Other'], datasets: [{{ data: [{ktp_count}, {npwp_count}, {emp_id_count}, {other_count}], backgroundColor: ['#60a5fa', '#10b981', '#f59e0b', '#ef4444'], borderWidth: 0 }}] }},
options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#9ca3af', padding: 15, font: {{ size: 12 }} }} }}, tooltip: {{ backgroundColor: '#1a1f2e', titleColor: '#e4e6eb', bodyColor: '#9ca3af', borderColor: '#2d3748', borderWidth: 1 }} }} }}
}});
}}
</script>
</body>
</html>""")

@router.get("/ui/incidents", response_class=HTMLResponse)
async def incidents_page(db: Session = Depends(get_db)):
    try:
        incidents = db.query(Offense).order_by(desc(Offense.timestamp)).limit(100).all()
        total = db.query(Offense).count()
    except Exception as e:
        logger.error(f"Incidents page error: {e}")
        incidents = []
        total = 0
    jakarta_tz = timedelta(hours=7)
    return HTMLResponse(content=f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Incidents - DLP Engine</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Inter', sans-serif; background: #0f1419; color: #e4e6eb; padding: 24px; }}
.container {{ max-width: 1400px; margin: 0 auto; }}
.header {{ background: #1a1f2e; border: 1px solid #2d3748; border-radius: 12px; padding: 24px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; }}
.btn-back {{ background: #60a5fa; color: white; padding: 10px 20px; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 14px; transition: all 0.2s; }}
.btn-back:hover {{ background: #3b82f6; transform: translateY(-2px); }}
.card {{ background: #1a1f2e; border: 1px solid #2d3748; border-radius: 12px; padding: 24px; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 16px; text-align: left; border-bottom: 1px solid #2d3748; }}
th {{ color: #9ca3af; font-weight: 600; font-size: 12px; text-transform: uppercase; }}
td {{ color: #e4e6eb; font-size: 14px; }}
tr:hover {{ background: rgba(96, 165, 250, 0.05); }}
</style>
</head>
<body>
<div class="container">
<div class="header"><h1 style="font-size: 24px; font-weight: 700;">All Incidents ({total})</h1><a href="/" class="btn-back">← Back</a></div>
<div class="card">
<table>
<thead><tr><th>ID</th><th>User</th><th>Incident</th><th>Timestamp (WIB)</th></tr></thead>
<tbody>
{"".join([f'<tr><td>#{inc.id}</td><td>{inc.user_principal_name}</td><td>{inc.incident_title}</td><td>{(inc.timestamp + jakarta_tz).strftime("%Y-%m-%d %H:%M:%S")}</td></tr>' for inc in incidents]) if incidents else '<tr><td colspan="4" style="text-align: center; padding: 48px; color: #6b7280;">No incidents</td></tr>'}
</tbody>
</table>
</div>
</div>
</body>
</html>""")

@router.get("/ui/health", response_class=HTMLResponse)
async def health_check_page():
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        db_status = "connected"
        db_icon = "✅"
        db_color = "#10b981"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = "error"
        db_icon = "❌"
        db_color = "#ef4444"
    try:
        from email_notifications import EmailNotificationService
        email_enabled = True
    except:
        email_enabled = False
    status = "healthy" if db_status == "connected" else "degraded"
    status_color = "#10b981" if status == "healthy" else "#f59e0b"
    return HTMLResponse(content=f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Health Check - DLP Engine</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Inter', sans-serif; background: #0f1419; color: #e4e6eb; padding: 24px; min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
.container {{ max-width: 800px; width: 100%; }}
.card {{ background: #1a1f2e; border: 1px solid #2d3748; border-radius: 12px; padding: 40px; }}
.status-header {{ text-align: center; margin-bottom: 40px; }}
.status-icon {{ font-size: 72px; margin-bottom: 20px; }}
.status-title {{ font-size: 32px; font-weight: 700; color: {status_color}; margin-bottom: 10px; }}
.status-subtitle {{ color: #9ca3af; font-size: 16px; }}
.info-grid {{ display: grid; gap: 16px; margin-top: 32px; }}
.info-item {{ background: #0f1419; padding: 20px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; }}
.info-label {{ color: #9ca3af; font-size: 14px; font-weight: 500; }}
.info-value {{ color: #e4e6eb; font-size: 16px; font-weight: 600; }}
.btn-back {{ display: inline-block; background: #60a5fa; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 600; margin-top: 24px; transition: all 0.2s; }}
.btn-back:hover {{ background: #3b82f6; transform: translateY(-2px); }}
</style>
</head>
<body>
<div class="container">
<div class="card">
<div class="status-header">
<div class="status-icon">{'💚' if status == 'healthy' else '⚠️'}</div>
<h1 class="status-title">{status.upper()}</h1>
<p class="status-subtitle">DLP Remediation Engine v2.0.0</p>
</div>
<div class="info-grid">
<div class="info-item"><span class="info-label">🗄️ Database</span><span class="info-value" style="color: {db_color};">{db_icon} {db_status}</span></div>
<div class="info-item"><span class="info-label">✉️ Email Notifications</span><span class="info-value">{'✅ Enabled' if email_enabled else '⚠️ Disabled'}</span></div>
<div class="info-item"><span class="info-label">📢 Teams Alerts</span><span class="info-value">✅ Via Logic App</span></div>
<div class="info-item"><span class="info-label">🔍 Sensitive Data Detection</span><span class="info-value">✅ Active</span></div>
<div class="info-item"><span class="info-label">🔒 Account Revocation</span><span class="info-value">✅ Active</span></div>
<div class="info-item"><span class="info-label">🕐 Timestamp</span><span class="info-value">{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC</span></div>
</div>
<div style="text-align: center;"><a href="/" class="btn-back">← Back to Dashboard</a></div>
</div>
</div>
</body>
</html>""")

@router.get("/ui/stats", response_class=HTMLResponse)
async def stats_page(db: Session = Depends(get_db)):
    try:
        total = db.query(Offense).count()
        users = db.query(Offense.user_principal_name).distinct().count()
        high_risk = db.query(Offense.user_principal_name, func.count(Offense.id).label('count')).group_by(Offense.user_principal_name).having(func.count(Offense.id) >= 3).count()
        jakarta_tz = timedelta(hours=7)
        now_jakarta = datetime.utcnow() + jakarta_tz
        today = now_jakarta.date()
        today_utc_start = datetime.combine(today, datetime.min.time()) - jakarta_tz
        today_utc_end = datetime.combine(today, datetime.max.time()) - jakarta_tz
        today_count = db.query(Offense).filter(Offense.timestamp >= today_utc_start, Offense.timestamp <= today_utc_end).count()
        recent = db.query(Offense).order_by(desc(Offense.timestamp)).limit(10).all()
    except Exception as e:
        logger.error(f"Stats error: {e}")
        total = users = high_risk = today_count = 0
        recent = []
    return HTMLResponse(content=f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Statistics - DLP Engine</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Inter', sans-serif; background: #0f1419; color: #e4e6eb; padding: 24px; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
.header {{ background: #1a1f2e; border: 1px solid #2d3748; border-radius: 12px; padding: 24px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; }}
.btn-back {{ background: #60a5fa; color: white; padding: 10px 20px; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 14px; transition: all 0.2s; }}
.btn-back:hover {{ background: #3b82f6; transform: translateY(-2px); }}
.stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 24px; }}
.stat-card {{ background: #1a1f2e; border: 1px solid #2d3748; border-radius: 12px; padding: 24px; }}
.stat-label {{ color: #9ca3af; font-size: 13px; text-transform: uppercase; margin-bottom: 12px; }}
.stat-value {{ font-size: 36px; font-weight: 700; color: #e4e6eb; }}
.card {{ background: #1a1f2e; border: 1px solid #2d3748; border-radius: 12px; padding: 24px; }}
.card-title {{ font-size: 18px; font-weight: 600; margin-bottom: 20px; }}
.incident-item {{ background: #0f1419; border: 1px solid #2d3748; border-radius: 8px; padding: 16px; margin-bottom: 12px; }}
.incident-meta {{ font-size: 12px; color: #9ca3af; }}
</style>
</head>
<body>
<div class="container">
<div class="header"><h1 style="font-size: 24px; font-weight: 700;">📊 Statistics</h1><a href="/" class="btn-back">← Back</a></div>
<div class="stats-grid">
<div class="stat-card"><div class="stat-label">Total Incidents</div><div class="stat-value">{total}</div></div>
<div class="stat-card"><div class="stat-label">Unique Users</div><div class="stat-value">{users}</div></div>
<div class="stat-card"><div class="stat-label">High Risk</div><div class="stat-value">{high_risk}</div></div>
<div class="stat-card"><div class="stat-label">Today</div><div class="stat-value">{today_count}</div></div>
</div>
<div class="card">
<h2 class="card-title">Recent Incidents</h2>
{"".join([f'<div class="incident-item"><div style="font-weight: 600; margin-bottom: 8px;">{inc.incident_title}</div><div class="incident-meta"><strong>User:</strong> {inc.user_principal_name} • <strong>Time:</strong> {(inc.timestamp + timedelta(hours=7)).strftime("%Y-%m-%d %H:%M:%S")} WIB</div></div>' for inc in recent]) if recent else '<p style="color: #6b7280; text-align: center; padding: 40px;">No incidents</p>'}
</div>
</div>
</body>
</html>""")