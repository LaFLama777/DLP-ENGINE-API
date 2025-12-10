from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query
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


# Shared HTML template components
def get_base_html_head(title: str) -> str:
    """Return common HTML head with styling"""
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{title} - DLP Engine</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ 
                font-family: 'Inter', sans-serif; 
                background: #000000; 
                color: #e4e6eb; 
                min-height: 100vh;
            }}
            .sidebar {{
                position: fixed;
                left: 0;
                top: 0;
                width: 240px;
                height: 100vh;
                background: #111111;
                border-right: 1px solid rgba(255, 255, 255, 0.1);
                padding: 24px 0;
                z-index: 1000;
            }}
            .logo {{
                padding: 0 24px 24px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
                margin-bottom: 24px;
            }}
            .logo h1 {{
                font-size: 18px;
                font-weight: 700;
                color: #60a5fa;
            }}
            .nav-item {{
                padding: 12px 24px;
                color: #9ca3af;
                text-decoration: none;
                display: block;
                transition: all 0.2s;
                font-size: 14px;
            }}
            .nav-item:hover, .nav-item.active {{
                background: rgba(255, 255, 255, 0.1);
                color: #60a5fa;
                border-left: 3px solid #60a5fa;
            }}
            .main-content {{
                margin-left: 240px;
                padding: 24px;
                min-height: 100vh;
            }}
            .top-bar {{
                background: #111111;
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 20px 24px;
                margin-bottom: 24px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            .status-badge {{
                background: #10b981;
                color: white;
                padding: 8px 16px;
                border-radius: 20px;
                font-size: 13px;
                font-weight: 600;
                display: flex;
                align-items: center;
                gap: 8px;
            }}
            .status-dot {{
                width: 8px;
                height: 8px;
                background: white;
                border-radius: 50%;
                animation: pulse 2s infinite;
            }}
            @keyframes pulse {{
                0%, 100% {{ opacity: 1; }}
                50% {{ opacity: 0.5; }}
            }}
            .btn-back {{
                background: #60a5fa;
                color: white;
                padding: 10px 20px;
                border-radius: 8px;
                text-decoration: none;
                font-weight: 600;
                font-size: 14px;
                transition: all 0.2s;
                display: inline-block;
            }}
            .btn-back:hover {{
                background: #3b82f6;
                transform: translateY(-2px);
            }}
            .card {{
                background: #111111;
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 24px;
            }}
            .card-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
            }}
            .card-title {{
                font-size: 16px;
                font-weight: 600;
                color: #e4e6eb;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
            }}
            th, td {{
                padding: 16px;
                text-align: left;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            }}
            th {{
                color: #9ca3af;
                font-weight: 600;
                font-size: 12px;
                text-transform: uppercase;
            }}
            td {{
                color: #e4e6eb;
                font-size: 14px;
            }}
            tr:hover {{
                background: rgba(96, 165, 250, 0.05);
            }}
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 20px;
                margin-bottom: 24px;
            }}
            .stat-card {{
                background: #111111;
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 24px;
                transition: transform 0.2s;
            }}
            .stat-card:hover {{
                transform: translateY(-4px);
            }}
            .stat-label {{
                color: #9ca3af;
                font-size: 13px;
                font-weight: 500;
                text-transform: uppercase;
                margin-bottom: 12px;
            }}
            .stat-value {{
                font-size: 36px;
                font-weight: 700;
                color: #e4e6eb;
                margin-bottom: 8px;
            }}
            .stat-change {{
                font-size: 12px;
                color: #10b981;
            }}
            .stat-change.negative {{
                color: #ef4444;
            }}
            .empty-state {{
                text-align: center;
                padding: 48px 24px;
                color: #6b7280;
            }}
            .pagination {{
                display: flex;
                gap: 10px;
                justify-content: center;
                margin-top: 20px;
            }}
            .pagination a {{
                padding: 8px 16px;
                background: rgba(255, 255, 255, 0.1);
                color: #e4e6eb;
                text-decoration: none;
                border-radius: 6px;
                transition: all 0.2s;
            }}
            .pagination a:hover {{
                background: #60a5fa;
            }}
            .pagination a.active {{
                background: #60a5fa;
            }}
            .filter-bar {{
                background: #111111;
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 20px;
                margin-bottom: 24px;
                display: flex;
                gap: 15px;
                align-items: center;
            }}
            .filter-bar input, .filter-bar select {{
                background: #000000;
                border: 1px solid rgba(255, 255, 255, 0.1);
                color: #e4e6eb;
                padding: 10px 15px;
                border-radius: 8px;
                font-size: 14px;
            }}
            .filter-bar input::placeholder {{
                color: #6b7280;
            }}
        </style>
    </head>
    """


@router.get("/", response_class=HTMLResponse)
async def dashboard(db: Session = Depends(get_db)):
    """Main dashboard with statistics and charts"""
    try:
        total_incidents = db.query(Offense).count()
        unique_users = db.query(Offense.user_principal_name).distinct().count()
        
        # Today's incidents (Jakarta timezone)
        jakarta_tz = timedelta(hours=7)
        now_jakarta = datetime.utcnow() + jakarta_tz
        today = now_jakarta.date()
        today_utc_start = datetime.combine(today, datetime.min.time()) - jakarta_tz
        today_utc_end = datetime.combine(today, datetime.max.time()) - jakarta_tz
        today_incidents = db.query(Offense).filter(
            Offense.timestamp >= today_utc_start,
            Offense.timestamp <= today_utc_end
        ).count()
        
        # High risk users (>=3 violations)
        high_risk_users = db.query(
            Offense.user_principal_name,
            func.count(Offense.id).label('offense_count')
        ).group_by(Offense.user_principal_name).having(
            func.count(Offense.id) >= 3
        ).count()
        
        # Recent incidents
        recent_incidents = db.query(Offense).order_by(
            desc(Offense.timestamp)
        ).limit(10).all()
        
        # Monthly data for chart
        monthly_data = db.query(
            func.extract('month', Offense.timestamp).label('month'),
            func.count(Offense.id).label('count')
        ).group_by('month').order_by('month').all()
        
        # Violation type counts
        ktp_count = db.query(Offense).filter(
            Offense.incident_title.contains('KTP')
        ).count()
        npwp_count = db.query(Offense).filter(
            Offense.incident_title.contains('NPWP')
        ).count()
        emp_id_count = db.query(Offense).filter(
            Offense.incident_title.contains('Employee')
        ).count()
        other_count = total_incidents - (ktp_count + npwp_count + emp_id_count)
        
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        total_incidents = unique_users = today_incidents = high_risk_users = 0
        recent_incidents = []
        monthly_data = []
        ktp_count = npwp_count = emp_id_count = other_count = 0
    
    # Prepare monthly chart data
    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    monthly_counts = [0] * 12
    for month, count in monthly_data:
        if month and 1 <= int(month) <= 12:
            monthly_counts[int(month) - 1] = count
    
    # Build recent incidents HTML
    recent_html = ""
    if recent_incidents:
        for inc in recent_incidents[:5]:
            timestamp_wib = (inc.timestamp + timedelta(hours=7)).strftime("%Y-%m-%d %H:%M:%S")
            recent_html += f'''
            <div style="background: #000000; border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px; padding: 16px; margin-bottom: 12px; transition: all 0.2s;" onmouseover="this.style.borderColor='#60a5fa'; this.style.transform='translateX(4px)'" onmouseout="this.style.borderColor='rgba(255, 255, 255, 0.1)'; this.style.transform='translateX(0)'">
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <div style="font-size: 14px; font-weight: 500; color: #e4e6eb; flex: 1;">{inc.incident_title}</div>
                    <span style="padding: 4px 12px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; background: rgba(239, 68, 68, 0.2); color: #f87171;">HIGH</span>
                </div>
                <div style="font-size: 12px; color: #9ca3af;">
                    <strong>User:</strong> {inc.user_principal_name} • <strong>Time:</strong> {timestamp_wib} WIB
                </div>
            </div>
            '''
    else:
        recent_html = '<div class="empty-state"><p>No incidents recorded yet</p></div>'
    
    html = get_base_html_head("Dashboard")
    html += f"""
    <body>
        <div class="sidebar">
            <div class="logo"><h1>DLP Engine</h1></div>
            <a href="/" class="nav-item active">Dashboard</a>
            <a href="/ui/incidents" class="nav-item">Incidents</a>
            <a href="/ui/users" class="nav-item">Users</a>
            <a href="/ui/health" class="nav-item">Health Check</a>
            <a href="/ui/stats" class="nav-item">Statistics</a>
        </div>
        
        <div class="main-content">
            <div class="top-bar">
                <div>
                    <h2 style="font-size: 24px; font-weight: 700; margin-bottom: 4px;">Security Dashboard</h2>
                    <p style="color: #9ca3af; font-size: 14px;">Monitor and manage DLP incidents in real-time</p>
                </div>
                <div class="status-badge">
                    <div class="status-dot"></div>
                    System Online
                </div>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Total Incidents</div>
                    <div class="stat-value">{total_incidents}</div>
                    <div class="stat-change">↑ All time</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Users Monitored</div>
                    <div class="stat-value">{unique_users}</div>
                    <div class="stat-change">Active users</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">High Risk</div>
                    <div class="stat-value">{high_risk_users}</div>
                    <div class="stat-change negative">↑ Requires attention</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Today</div>
                    <div class="stat-value">{today_incidents}</div>
                    <div class="stat-change">Last 24 hours</div>
                </div>
            </div>
            
            <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 20px; margin-bottom: 24px;">
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">Incident Trend</div>
                    </div>
                    <div style="position: relative; height: 300px;">
                        <canvas id="trendChart"></canvas>
                    </div>
                </div>
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">Violation Types</div>
                    </div>
                    <div style="position: relative; height: 300px;">
                        <canvas id="violationChart"></canvas>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Recent Activity</div>
                    <a href="/ui/incidents" style="color: #60a5fa; text-decoration: none; font-size: 14px;">View All →</a>
                </div>
                {recent_html}
            </div>
        </div>
        
        <script>
            const trendCtx = document.getElementById('trendChart');
            if (trendCtx) {{
                new Chart(trendCtx, {{
                    type: 'line',
                    data: {{
                        labels: {months},
                        datasets: [{{
                            label: 'Incidents',
                            data: {monthly_counts},
                            borderColor: '#60a5fa',
                            backgroundColor: 'rgba(96, 165, 250, 0.1)',
                            tension: 0.4,
                            fill: true,
                            pointBackgroundColor: '#60a5fa',
                            pointBorderColor: '#fff'
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{
                            legend: {{ display: false }},
                            tooltip: {{
                                backgroundColor: '#111111',
                                titleColor: '#e4e6eb',
                                bodyColor: '#9ca3af',
                                borderColor: 'rgba(255, 255, 255, 0.1)',
                                borderWidth: 1
                            }}
                        }},
                        scales: {{
                            y: {{
                                beginAtZero: true,
                                grid: {{ color: 'rgba(255, 255, 255, 0.1)' }},
                                ticks: {{ color: '#9ca3af', stepSize: 1 }}
                            }},
                            x: {{
                                grid: {{ display: false }},
                                ticks: {{ color: '#9ca3af' }}
                            }}
                        }}
                    }}
                }});
            }}
            
            const violationCtx = document.getElementById('violationChart');
            if (violationCtx) {{
                new Chart(violationCtx, {{
                    type: 'doughnut',
                    data: {{
                        labels: ['KTP', 'NPWP', 'Employee ID', 'Other'],
                        datasets: [{{
                            data: [{ktp_count}, {npwp_count}, {emp_id_count}, {other_count}],
                            backgroundColor: ['#60a5fa', '#10b981', '#f59e0b', '#ef4444'],
                            borderWidth: 0
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{
                            legend: {{
                                position: 'bottom',
                                labels: {{
                                    color: '#9ca3af',
                                    padding: 15,
                                    font: {{ size: 12 }}
                                }}
                            }},
                            tooltip: {{
                                backgroundColor: '#111111',
                                titleColor: '#e4e6eb',
                                bodyColor: '#9ca3af',
                                borderColor: 'rgba(255, 255, 255, 0.1)',
                                borderWidth: 1
                            }}
                        }}
                    }}
                }});
            }}
        </script>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html)


@router.get("/ui/incidents", response_class=HTMLResponse)
async def incidents_page(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=10, le=100),
    search: str = Query(None)
):
    """Incidents page with pagination and search"""
    try:
        # Base query
        query = db.query(Offense)
        
        # Apply search filter
        if search:
            query = query.filter(
                (Offense.user_principal_name.contains(search)) |
                (Offense.incident_title.contains(search))
            )
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * per_page
        incidents = query.order_by(desc(Offense.timestamp)).limit(per_page).offset(offset).all()
        
        # Calculate pagination
        total_pages = (total + per_page - 1) // per_page
        
    except Exception as e:
        logger.error(f"Incidents page error: {e}")
        incidents = []
        total = 0
        total_pages = 1
    
    jakarta_tz = timedelta(hours=7)
    
    # Build table rows
    rows_html = ""
    if incidents:
        for inc in incidents:
            timestamp_wib = (inc.timestamp + jakarta_tz).strftime("%Y-%m-%d %H:%M:%S")
            rows_html += f'''
            <tr>
                <td>#{inc.id}</td>
                <td>{inc.user_principal_name}</td>
                <td>{inc.incident_title}</td>
                <td>{timestamp_wib}</td>
            </tr>
            '''
    else:
        rows_html = '<tr><td colspan="4" style="text-align: center; padding: 48px; color: #6b7280;">No incidents found</td></tr>'
    
    # Build pagination
    pagination_html = ""
    if total_pages > 1:
        pagination_html = '<div class="pagination">'
        if page > 1:
            pagination_html += f'<a href="/ui/incidents?page={page-1}&per_page={per_page}{f"&search={search}" if search else ""}">← Previous</a>'
        
        for p in range(max(1, page-2), min(total_pages+1, page+3)):
            active = ' class="active"' if p == page else ''
            pagination_html += f'<a href="/ui/incidents?page={p}&per_page={per_page}{f"&search={search}" if search else ""}"{active}>{p}</a>'
        
        if page < total_pages:
            pagination_html += f'<a href="/ui/incidents?page={page+1}&per_page={per_page}{f"&search={search}" if search else ""}">Next →</a>'
        pagination_html += '</div>'
    
    html = get_base_html_head("Incidents")
    html += f"""
    <body>
        <div class="sidebar">
            <div class="logo"><h1>DLP Engine</h1></div>
            <a href="/" class="nav-item">Dashboard</a>
            <a href="/ui/incidents" class="nav-item active">Incidents</a>
            <a href="/ui/users" class="nav-item">Users</a>
            <a href="/ui/health" class="nav-item">Health Check</a>
            <a href="/ui/stats" class="nav-item">Statistics</a>
        </div>
        
        <div class="main-content">
            <div class="top-bar">
                <h1 style="font-size: 24px; font-weight: 700;">All Incidents ({total})</h1>
                <a href="/" class="btn-back">← Back to Dashboard</a>
            </div>
            
            <div class="filter-bar">
                <input type="text" placeholder="Search by user or incident..." value="{search or ''}" 
                       onkeypress="if(event.key==='Enter') window.location.href='/ui/incidents?search='+this.value" 
                       style="flex: 1;">
                <select onchange="window.location.href='/ui/incidents?per_page='+this.value{f'&search={search}' if search else ''}'" 
                        style="width: 150px;">
                    <option value="25" {'selected' if per_page==25 else ''}>25 per page</option>
                    <option value="50" {'selected' if per_page==50 else ''}>50 per page</option>
                    <option value="100" {'selected' if per_page==100 else ''}>100 per page</option>
                </select>
            </div>
            
            <div class="card">
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>User</th>
                            <th>Incident</th>
                            <th>Timestamp (WIB)</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows_html}
                    </tbody>
                </table>
                {pagination_html}
            </div>
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html)


@router.get("/ui/users", response_class=HTMLResponse)
async def users_page(db: Session = Depends(get_db)):
    """Users page showing violation counts per user"""
    try:
        # Get user statistics
        user_stats = db.query(
            Offense.user_principal_name,
            func.count(Offense.id).label('violation_count'),
            func.max(Offense.timestamp).label('last_violation')
        ).group_by(Offense.user_principal_name).order_by(
            desc('violation_count')
        ).all()
        
    except Exception as e:
        logger.error(f"Users page error: {e}")
        user_stats = []
    
    jakarta_tz = timedelta(hours=7)
    
    # Build user rows
    rows_html = ""
    if user_stats:
        for stat in user_stats:
            risk_level = "Critical" if stat.violation_count >= 3 else ("High" if stat.violation_count >= 2 else "Low")
            risk_color = "#ef4444" if stat.violation_count >= 3 else ("#ffc107" if stat.violation_count >= 2 else "#10b981")
            last_violation_wib = (stat.last_violation + jakarta_tz).strftime("%Y-%m-%d %H:%M:%S")
            
            rows_html += f'''
            <tr>
                <td>{stat.user_principal_name}</td>
                <td style="font-size: 20px; font-weight: 700; color: {risk_color};">{stat.violation_count}</td>
                <td><span style="color: {risk_color}; font-weight: 600;">{risk_level}</span></td>
                <td>{last_violation_wib}</td>
            </tr>
            '''
    else:
        rows_html = '<tr><td colspan="4" style="text-align: center; padding: 48px; color: #6b7280;">No users found</td></tr>'
    
    html = get_base_html_head("Users")
    html += f"""
    <body>
        <div class="sidebar">
            <div class="logo"><h1>DLP Engine</h1></div>
            <a href="/" class="nav-item">Dashboard</a>
            <a href="/ui/incidents" class="nav-item">Incidents</a>
            <a href="/ui/users" class="nav-item active">Users</a>
            <a href="/ui/health" class="nav-item">Health Check</a>
            <a href="/ui/stats" class="nav-item">Statistics</a>
        </div>
        
        <div class="main-content">
            <div class="top-bar">
                <h1 style="font-size: 24px; font-weight: 700;">User Violations</h1>
                <a href="/" class="btn-back">← Back to Dashboard</a>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Users Ranked by Violation Count</div>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>User</th>
                            <th>Violations</th>
                            <th>Risk Level</th>
                            <th>Last Violation (WIB)</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows_html}
                    </tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html)


@router.get("/ui/health", response_class=HTMLResponse)
async def health_check_page():
    """Health check page"""
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
        from email_notifications import GraphEmailNotificationService
        email_enabled = True
    except:
        email_enabled = False
    
    status = "healthy" if db_status == "connected" else "degraded"
    status_color = "#10b981" if status == "healthy" else "#f59e0b"
    
    html = get_base_html_head("Health Check")
    html += f"""
    <body>
        <div class="sidebar">
            <div class="logo"><h1>DLP Engine</h1></div>
            <a href="/" class="nav-item">Dashboard</a>
            <a href="/ui/incidents" class="nav-item">Incidents</a>
            <a href="/ui/users" class="nav-item">Users</a>
            <a href="/ui/health" class="nav-item active">❤️ Health Check</a>
            <a href="/ui/stats" class="nav-item">Statistics</a>
        </div>
        
        <div class="main-content" style="display: flex; align-items: center; justify-content: center;">
            <div class="card" style="max-width: 800px; width: 100%;">
                <div style="text-align: center; margin-bottom: 40px;">
                    <div style="font-size: 72px; margin-bottom: 20px;">{'' if status == 'healthy' else ''}</div>
                    <h1 style="font-size: 32px; font-weight: 700; color: {status_color}; margin-bottom: 10px;">{status.upper()}</h1>
                    <p style="color: #9ca3af; font-size: 16px;">DLP Remediation Engine v2.0.0</p>
                </div>
                
                <div style="display: grid; gap: 16px;">
                    <div style="background: #000000; padding: 20px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center;">
                        <span style="color: #9ca3af; font-size: 14px; font-weight: 500;">Database</span>
                        <span style="color: {db_color}; font-size: 16px; font-weight: 600;">{db_icon} {db_status}</span>
                    </div>
                    <div style="background: #000000; padding: 20px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center;">
                        <span style="color: #9ca3af; font-size: 14px; font-weight: 500;">Email Notifications</span>
                        <span style="font-size: 16px; font-weight: 600;">{'Enabled' if email_enabled else 'Disabled'}</span>
                    </div>
                    <div style="background: #000000; padding: 20px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center;">
                        <span style="color: #9ca3af; font-size: 14px; font-weight: 500;">Teams Alerts</span>
                        <span style="font-size: 16px; font-weight: 600;">Via Logic App</span>
                    </div>
                    <div style="background: #000000; padding: 20px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center;">
                        <span style="color: #9ca3af; font-size: 14px; font-weight: 500;">Sensitive Data Detection</span>
                        <span style="font-size: 16px; font-weight: 600;">Active</span>
                    </div>
                    <div style="background: #000000; padding: 20px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center;">
                        <span style="color: #9ca3af; font-size: 14px; font-weight: 500;">Account Revocation</span>
                        <span style="font-size: 16px; font-weight: 600;">Active</span>
                    </div>
                    <div style="background: #000000; padding: 20px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center;">
                        <span style="color: #9ca3af; font-size: 14px; font-weight: 500;">🕐 Timestamp</span>
                        <span style="font-size: 16px; font-weight: 600;">{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC</span>
                    </div>
                </div>
                
                <div style="text-align: center; margin-top: 30px;">
                    <a href="/" class="btn-back">← Back to Dashboard</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html)


@router.get("/ui/stats", response_class=HTMLResponse)
async def stats_page(db: Session = Depends(get_db)):
    """Statistics page"""
    try:
        total = db.query(Offense).count()
        users = db.query(Offense.user_principal_name).distinct().count()
        high_risk = db.query(
            Offense.user_principal_name,
            func.count(Offense.id).label('count')
        ).group_by(Offense.user_principal_name).having(
            func.count(Offense.id) >= 3
        ).count()
        
        jakarta_tz = timedelta(hours=7)
        now_jakarta = datetime.utcnow() + jakarta_tz
        today = now_jakarta.date()
        today_utc_start = datetime.combine(today, datetime.min.time()) - jakarta_tz
        today_utc_end = datetime.combine(today, datetime.max.time()) - jakarta_tz
        today_count = db.query(Offense).filter(
            Offense.timestamp >= today_utc_start,
            Offense.timestamp <= today_utc_end
        ).count()
        
        recent = db.query(Offense).order_by(desc(Offense.timestamp)).limit(10).all()
    except Exception as e:
        logger.error(f"Stats error: {e}")
        total = users = high_risk = today_count = 0
        recent = []
    
    # Build recent incidents
    recent_html = ""
    if recent:
        for inc in recent:
            timestamp_wib = (inc.timestamp + timedelta(hours=7)).strftime("%Y-%m-%d %H:%M:%S")
            recent_html += f'''
            <div style="background: #000000; border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px; padding: 16px; margin-bottom: 12px;">
                <div style="font-weight: 600; margin-bottom: 8px;">{inc.incident_title}</div>
                <div style="font-size: 12px; color: #9ca3af;">
                    <strong>User:</strong> {inc.user_principal_name} • <strong>Time:</strong> {timestamp_wib} WIB
                </div>
            </div>
            '''
    else:
        recent_html = '<p style="color: #6b7280; text-align: center; padding: 40px;">No incidents</p>'
    
    html = get_base_html_head("Statistics")
    html += f"""
    <body>
        <div class="sidebar">
            <div class="logo"><h1>DLP Engine</h1></div>
            <a href="/" class="nav-item">Dashboard</a>
            <a href="/ui/incidents" class="nav-item">Incidents</a>
            <a href="/ui/users" class="nav-item">Users</a>
            <a href="/ui/health" class="nav-item">Health Check</a>
            <a href="/ui/stats" class="nav-item active">Statistics</a>
        </div>
        
        <div class="main-content">
            <div class="top-bar">
                <h1 style="font-size: 24px; font-weight: 700;">📊 Statistics</h1>
                <a href="/" class="btn-back">← Back to Dashboard</a>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Total Incidents</div>
                    <div class="stat-value">{total}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Unique Users</div>
                    <div class="stat-value">{users}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">High Risk</div>
                    <div class="stat-value">{high_risk}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Today</div>
                    <div class="stat-value">{today_count}</div>
                </div>
            </div>
            
            <div class="card">
                <h2 style="font-size: 18px; font-weight: 600; margin-bottom: 20px;">Recent Incidents</h2>
                {recent_html}
            </div>
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html)
