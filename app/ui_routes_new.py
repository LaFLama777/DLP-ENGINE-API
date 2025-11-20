from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, text
from database import SessionLocal, Offense
from app.styles import Theme, get_css, get_base_html_head
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

def get_db():
    """Database dependency"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/", response_class=HTMLResponse)
async def dashboard_page(db: Session = Depends(get_db)):
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
            timestamp_wib = (inc.timestamp + timedelta(hours=7)).strftime("%H:%M")
            recent_html += f'''
            <div style="display: flex; align-items: center; padding: 16px 0; border-bottom: 1px solid rgba(255,255,255,0.05);">
                <div style="width: 36px; height: 36px; border-radius: 10px; background: rgba(239, 68, 68, 0.1); display: flex; align-items: center; justify-content: center; margin-right: 16px; color: {Theme.danger};">
                    &#9888;&#65039;
                </div>
                <div style="flex: 1;">
                    <div style="font-size: 14px; font-weight: 600; color: {Theme.text_primary};">{inc.incident_title}</div>
                    <div style="font-size: 12px; color: {Theme.text_secondary};">{inc.user_principal_name}</div>
                </div>
                <div style="text-align: right;">
                    <div style="font-size: 12px; font-weight: 600; color: {Theme.text_primary};">{timestamp_wib}</div>
                    <div style="font-size: 10px; color: {Theme.text_muted};">WIB</div>
                </div>
            </div>
            '''
    else:
        recent_html = '<div class="empty-state" style="text-align: center; padding: 40px; color: rgba(255,255,255,0.3);">No recent activity</div>'
    
    html = get_base_html_head("Dashboard")
    html += f"""
    <body>
        <div class="layout-container">
            {get_sidebar("dashboard")}
            
            <div class="main-content">
                <div class="top-bar">
                    <div class="breadcrumbs">
                        Pages / <span>Dashboard</span>
                    </div>
                    <div style="color: {Theme.text_primary}; font-weight: 600; font-size: 14px;">
                        Security Operations
                    </div>
                </div>
                
                <div class="stats-grid">
                    <div class="card stat-card-mini">
                        <div>
                            <div style="color: {Theme.text_secondary}; font-size: 12px; font-weight: 600; margin-bottom: 4px;">TOTAL INCIDENTS</div>
                            <div style="color: {Theme.text_primary}; font-size: 18px; font-weight: 700;">{total_incidents} <span style="color: {Theme.success}; font-size: 12px;">+12%</span></div>
                        </div>
                        <div class="stat-icon" style="background: {Theme.primary};">&#128680;</div>
                    </div>
                    <div class="card stat-card-mini">
                        <div>
                            <div style="color: {Theme.text_secondary}; font-size: 12px; font-weight: 600; margin-bottom: 4px;">USERS MONITORED</div>
                            <div style="color: {Theme.text_primary}; font-size: 18px; font-weight: 700;">{unique_users} <span style="color: {Theme.success}; font-size: 12px;">Active</span></div>
                        </div>
                        <div class="stat-icon" style="background: {Theme.info};">&#128101;</div>
                    </div>
                    <div class="card stat-card-mini">
                        <div>
                            <div style="color: {Theme.text_secondary}; font-size: 12px; font-weight: 600; margin-bottom: 4px;">HIGH RISK USERS</div>
                            <div style="color: {Theme.text_primary}; font-size: 18px; font-weight: 700;">{high_risk_users} <span style="color: {Theme.danger}; font-size: 12px;">Action Req.</span></div>
                        </div>
                        <div class="stat-icon" style="background: {Theme.danger};">&#9888;&#65039;</div>
                    </div>
                    <div class="card stat-card-mini">
                        <div>
                            <div style="color: {Theme.text_secondary}; font-size: 12px; font-weight: 600; margin-bottom: 4px;">TODAY'S INCIDENTS</div>
                            <div style="color: {Theme.text_primary}; font-size: 18px; font-weight: 700;">{today_incidents} <span style="color: {Theme.warning}; font-size: 12px;">New</span></div>
                        </div>
                        <div class="stat-icon" style="background: {Theme.warning};">&#128197;</div>
                    </div>
                </div>
                
                <div style="display: grid; grid-template-columns: 7fr 5fr; gap: 24px; margin-bottom: 24px;">
                    <div class="card">
                        <div style="margin-bottom: 24px;">
                            <h3 style="font-size: 18px; color: {Theme.text_primary}; margin-bottom: 4px;">Incident Trend</h3>
                            <p style="font-size: 14px; color: {Theme.text_secondary};"><span style="color: {Theme.success}; font-weight: 600;">(+5%)</span> increase in 2024</p>
                        </div>
                        <div class="chart-container">
                            <canvas id="trendChart"></canvas>
                        </div>
                    </div>
                    <div class="card">
                        <div style="margin-bottom: 24px;">
                            <h3 style="font-size: 18px; color: {Theme.text_primary}; margin-bottom: 4px;">Violation Types</h3>
                            <p style="font-size: 14px; color: {Theme.text_secondary};">Distribution by category</p>
                        </div>
                        <div class="chart-container" style="height: 200px;">
                            <canvas id="violationChart"></canvas>
                        </div>
                        <div style="margin-top: 24px; display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;">
                            <div style="text-align: center;">
                                <div style="color: {Theme.text_secondary}; font-size: 10px; font-weight: 600; margin-bottom: 4px;">KTP</div>
                                <div style="color: {Theme.text_primary}; font-size: 16px; font-weight: 700;">{ktp_count}</div>
                                <div style="width: 100%; height: 3px; background: rgba(255,255,255,0.1); border-radius: 2px; margin-top: 8px;">
                                    <div style="width: 60%; height: 100%; background: {Theme.primary}; border-radius: 2px;"></div>
                                </div>
                            </div>
                            <div style="text-align: center;">
                                <div style="color: {Theme.text_secondary}; font-size: 10px; font-weight: 600; margin-bottom: 4px;">NPWP</div>
                                <div style="color: {Theme.text_primary}; font-size: 16px; font-weight: 700;">{npwp_count}</div>
                                <div style="width: 100%; height: 3px; background: rgba(255,255,255,0.1); border-radius: 2px; margin-top: 8px;">
                                    <div style="width: 80%; height: 100%; background: {Theme.success}; border-radius: 2px;"></div>
                                </div>
                            </div>
                            <div style="text-align: center;">
                                <div style="color: {Theme.text_secondary}; font-size: 10px; font-weight: 600; margin-bottom: 4px;">ID</div>
                                <div style="color: {Theme.text_primary}; font-size: 16px; font-weight: 700;">{emp_id_count}</div>
                                <div style="width: 100%; height: 3px; background: rgba(255,255,255,0.1); border-radius: 2px; margin-top: 8px;">
                                    <div style="width: 40%; height: 100%; background: {Theme.warning}; border-radius: 2px;"></div>
                                </div>
                            </div>
                            <div style="text-align: center;">
                                <div style="color: {Theme.text_secondary}; font-size: 10px; font-weight: 600; margin-bottom: 4px;">OTHER</div>
                                <div style="color: {Theme.text_primary}; font-size: 16px; font-weight: 700;">{other_count}</div>
                                <div style="width: 100%; height: 3px; background: rgba(255,255,255,0.1); border-radius: 2px; margin-top: 8px;">
                                    <div style="width: 50%; height: 100%; background: {Theme.danger}; border-radius: 2px;"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
                        <div>
                            <h3 style="font-size: 18px; color: {Theme.text_primary}; margin-bottom: 4px;">Recent Incidents</h3>
                            <p style="font-size: 14px; color: {Theme.text_secondary};"><span style="color: {Theme.text_primary}; font-weight: 600;">{len(recent_incidents)} new</span> this week</p>
                        </div>
                        <a href="/ui/incidents" style="color: {Theme.primary}; font-size: 12px; font-weight: 600; text-decoration: none;">VIEW ALL</a>
                    </div>
                    <div class="table-container">
                        <div style="display: flex; flex-direction: column; gap: 0;">
                            {recent_html}
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script>
            Chart.defaults.color = '{Theme.text_muted}';
            Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.05)';
            Chart.defaults.font.family = "'Plus Jakarta Sans', sans-serif";
            
            const trendCtx = document.getElementById('trendChart');
            if (trendCtx) {{
                const ctx = trendCtx.getContext('2d');
                const gradient = ctx.createLinearGradient(0, 0, 0, 300);
                gradient.addColorStop(0, 'rgba(59, 130, 246, 0.3)');
                gradient.addColorStop(1, 'rgba(59, 130, 246, 0)');
                
                new Chart(trendCtx, {{
                    type: 'line',
                    data: {{
                        labels: {months},
                        datasets: [{{
                            label: 'Incidents',
                            data: {monthly_counts},
                            borderColor: '{Theme.primary}',
                            backgroundColor: gradient,
                            borderWidth: 3,
                            tension: 0.4,
                            fill: true,
                            pointRadius: 0,
                            pointHoverRadius: 6
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{
                            legend: {{ display: false }},
                            tooltip: {{
                                backgroundColor: '#000000',
                                title Color: '{Theme.text_primary}',
bodyColor: '{Theme.text_secondary}',
                                borderColor: '{Theme.glass_border}',
                                borderWidth: 1,
                                padding: 12,
                                displayColors: false
                            }}
                        }},
                        scales: {{
                            y: {{
                                beginAtZero: true,
                                grid: {{ color: 'rgba(255, 255, 255, 0.05)', borderDash: [5, 5] }},
                                ticks: {{ padding: 10, color: '{Theme.text_secondary}' }}
                            }},
                            x: {{
                                grid: {{ display: false }},
                                ticks: {{ padding: 10, color: '{Theme.text_secondary}' }}
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
                        labels: ['KTP', 'NPWP', 'ID', 'Other'],
                        datasets: [{{
                            data: [{ktp_count}, {npwp_count}, {emp_id_count}, {other_count}],
                            backgroundColor: ['{Theme.primary}', '{Theme.success}', '{Theme.warning}', '{Theme.danger}'],
                            borderWidth: 0
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        cutout: '70%',
                        plugins: {{
                            legend: {{ display: false }}
                        }}
                    }}
                }});
            }}
        </script>
        {get_styles()}
    </body>
    </html>
    """
    
    return HTMLResponse(content=html)


def get_sidebar(active_page=""):
    """Generate sidebar HTML"""
    pages = [
        ("dashboard", "/", "&#128202;", "Dashboard"),
        ("incidents", "/ui/incidents", "&#128680;", "Incidents"),
        ("users", "/ui/users", "&#128101;", "Users"),
        ("health", "/ui/health", "&#9889;", "Health"),
        ("stats", "/ui/stats", "&#128200;", "Statistics"),
    ]
    
    nav_items = ""
    for page_id, url, icon, label in pages:
        active_class = "active" if page_id == active_page else ""
        nav_items += f'''
        <a href="{url}" class="nav-item {active_class}">
            <div class="nav-icon">{icon}</div>
            <span>{label}</span>
        </a>
        '''
    
    return f'''
    <div class="sidebar">
        <div class="logo">
            <h1>&#128737;&#65039; DLP ENGINE</h1>
            <p>Security Operations</p>
        </div>
        {nav_items}
    </div>
    '''


def get_styles():
    """Get common styles for all pages"""
    return f"""
    <style>
        .layout-container {{
            display: flex;
            min-height: 100vh;
        }}
        .sidebar {{
            width: 280px;
            background: {Theme.gradient_card};
            backdrop-filter: blur(20px);
            border-right: 1px solid {Theme.glass_border};
            padding: 32px 20px;
            display: flex;
            flex-direction: column;
        }}
        .logo {{
            margin-bottom: 40px;
        }}
        .logo h1 {{
            font-size: 18px;
            margin-bottom: 4px;
            background: {Theme.gradient_primary};
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        .logo p {{
            font-size: 11px;
            color: {Theme.text_secondary};
            margin: 0;
        }}
        .nav-item {{
            display: flex;
            align-items: center;
            padding: 12px 16px;
            margin-bottom: 8px;
            border-radius: 12px;
            color: {Theme.text_secondary};
            text-decoration: none;
            transition: all 0.3s ease;
        }}
        .nav-item:hover {{
            background: rgba(255, 255, 255, 0.05);
            color: {Theme.text_primary};
            transform: translateX(4px);
        }}
        .nav-item.active {{
            background: {Theme.gradient_primary};
            color: white;
            box-shadow: 0 8px 20px rgba(59, 130, 246, 0.3);
        }}
        .nav-icon {{
            margin-right: 12px;
            font-size: 18px;
        }}
        .main-content {{
            flex: 1;
            padding: 32px;
        }}
        .top-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 32px;
        }}
        .breadcrumbs {{
            color: {Theme.text_secondary};
            font-size: 14px;
        }}
        .breadcrumbs span {{
            color: {Theme.text_primary};
            font-weight: 600;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 24px;
            margin-bottom: 32px;
        }}
        .stat-card-mini {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .stat-icon {{
            width: 48px;
            height: 48px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
        }}
        .chart-container {{
            height: 300px;
            position: relative;
        }}
        .table-container {{
            overflow-x: auto;
        }}
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.5; }}
        }}
        @keyframes pulse-ring {{
            0% {{
                transform: scale(0.8);
                opacity: 1;
            }}
            100% {{
                transform: scale(1.2);
                opacity: 0;
            }}
        }}
        .service-card:hover {{
            transform: translateY(-4px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.3);
            border-color: rgba(255,255,255,0.2);
        }}
    </style>
    """


@router.get("/ui/health", response_class=HTMLResponse)
async def health_page():
    """Health check page - Premium Design"""
    #Database check
    try:
        db = SessionLocal()
        db_start = datetime.utcnow()
        db.execute(text("SELECT 1"))
        db_latency = int((datetime.utcnow() - db_start).total_seconds() * 1000)
        db.close()
        db_status = "Operational"
        db_status_code = "success"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = "Offline"
        db_status_code = "danger"
        db_latency = 0
    
    # Email check
    try:
        from email_notifications import GraphEmailNotificationService
        email_status = "Active"
        email_status_code = "success"
    except:
        email_status = "Inactive"
        email_status_code = "warning"
    
    # Overall system status
    system_status = "All Systems Operational" if db_status == "Operational" else "System Degraded"
    system_color = Theme.success if db_status == "Operational" else Theme.warning
    
    # Uptime (mock - you can replace with actual uptime tracking)
    uptime_days = 12
    uptime_hours = 7
    
    html = get_base_html_head("System Health")
    html += f"""
    <body>
        <div class="layout-container">
            {get_sidebar("health")}
            
            <div class="main-content">
                <div class="top-bar">
                    <div class="breadcrumbs">
                        Pages / <span>System Health</span>
                    </div>
                    <div class="status-pill" style="background: {system_color}20; color: {system_color}; padding: 8px 16px; border-radius: 20px; font-size: 12px; font-weight: 700; border: 1px solid {system_color}40;">
                        <span class="pulse-dot" style="display: inline-block; width: 8px; height: 8px; background: {system_color}; border-radius: 50%; margin-right: 8px; animation: pulse 2s infinite;"></span>
                        {system_status.upper()}
                    </div>
                </div>
                
                <!-- Hero Status Section -->
                <div class="health-hero" style="background: {Theme.gradient_card}; border: 1px solid {Theme.glass_border}; border-radius: 24px; padding: 60px; text-align: center; margin-bottom: 32px; position: relative; overflow: hidden;">
                    <div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: {Theme.gradient_glow}; opacity: 0.3;"></div>
                    <div style="position: relative; z-index: 1;">
                        <div class="status-icon" style="width: 120px; height: 120px; margin: 0 auto 24px; background: {system_color}15; border-radius: 50%; display: flex; align-items: center; justify-content: center; border: 3px solid {system_color}30; position: relative;">
                            <div class="pulse-ring" style="position: absolute; width: 100%; height: 100%; border-radius: 50%; border: 3px solid {system_color}; animation: pulse-ring 2s cubic-bezier(0.455, 0.03, 0.515, 0.955) infinite;"></div>
                            <div style="font-size: 48px;">{'&#9989;' if db_status == 'Operational' else '&#9888;&#65039;'}</div>
                        </div>
                        <h1 style="font-size: 42px; margin-bottom: 12px; font-weight: 800; background: {Theme.gradient_primary}; -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;">
                            {system_status}
                        </h1>
                        <p style="color: {Theme.text_secondary}; font-size: 16px; margin-bottom: 32px;">DLP Remediation Engine v2.0.0 | Monitoring Active</p>
                        
                        <div style="display: inline-flex; gap: 32px; background: rgba(0,0,0,0.3); padding: 20px 40px; border-radius: 16px; backdrop-filter: blur(10px);">
                            <div>
                                <div style="color: {Theme.text_muted}; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px;">Uptime</div>
                                <div style="color: {Theme.success}; font-size: 24px; font-weight: 700;">{uptime_days}d {uptime_hours}h</div>
                            </div>
                            <div style="border-left: 1px solid rgba(255,255,255,0.1);"></div>
                            <div>
                                <div style="color: {Theme.text_muted}; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px;">Response Time</div>
                                <div style="color: {Theme.primary}; font-size: 24px; font-weight: 700;">{db_latency}ms</div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Service Status Grid -->
                <h3 style="font-size: 18px; font-weight: 700; margin-bottom: 20px; color: {Theme.text_primary};">Service Status</h3>
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 24px; margin-bottom: 32px;">
                    <!-- Database Card -->
                    <div class="service-card" style="background: {Theme.gradient_card}; border: 1px solid {Theme.glass_border}; border-radius: 20px; padding: 32px; position: relative; overflow: hidden; transition: all 0.3s ease;">
                        <div style="position: absolute; top: 0; right: 0; width: 100px; height: 100px; background: {Theme.primary if db_status_code == 'success' else Theme.danger}; opacity: 0.1; border-radius: 0 20px 0 100%;"></div>
                        <div style="position: relative; z-index: 1;">
                            <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 20px;">
                                <div>
                                    <div style="font-size: 14px; color: {Theme.text_muted}; text-transform: uppercase; font-weight: 600; letter-spacing: 1px; margin-bottom: 8px;">Database</div>
                                    <div style="font-size: 28px; font-weight: 700; color: {Theme.text_primary};">PostgreSQL</div>
                                </div>
                                <div style="width: 56px; height: 56px; background: {Theme.primary if db_status_code == 'success' else Theme.danger}20; border-radius: 16px; display: flex; align-items: center; justify-content: center; font-size: 28px;">
                                    &#128190;
                                </div>
                            </div>
                            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px;">
                                <span style="display: inline-block; width: 10px; height: 10px; background: {Theme.success if db_status_code == 'success' else Theme.danger}; border-radius: 50%; box-shadow: 0 0 10px {Theme.success if db_status_code == 'success' else Theme.danger};"></span>
                                <span style="color: {Theme.success if db_status_code == 'success' else Theme.danger}; font-weight: 700; font-size: 16px;">{db_status}</span>
                            </div>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; padding-top: 16px; border-top: 1px solid rgba(255,255,255,0.05);">
                                <div>
                                    <div style="font-size: 11px; color: {Theme.text_muted}; margin-bottom: 4px;">Latency</div>
                                    <div style="font-size: 18px; font-weight: 600; color: {Theme.primary};">{db_latency}ms</div>
                                </div>
                                <div>
                                    <div style="font-size: 11px; color: {Theme.text_muted}; margin-bottom: 4px;">Provider</div>
                                    <div style="font-size: 18px; font-weight: 600; color: {Theme.text_primary};">Supabase</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Email Service Card -->
                    <div class="service-card" style="background: {Theme.gradient_card}; border: 1px solid {Theme.glass_border}; border-radius: 20px; padding: 32px; position: relative; overflow: hidden; transition: all 0.3s ease;">
                        <div style="position: absolute; top: 0; right: 0; width: 100px; height: 100px; background: {Theme.success if email_status_code == 'success' else Theme.warning}; opacity: 0.1; border-radius: 0 20px 0 100%;"></div>
                        <div style="position: relative; z-index: 1;">
                            <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 20px;">
                                <div>
                                    <div style="font-size: 14px; color: {Theme.text_muted}; text-transform: uppercase; font-weight: 600; letter-spacing: 1px; margin-bottom: 8px;">Email Service</div>
                                    <div style="font-size: 28px; font-weight: 700; color: {Theme.text_primary};">Microsoft Graph</div>
                                </div>
                                <div style="width: 56px; height: 56px; background: {Theme.success if email_status_code == 'success' else Theme.warning}20; border-radius: 16px; display: flex; align-items: center; justify-content: center; font-size: 28px;">
                                    &#128231;
                                </div>
                            </div>
                            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px;">
                                <span style="display: inline-block; width: 10px; height: 10px; background: {Theme.success if email_status_code == 'success' else Theme.warning}; border-radius: 50%; box-shadow: 0 0 10px {Theme.success if email_status_code == 'success' else Theme.warning};"></span>
                                <span style="color: {Theme.success if email_status_code == 'success' else Theme.warning}; font-weight: 700; font-size: 16px;">{email_status}</span>
                            </div>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; padding-top: 16px; border-top: 1px solid rgba(255,255,255,0.05);">
                                <div>
                                    <div style="font-size: 11px; color: {Theme.text_muted}; margin-bottom: 4px;">Notifications</div>
                                    <div style="font-size: 18px; font-weight: 600; color: {Theme.primary};">{'Enabled' if email_status_code == 'success' else 'Disabled'}</div>
                                </div>
                                <div>
                                    <div style="font-size: 11px; color: {Theme.text_muted}; margin-bottom: 4px;">Mode</div>
                                    <div style="font-size: 18px; font-weight: 600; color: {Theme.text_primary};">Cloud</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- System Information -->
                <h3 style="font-size: 18px; font-weight: 700; margin-bottom: 20px; color: {Theme.text_primary};">System Information</h3>
                <div style="background: {Theme.gradient_card}; border: 1px solid {Theme.glass_border}; border-radius: 20px; padding: 32px;">
                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 32px;">
                        <div style="text-align: center; padding: 20px; background: rgba(59, 130, 246, 0.05); border-radius: 16px; border: 1px solid rgba(59, 130, 246, 0.2);">
                            <div style="font-size: 36px; margin-bottom: 12px;">&#128336;</div>
                            <div style="font-size: 12px; color: {Theme.text_muted}; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 1px;">System Time</div>
                            <div style="font-size: 20px; font-weight: 700; color: {Theme.primary};">{datetime.utcnow().strftime("%H:%M:%S")}</div>
                            <div style="font-size: 12px; color: {Theme.text_secondary}; margin-top: 4px;">{datetime.utcnow().strftime("%Y-%m-%d")} UTC</div>
                        </div>
                        <div style="text-align: center; padding: 20px; background: rgba(16, 185, 129, 0.05); border-radius: 16px; border: 1px solid rgba(16, 185, 129, 0.2);">
                            <div style="font-size: 36px; margin-bottom: 12px;">&#128640;</div>
                            <div style="font-size: 12px; color: {Theme.text_muted}; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 1px;">Version</div>
                            <div style="font-size: 20px; font-weight: 700; color: {Theme.success};">v2.0.0</div>
                            <div style="font-size: 12px; color: {Theme.text_secondary}; margin-top: 4px;">Production Build</div>
                        </div>
                        <div style="text-align: center; padding: 20px; background: rgba(245, 158, 11, 0.05); border-radius: 16px; border: 1px solid rgba(245, 158, 11, 0.2);">
                            <div style="font-size: 36px; margin-bottom: 12px;">&#127757;</div>
                            <div style="font-size: 12px; color: {Theme.text_muted}; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 1px;">Environment</div>
                            <div style="font-size: 20px; font-weight: 700; color: {Theme.warning};">Azure Cloud</div>
                            <div style="font-size: 12px; color: {Theme.text_secondary}; margin-top: 4px;">Southeast Asia</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        {get_styles()}
    </body>
    </html>
    """
    
    return HTMLResponse(content=html)


# Continuing with other routes (stats, incidents, users) - same pattern...
