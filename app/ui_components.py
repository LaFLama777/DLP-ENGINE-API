"""
Professional UI Components for DLP Engine

This module provides reusable UI components with professional SVG icons
and consistent styling across all pages.
"""

def get_professional_sidebar(active_page: str = "dashboard") -> str:
    """
    Get professional sidebar HTML with SVG icons

    Args:
        active_page: The currently active page ('dashboard', 'incidents', 'health', 'redoc')

    Returns:
        HTML string for the sidebar
    """
    return f'''
    <!-- Professional Collapsible Sidebar -->
    <div class="sidebar" id="sidebar">
        <div class="sidebar-header">
            <div class="sidebar-brand">
                <div class="brand-icon">D</div>
                <div class="brand-text">
                    <div class="brand-title">DLP Engine</div>
                    <div class="brand-subtitle">Enterprise</div>
                </div>
            </div>
            <div class="sidebar-toggle" onclick="toggleSidebar()">
                <svg viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <line x1="3" y1="12" x2="21" y2="12"></line>
                    <line x1="3" y1="6" x2="21" y2="6"></line>
                    <line x1="3" y1="18" x2="21" y2="18"></line>
                </svg>
            </div>
        </div>

        <nav class="sidebar-nav">
            <div class="nav-section">
                <div class="nav-section-title">Overview</div>
                <a href="/" class="nav-item {'active' if active_page == 'dashboard' else ''}">
                    <div class="nav-icon">
                        <svg viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <rect x="3" y="3" width="7" height="7"></rect>
                            <rect x="14" y="3" width="7" height="7"></rect>
                            <rect x="14" y="14" width="7" height="7"></rect>
                            <rect x="3" y="14" width="7" height="7"></rect>
                        </svg>
                    </div>
                    <span class="nav-text">Dashboard</span>
                </a>
                <a href="/incidents" class="nav-item {'active' if active_page == 'incidents' else ''}">
                    <div class="nav-icon">
                        <svg viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <circle cx="11" cy="11" r="8"></circle>
                            <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                        </svg>
                    </div>
                    <span class="nav-text">All Incidents</span>
                </a>
            </div>

            <div class="nav-section">
                <div class="nav-section-title">Monitoring</div>
                <a href="/health" class="nav-item {'active' if active_page == 'health' else ''}">
                    <div class="nav-icon">
                        <svg viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M22 12h-4l-3 9L9 3l-3 9H2"></path>
                        </svg>
                    </div>
                    <span class="nav-text">System Health</span>
                </a>
                <a href="/redoc" class="nav-item {'active' if active_page == 'redoc' else ''}">
                    <div class="nav-icon">
                        <svg viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                            <polyline points="14 2 14 8 20 8"></polyline>
                            <line x1="16" y1="13" x2="8" y2="13"></line>
                            <line x1="16" y1="17" x2="8" y2="17"></line>
                            <polyline points="10 9 9 9 8 9"></polyline>
                        </svg>
                    </div>
                    <span class="nav-text">API Documentation</span>
                </a>
            </div>

            <div class="nav-section">
                <div class="nav-section-title">Resources</div>
                <a href="https://github.com/anthropics/claude-code" target="_blank" class="nav-item">
                    <div class="nav-icon">
                        <svg viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path>
                            <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path>
                        </svg>
                    </div>
                    <span class="nav-text">Documentation</span>
                </a>
                <a href="https://portal.azure.com" target="_blank" class="nav-item">
                    <div class="nav-icon">
                        <svg viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"></path>
                        </svg>
                    </div>
                    <span class="nav-text">Azure Portal</span>
                </a>
            </div>
        </nav>
    </div>
    '''


def get_sidebar_css() -> str:
    """
    Get professional sidebar CSS

    Returns:
        CSS string for the sidebar
    """
    return '''
    /* Professional Collapsible Sidebar */
    .sidebar {
        position: fixed;
        left: 0;
        top: 0;
        width: 280px;
        height: 100vh;
        background: linear-gradient(180deg, #0f0f0f 0%, #000000 100%);
        border-right: 1px solid rgba(255, 255, 255, 0.08);
        transition: width 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        z-index: 1000;
        overflow: hidden;
    }

    .sidebar.collapsed {
        width: 64px;
    }

    .sidebar-header {
        padding: 24px 20px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        display: flex;
        align-items: center;
        justify-content: space-between;
        height: 72px;
    }

    .sidebar-brand {
        display: flex;
        align-items: center;
        gap: 12px;
        white-space: nowrap;
        overflow: hidden;
    }

    .brand-icon {
        width: 32px;
        height: 32px;
        background: linear-gradient(135deg, #ffffff 0%, #a3a3a3 100%);
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: 800;
        color: #000;
        flex-shrink: 0;
    }

    .brand-text {
        display: flex;
        flex-direction: column;
        opacity: 1;
        transition: opacity 0.2s;
    }

    .sidebar.collapsed .brand-text {
        opacity: 0;
        width: 0;
    }

    .brand-title {
        font-size: 15px;
        font-weight: 700;
        color: #ffffff;
        letter-spacing: -0.01em;
    }

    .brand-subtitle {
        font-size: 10px;
        color: #737373;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    .sidebar-toggle {
        width: 28px;
        height: 28px;
        border-radius: 6px;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: all 0.2s;
        flex-shrink: 0;
    }

    .sidebar-toggle:hover {
        background: rgba(255, 255, 255, 0.1);
        border-color: rgba(255, 255, 255, 0.2);
    }

    .sidebar-toggle svg {
        width: 16px;
        height: 16px;
        stroke: #a3a3a3;
        transition: transform 0.3s;
    }

    .sidebar.collapsed .sidebar-toggle svg {
        transform: rotate(180deg);
    }

    .sidebar-nav {
        padding: 16px 8px;
        overflow-y: auto;
        height: calc(100vh - 72px);
    }

    .sidebar-nav::-webkit-scrollbar {
        width: 4px;
    }

    .sidebar-nav::-webkit-scrollbar-thumb {
        background: rgba(255, 255, 255, 0.1);
        border-radius: 2px;
    }

    .nav-section {
        margin-bottom: 24px;
    }

    .nav-section-title {
        padding: 8px 12px;
        font-size: 10px;
        font-weight: 600;
        color: #525252;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        white-space: nowrap;
        overflow: hidden;
        transition: opacity 0.2s;
    }

    .sidebar.collapsed .nav-section-title {
        opacity: 0;
        height: 0;
        padding: 0;
    }

    .nav-item {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 10px 12px;
        margin: 2px 0;
        border-radius: 8px;
        color: #a3a3a3;
        text-decoration: none;
        font-size: 14px;
        font-weight: 500;
        transition: all 0.2s;
        white-space: nowrap;
        position: relative;
    }

    .nav-item:hover {
        background: rgba(255, 255, 255, 0.05);
        color: #ffffff;
    }

    .nav-item.active {
        background: rgba(255, 255, 255, 0.08);
        color: #ffffff;
    }

    .nav-item.active::before {
        content: '';
        position: absolute;
        left: 0;
        top: 50%;
        transform: translateY(-50%);
        width: 3px;
        height: 20px;
        background: #ffffff;
        border-radius: 0 2px 2px 0;
    }

    .nav-icon {
        width: 20px;
        height: 20px;
        flex-shrink: 0;
        display: flex;
        align-items: center;
        justify-content: center;
    }

    .nav-icon svg {
        width: 18px;
        height: 18px;
        stroke: currentColor;
        fill: none;
    }

    .nav-text {
        overflow: hidden;
        opacity: 1;
        transition: opacity 0.2s;
    }

    .sidebar.collapsed .nav-text {
        opacity: 0;
        width: 0;
    }

    /* Main content adjustment */
    .main-wrapper {
        margin-left: 280px;
        transition: margin-left 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .main-wrapper.sidebar-collapsed {
        margin-left: 64px;
    }

    @media (max-width: 768px) {
        .sidebar {
            transform: translateX(-100%);
        }
        .main-wrapper {
            margin-left: 0 !important;
        }
    }
    '''


def get_sidebar_javascript() -> str:
    """
    Get sidebar toggle JavaScript

    Returns:
        JavaScript string for sidebar functionality
    """
    return '''
    <script>
        // Sidebar toggle functionality
        function toggleSidebar() {
            const sidebar = document.getElementById('sidebar');
            const mainWrapper = document.getElementById('mainWrapper');
            sidebar.classList.toggle('collapsed');
            mainWrapper.classList.toggle('sidebar-collapsed');

            // Save state to localStorage
            const isCollapsed = sidebar.classList.contains('collapsed');
            localStorage.setItem('sidebarCollapsed', isCollapsed);
        }

        // Restore sidebar state on load
        window.addEventListener('DOMContentLoaded', () => {
            const isCollapsed = localStorage.getItem('sidebarCollapsed') === 'true';
            if (isCollapsed) {
                document.getElementById('sidebar').classList.add('collapsed');
                document.getElementById('mainWrapper').classList.add('sidebar-collapsed');
            }
        });
    </script>
    '''


# Professional SVG Icons
class Icons:
    """SVG icon library for the application"""

    @staticmethod
    def shield(size: int = 24) -> str:
        return f'''<svg viewBox="0 0 24 24" width="{size}" height="{size}" stroke="currentColor" stroke-width="2" fill="none">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
        </svg>'''

    @staticmethod
    def alert_triangle(size: int = 24) -> str:
        return f'''<svg viewBox="0 0 24 24" width="{size}" height="{size}" stroke="currentColor" stroke-width="2" fill="none">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
            <line x1="12" y1="9" x2="12" y2="13"></line>
            <line x1="12" y1="17" x2="12.01" y2="17"></line>
        </svg>'''

    @staticmethod
    def calendar(size: int = 24) -> str:
        return f'''<svg viewBox="0 0 24 24" width="{size}" height="{size}" stroke="currentColor" stroke-width="2" fill="none">
            <rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect>
            <line x1="16" y1="2" x2="16" y2="6"></line>
            <line x1="8" y1="2" x2="8" y2="6"></line>
            <line x1="3" y1="10" x2="21" y2="10"></line>
        </svg>'''

    @staticmethod
    def users(size: int = 24) -> str:
        return f'''<svg viewBox="0 0 24 24" width="{size}" height="{size}" stroke="currentColor" stroke-width="2" fill="none">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
            <circle cx="9" cy="7" r="4"></circle>
            <path d="M23 21v-2a4 4 0 0 0-3-3.87"></path>
            <path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
        </svg>'''

    @staticmethod
    def search(size: int = 24) -> str:
        return f'''<svg viewBox="0 0 24 24" width="{size}" height="{size}" stroke="currentColor" stroke-width="2" fill="none">
            <circle cx="11" cy="11" r="8"></circle>
            <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
        </svg>'''

    @staticmethod
    def trending_up(size: int = 24) -> str:
        return f'''<svg viewBox="0 0 24 24" width="{size}" height="{size}" stroke="currentColor" stroke-width="2" fill="none">
            <polyline points="23 6 13.5 15.5 8.5 10.5 1 18"></polyline>
            <polyline points="17 6 23 6 23 12"></polyline>
        </svg>'''

    @staticmethod
    def target(size: int = 24) -> str:
        return f'''<svg viewBox="0 0 24 24" width="{size}" height="{size}" stroke="currentColor" stroke-width="2" fill="none">
            <circle cx="12" cy="12" r="10"></circle>
            <circle cx="12" cy="12" r="6"></circle>
            <circle cx="12" cy="12" r="2"></circle>
        </svg>'''

    @staticmethod
    def bell(size: int = 24) -> str:
        return f'''<svg viewBox="0 0 24 24" width="{size}" height="{size}" stroke="currentColor" stroke-width="2" fill="none">
            <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
            <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
        </svg>'''

    @staticmethod
    def refresh(size: int = 24) -> str:
        return f'''<svg viewBox="0 0 24 24" width="{size}" height="{size}" stroke="currentColor" stroke-width="2" fill="none">
            <polyline points="23 4 23 10 17 10"></polyline>
            <polyline points="1 20 1 14 7 14"></polyline>
            <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path>
        </svg>'''
