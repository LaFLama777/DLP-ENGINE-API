class Theme:
    # Premium Dark Theme - Pure Black Design
    bg_dark = "#000000"  # Pure black
    bg_dark_secondary = "#0a0a0a"  # Slightly lighter black
    bg_card = "#111111"  # Card background
    
    # Glass Effects
    glass_bg = "rgba(255, 255, 255, 0.02)"
    glass_border = "rgba(255, 255, 255, 0.1)"
    glass_highlight = "rgba(255, 255, 255, 0.15)"
    glass_shadow = "0 20px 60px 0 rgba(0, 0, 0, 0.5)"
    
    # Brand Colors - Refined for dark theme
    primary = "#3b82f6"    # Modern Blue
    primary_dark = "#2563eb"
    primary_light = "#60a5fa"
    secondary = "#10b981"  # Emerald
    accent = "#8b5cf6"     # Purple accent
    
    # Status Colors
    success = "#10b981"    # Emerald green
    danger = "#ef4444"     # Modern red
    warning = "#f59e0b"    # Amber
    info = "#3b82f6"       # Blue
    
    # Text
    text_primary = "#ffffff"
    text_secondary = "#9ca3af"
    text_muted = "#6b7280"
    
    # Gradients
    gradient_primary = "linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)"
    gradient_success = "linear-gradient(135deg, #10b981 0%, #059669 100%)"
    gradient_card = "linear-gradient(135deg, rgba(0, 0, 0, 0.95) 0%, rgba(0, 0, 0, 0.98) 100%)"
    gradient_glass = "linear-gradient(135deg, rgba(255, 255, 255, 0.08) 0%, rgba(255, 255, 255, 0.02) 100%)"
    gradient_glow = "radial-gradient(circle at 50% 0%, rgba(59, 130, 246, 0.1) 0%, transparent 60%)"

def get_css() -> str:
    return f"""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap');
        
        :root {{
            --bg-dark: {Theme.bg_dark};
            --text-primary: {Theme.text_primary};
            --text-secondary: {Theme.text_secondary};
            --primary: {Theme.primary};
            --glass-border: {Theme.glass_border};
        }}

        * {{
            box-sizing: border-box;
            scrollbar-width: thin;
            scrollbar-color: {Theme.primary} transparent;
        }}

        body {{
            background-color: {Theme.bg_dark};
            background-image: 
                radial-gradient(circle at 20% 10%, rgba(59, 130, 246, 0.08) 0%, transparent 40%),
                radial-gradient(circle at 80% 80%, rgba(16, 185, 129, 0.05) 0%, transparent 40%);
            background-attachment: fixed;
            color: {Theme.text_primary};
            font-family: 'Plus Jakarta Sans', sans-serif;
            margin: 0;
            padding: 0;
            overflow-x: hidden;
            -webkit-font-smoothing: antialiased;
        }}

        /* Custom Scrollbar */
        ::-webkit-scrollbar {{
            width: 6px;
            height: 6px;
        }}
        ::-webkit-scrollbar-track {{
            background: transparent;
        }}
        ::-webkit-scrollbar-thumb {{
            background: rgba(255, 255, 255, 0.1);
            border-radius: 3px;
        }}
        ::-webkit-scrollbar-thumb:hover {{
            background: {Theme.primary};
        }}

        /* Glassmorphism Card */
        .card {{
            background: {Theme.gradient_card};
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid {Theme.glass_border};
            border-radius: 20px;
            padding: 24px;
            box-shadow: {Theme.glass_shadow};
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }}

        .card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            opacity: 0.5;
        }}

        .card:hover {{
            transform: translateY(-5px) scale(1.01);
            box-shadow: 0 20px 40px 0 rgba(0, 0, 0, 0.4);
            border-color: rgba(255, 255, 255, 0.2);
        }}
        
        .card:hover::before {{
            opacity: 0.8;
            background: linear-gradient(90deg, transparent, {Theme.primary}, transparent);
        }}

        /* Typography */
        h1, h2, h3, h4, h5, h6 {{
            margin: 0;
            font-weight: 700;
            letter-spacing: -0.02em;
        }}

        .text-gradient {{
            background: {Theme.gradient_primary};
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}

        /* Buttons */
        .btn-primary {{
            background: {Theme.primary};
            color: white;
            border: none;
            padding: 10px 24px;
            border-radius: 12px;
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 6px rgba(0, 117, 255, 0.2);
            position: relative;
            overflow: hidden;
        }}

        .btn-primary:hover {{
            transform: translateY(-2px);
            box-shadow: 0 7px 14px rgba(0, 117, 255, 0.4);
        }}
        
        .btn-primary::after {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(rgba(255,255,255,0.2), transparent);
            opacity: 0;
            transition: opacity 0.3s;
        }}
        
        .btn-primary:hover::after {{
            opacity: 1;
        }}
        
        .btn-glass {{
            background: rgba(255, 255, 255, 0.05);
            color: white;
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 8px 16px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            text-decoration: none;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }}
        
        .btn-glass:hover {{
            background: rgba(255, 255, 255, 0.1);
            border-color: rgba(255, 255, 255, 0.3);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}

        /* Table Styling */
        table {{
            width: 100%;
            border-collapse: separate;
            border-spacing: 0 8px; /* Tighter spacing */
            margin-top: -8px;
        }}

        th {{
            text-align: left;
            padding: 12px 24px;
            color: {Theme.text_secondary};
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }}

        td {{
            padding: 16px 24px;
            background: rgba(255, 255, 255, 0.015);
            color: {Theme.text_primary};
            font-size: 14px;
            border-top: 1px solid rgba(255, 255, 255, 0.02);
            border-bottom: 1px solid rgba(255, 255, 255, 0.02);
            transition: all 0.2s ease;
        }}
        
        td:first-child {{
            border-top-left-radius: 12px;
            border-bottom-left-radius: 12px;
            border-left: 1px solid rgba(255, 255, 255, 0.02);
        }}
        
        td:last-child {{
            border-top-right-radius: 12px;
            border-bottom-right-radius: 12px;
            border-right: 1px solid rgba(255, 255, 255, 0.02);
        }}

        tr:hover td {{
            background: rgba(255, 255, 255, 0.05);
            transform: scale(1.01);
            border-color: rgba(255, 255, 255, 0.1);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            z-index: 1;
        }}

        /* Badges */
        .badge {{
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            display: inline-block;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .badge-success {{ background: rgba(1, 181, 116, 0.15); color: {Theme.success}; border: 1px solid rgba(1, 181, 116, 0.3); }}
        .badge-danger {{ background: rgba(227, 26, 26, 0.15); color: {Theme.danger}; border: 1px solid rgba(227, 26, 26, 0.3); }}
        .badge-warning {{ background: rgba(255, 159, 67, 0.15); color: {Theme.warning}; border: 1px solid rgba(255, 159, 67, 0.3); }}
        .badge-info {{ background: rgba(0, 117, 255, 0.15); color: {Theme.primary}; border: 1px solid rgba(0, 117, 255, 0.3); }}

        /* Animations */
        @keyframes float {{
            0% {{ transform: translateY(0px); }}
            50% {{ transform: translateY(-10px); }}
            100% {{ transform: translateY(0px); }}
        }}
        
        .animate-float {{
            animation: float 6s ease-in-out infinite;
        }}
        
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(20px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        
        .fade-in {{
            animation: fadeIn 0.6s cubic-bezier(0.4, 0, 0.2, 1) forwards;
            opacity: 0;
        }}
        
        .delay-1 {{ animation-delay: 0.1s; }}
        .delay-2 {{ animation-delay: 0.2s; }}
        .delay-3 {{ animation-delay: 0.3s; }}
        
        @keyframes pulse-glow {{
            0% {{ box-shadow: 0 0 0 0 rgba(0, 117, 255, 0.4); }}
            70% {{ box-shadow: 0 0 0 10px rgba(0, 117, 255, 0); }}
            100% {{ box-shadow: 0 0 0 0 rgba(0, 117, 255, 0); }}
        }}
        
        .pulse {{
        }}
        
        input:focus, select:focus {{
            border-color: {Theme.primary} !important;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2) !important;
            background: rgba(0, 0, 0, 0.8) !important;
            outline: none;
        }}
    </style>
    """

def get_base_html_head(title: str) -> str:
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{title} - DLP Engine</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        {get_css()}
    </head>
    """
