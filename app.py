import streamlit as st
import streamlit.components.v1 as components
import os
from src.core.orchestrator import ThreatIntelOrchestrator
import json

# Page Configuration
st.set_page_config(page_title="Automated Threat Intelligence Platform", layout="wide")

st.markdown("""
    <style>
    .main {
        background-color: #0e1117;
    }
    .stButton>button {
        width: 100%;
        border-radius: 5px;
        height: 3em;
        background-color: #ff4b4b;
        color: white;
    }
    .report-card {
        background-color: #161b22;
        padding: 20px;
        border-radius: 10px;
        border-left: 5px solid #ff4b4b;
        margin-bottom: 20px;
    }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ Automated Threat Intel & Correlation Platform")
st.subheader("Passive OSINT & Active Reconnaissance Dashboard")

# Sidebar for API Configuration Check
with st.sidebar:
    st.header("System Status")
    hunter_key = os.getenv("HUNTER_API_KEY")
    if hunter_key:
        st.success("Hunter.io API: Connected")
    else:
        st.warning("Hunter.io API: Missing")
    
    breach_key = os.getenv("BREACH_DIRECTORY_API_KEY")
    if breach_key:
        st.success("BreachDirectory API: Connected")
    else:
        st.warning("BreachDirectory API: Missing")
    
    import shutil
    nmap_executable = shutil.which("nmap")
    if nmap_executable or os.path.exists(os.getenv("NMAP_PATH", "")):
        st.success("Nmap: Detected")
    else:
        st.warning("Nmap: Not found in PATH or NMAP_PATH")

# Main Input
target_domain = st.text_input("Enter Target Domain (e.g., example.com)", placeholder="example.com")

if st.button("Run Threat Intelligence Workflow"):
    if not target_domain:
        st.error("Please enter a target domain.")
    else:
        orchestrator = ThreatIntelOrchestrator()
        
        with st.spinner(f"Analyzing {target_domain}... This may take a minute."):
            try:
                results, graph_html_path = orchestrator.run_recon(target_domain)
                
                # Layout
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.header("🌐 Correlation Graph")
                    with open(graph_html_path, 'r', encoding='utf-8') as f:
                        html_content = f.read()
                    components.html(html_content, height=650)
                
                with col2:
                    st.header("📊 Threat Report")
                    
                    # OSINT Summary
                    st.markdown('<div class="report-card">', unsafe_allow_html=True)
                    st.markdown("### Passive OSINT Results")
                    emails_found = results["osint"]["hunter"].get("data", {}).get("emails", [])
                    st.write(f"**Emails Found:** {len(emails_found)}")
                    
                    breaches = results["osint"].get("breaches", {})
                    total_leaks = sum([len(b) for b in breaches.values() if isinstance(b, list)])
                    st.write(f"**Data Leaks Found:** {total_leaks}")
                    
                    st.write(f"**IPs Identified:** {len(results['osint']['dns'].get('A', []))}")
                    st.markdown('</div>', unsafe_allow_html=True)

                    # Detailed Breach Analysis (New Feature)
                    if total_leaks > 0:
                        st.markdown('<div class="report-card" style="border-left: 5px solid #ffa500;">', unsafe_allow_html=True)
                        st.markdown("### ⚠️ Deep Leak Analysis")
                        st.warning("The following emails were found in known data breaches:")
                        
                        for email, leak_list in breaches.items():
                            if isinstance(leak_list, list) and len(leak_list) > 0:
                                with st.expander(f"Leaks for {email}"):
                                    for leak in leak_list:
                                        source = leak.get("source", "Unknown Source")
                                        st.write(f"🚩 **Source:** {source}")
                                        # Display what was leaked if available
                                        leak_info = []
                                        if leak.get("has_password"): leak_info.append("Passwords")
                                        if leak.get("has_username"): leak_info.append("Usernames")
                                        if leak.get("has_ip"): leak_info.append("IP Addresses")
                                        
                                        if leak_info:
                                            st.info(f"Exposed Data: {', '.join(leak_info)}")
                                        st.divider()
                        st.markdown('</div>', unsafe_allow_html=True)
                    
                    # Active Scan Summary
                    st.markdown('<div class="report-card">', unsafe_allow_html=True)
                    st.markdown("### Active Scan Findings")
                    for scan in results["scans"]:
                        st.write(f"**Host:** {scan['ip']}")
                        if isinstance(scan["results"], list):
                            for host in scan["results"]:
                                for proto in host["protocols"]:
                                    for port in proto["ports"]:
                                        st.write(f"- Port {port['port']}: {port['service']} ({port['version']})")
                        else:
                            st.error(f"Scan failed for {scan['ip']}")
                    st.markdown('</div>', unsafe_allow_html=True)

                # Raw Data Export
                with st.expander("View Raw JSON Data"):
                    st.json(results)
                    
            except Exception as e:
                st.error(f"An error occurred: {e}")
