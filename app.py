import streamlit as st
import tempfile
import os
import datetime
import hashlib
import pandas as pd
import plotly.express as px
from database.db import get_db_connection, init_db
from reports.pdf_generator import generate_pdf_report

# Import custom forensic analyzers
from modules.image_forensics.image_analyzer import analyze_image
from modules.network_forensics.network_analyzer import analyze_pcap
from modules.windows_forensics.windows_analyzer import analyze_evtx

# 1. Page Configuration
st.set_page_config(page_title="SHADOWTRACE", page_icon="🛡️", layout="wide")

# 2. Custom CSS
st.markdown("""
<style>
    .stApp { background-color: #030712; color: #e5e7eb; }
    header {visibility: hidden;} footer {visibility: hidden;}
    .glass-card {
        background: rgba(255, 255, 255, 0.03);
        backdrop-filter: blur(20px);
        border: 1px solid rgba(0, 229, 255, 0.2);
        border-radius: 12px; padding: 20px; text-align: center;
        box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1); margin-bottom: 20px;
    }
    .neon-text {
        color: #00e5ff; text-shadow: 0 0 10px rgba(0, 229, 255, 0.5); font-weight: bold;
    }
    [data-testid="stMetricValue"] { color: #00e5ff !important; text-shadow: 0 0 10px rgba(0, 229, 255, 0.5); }
    [data-testid="stSidebar"] { background-color: #0b1220 !important; border-right: 1px solid rgba(0, 229, 255, 0.1); }
</style>
""", unsafe_allow_html=True)

# --- HELPER FUNCTION TO SAVE TO DATABASE ---
def log_evidence_to_db(filename, file_bytes):
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT case_id FROM cases LIMIT 1")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO cases (case_id, investigator, created_at, status) VALUES (?, ?, ?, ?)",
                       ("CASE-001", "Lead Investigator", now, "Open"))
    
    evidence_id = f"EV-{int(datetime.datetime.now().timestamp())}"
    try:
        cursor.execute("INSERT INTO evidence (evidence_id, case_id, filename, sha256_hash, ingested_at) VALUES (?, ?, ?, ?, ?)",
                       (evidence_id, "CASE-001", filename, sha256, now))
        conn.commit()
    except Exception as e:
        st.error(f"Database Error: {e}")
    finally:
        conn.close()
    return sha256

# 3. Sidebar Navigation
with st.sidebar:
    st.markdown("<h2 style='text-align: center;'>🛡️ <span class='neon-text'>MENU</span></h2>", unsafe_allow_html=True)
    st.divider()
    page = st.radio(
        "Select Module:",
        ["Overview", "Android Forensics", "Memory Forensics", 
         "Image Forensics", "Windows Forensics", "Network Forensics", 
         "Evidence Vault", "Investigation Timeline", "Case Management", "Reports & Analytics"]
    )

# 4. Page Routing
if page == "Overview":
    st.markdown("<h1 style='text-align: center;'>🛡️ <span class='neon-text'>SHADOWTRACE</span></h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #9ca3af;'>Offline Digital Forensics & Cyber Investigation Suite</p>", unsafe_allow_html=True)
    st.divider()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM evidence")
    total_evidence = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM cases")
    total_cases = cursor.fetchone()[0]
    conn.close()

    col1, col2, col3, col4 = st.columns(4)
    with col1: st.markdown(f"<div class='glass-card'><h3>Total Evidence</h3><h2 class='neon-text'>{total_evidence}</h2></div>", unsafe_allow_html=True)
    with col2: st.markdown(f"<div class='glass-card'><h3>Open Cases</h3><h2 class='neon-text'>{total_cases}</h2></div>", unsafe_allow_html=True)
    with col3: st.markdown("<div class='glass-card'><h3>Suspicious Findings</h3><h2 class='neon-text'>0</h2></div>", unsafe_allow_html=True)
    with col4: st.markdown("<div class='glass-card'><h3>Reports Generated</h3><h2 class='neon-text'>0</h2></div>", unsafe_allow_html=True)
    st.info("Welcome, Investigator. System is ready. Select a module from the sidebar to begin.")

elif page == "Image Forensics":
    st.markdown("<h1>🖼️ <span class='neon-text'>Image Forensics</span></h1>", unsafe_allow_html=True)
    uploaded_image = st.file_uploader("Upload Evidence (JPG, PNG, JPEG)", type=["jpg", "jpeg", "png"])
    if uploaded_image is not None:
        if st.button("Run Image Analysis", type="primary"):
            with st.spinner("Analyzing image metadata..."):
                with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_image.name)[1]) as tmp_file:
                    tmp_file.write(uploaded_image.getvalue())
                    tmp_filepath = tmp_file.name
                try:
                    results = analyze_image(tmp_filepath)
                    db_hash = log_evidence_to_db(uploaded_image.name, uploaded_image.getvalue())
                    st.success("Analysis Complete and Saved to Vault!")
                    st.markdown("### 🔒 Evidence Integrity (SHA-256)")
                    st.code(db_hash, language="text")
                    st.markdown("### 📊 Extracted Metadata")
                    st.json(results["metadata"])
                finally:
                    if os.path.exists(tmp_filepath): os.remove(tmp_filepath)

elif page == "Network Forensics":
    st.markdown("<h1>🌐 <span class='neon-text'>Network Forensics</span></h1>", unsafe_allow_html=True)
    uploaded_pcap = st.file_uploader("Upload Network Capture", type=["pcap", "pcapng", "cap"])
    if uploaded_pcap is not None:
        if st.button("Run Network Analysis", type="primary"):
            with st.spinner("Analyzing network packets..."):
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp_file:
                    tmp_file.write(uploaded_pcap.getvalue())
                    tmp_filepath = tmp_file.name
                try:
                    results = analyze_pcap(tmp_filepath)
                    log_evidence_to_db(uploaded_pcap.name, uploaded_pcap.getvalue())
                    st.success("Analysis Complete and Saved to Vault!")
                    col1, col2 = st.columns(2)
                    with col1: st.metric("Total Packets", results["Total Packets"])
                    with col2: st.metric("Unique IP Addresses", results["Unique IP Addresses"])
                    st.markdown("### 📡 Protocol Breakdown")
                    st.json(results["Protocol Breakdown"])
                finally:
                    if os.path.exists(tmp_filepath): os.remove(tmp_filepath)

elif page == "Windows Forensics":
    st.markdown("<h1>🪟 <span class='neon-text'>Windows Forensics</span></h1>", unsafe_allow_html=True)
    uploaded_evtx = st.file_uploader("Upload Windows Event Log", type=["evtx"])
    if uploaded_evtx is not None:
        if st.button("Run Windows Analysis", type="primary"):
            with st.spinner("Parsing Windows event logs..."):
                with tempfile.NamedTemporaryFile(delete=False, suffix=".evtx") as tmp_file:
                    tmp_file.write(uploaded_evtx.getvalue())
                    tmp_filepath = tmp_file.name
                try:
                    results = analyze_evtx(tmp_filepath)
                    log_evidence_to_db(uploaded_evtx.name, uploaded_evtx.getvalue())
                    st.success("Analysis Complete and Saved to Vault!")
                    st.metric("Total Events Found", results["Total Events Found"])
                    st.markdown("### 📋 Recent Events Preview")
                    st.json(results["Recent Events Preview"])
                finally:
                    if os.path.exists(tmp_filepath): os.remove(tmp_filepath)

elif page == "Evidence Vault":
    st.markdown("<h1>🗄️ <span class='neon-text'>Evidence Vault</span></h1>", unsafe_allow_html=True)
    st.write("All ingested evidence is cryptographically hashed and stored here.")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM evidence ORDER BY ingested_at DESC")
    evidence_records = cursor.fetchall()
    conn.close()
    if not evidence_records:
        st.warning("Vault is empty. Upload evidence in one of the modules first.")
    else:
        for record in evidence_records:
            with st.expander(f"📄 {record['filename']} (ID: {record['evidence_id']})"):
                st.write(f"**Case ID:** {record['case_id']}")
                st.write(f"**Ingested At:** {record['ingested_at']}")
                st.write(f"**SHA-256:** `{record['sha256_hash']}`")

elif page == "Investigation Timeline":
    st.markdown("<h1>⏱️ <span class='neon-text'>Investigation Timeline</span></h1>", unsafe_allow_html=True)
    st.write("Visual chronological mapping of all ingested evidence.")
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT evidence_id, filename, ingested_at FROM evidence ORDER BY ingested_at", conn)
    conn.close()
    
    if df.empty:
        st.info("No evidence logged yet. Upload files to generate a timeline.")
    else:
        df['ingested_at'] = pd.to_datetime(df['ingested_at'])
        fig = px.scatter(df, x='ingested_at', y='filename', color='filename', hover_data=['evidence_id'], title="Evidence Ingestion Sequence")
        fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#00e5ff"))
        st.plotly_chart(fig, use_container_width=True)
        st.markdown("### 📋 Raw Timeline Data")
        st.dataframe(df, use_container_width=True)

elif page == "Case Management":
    st.markdown("<h1>📁 <span class='neon-text'>Case Management</span></h1>", unsafe_allow_html=True)
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### Create New Case")
        with st.form("new_case_form"):
            new_case_id = st.text_input("Case ID (e.g., CASE-002)")
            investigator = st.text_input("Investigator Name")
            submit = st.form_submit_button("Create Case")
            if submit and new_case_id and investigator:
                now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                conn = get_db_connection()
                try:
                    conn.execute("INSERT INTO cases (case_id, investigator, created_at, status) VALUES (?, ?, ?, ?)", (new_case_id, investigator, now, "Open"))
                    conn.commit()
                    st.success(f"Case {new_case_id} created successfully!")
                except Exception as e:
                    st.error(f"Error: {e}")
                finally:
                    conn.close()
    with col2:
        st.markdown("### Active Cases")
        conn = get_db_connection()
        cases_df = pd.read_sql_query("SELECT * FROM cases", conn)
        conn.close()
        if not cases_df.empty:
            st.dataframe(cases_df, use_container_width=True)

elif page == "Reports & Analytics":
    st.markdown("<h1>📄 <span class='neon-text'>Reports & Analytics</span></h1>", unsafe_allow_html=True)
    st.write("Generate a professional PDF report containing all vaulted evidence.")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT case_id, filename, sha256_hash, ingested_at FROM evidence")
    evidence_data = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    if st.button("Generate PDF Report", type="primary"):
        if not evidence_data:
            st.error("No evidence found. Upload files first.")
        else:
            with st.spinner("Generating PDF..."):
                pdf_path = generate_pdf_report("CASE-001", evidence_data)
                st.success("Report Generated Successfully!")
                
                # Provide a download button
                with open(pdf_path, "rb") as f:
                    st.download_button(
                        label="Download PDF",
                        data=f,
                        file_name="SHADOWTRACE_Report.pdf",
                        mime="application/pdf"
                    )

elif page in ["Android Forensics", "Memory Forensics"]:
    st.markdown(f"<h1><span class='neon-text'>{page}</span></h1>", unsafe_allow_html=True)
    st.warning(f"⚠️ **{page} is currently a Prototype.**")
    st.write("Parsing Android backups (.ab) and Memory Dumps (.raw/.mem) requires complex binary parsing and symbol tables. The UI shell is complete and ready for future integration.")

else:
    st.markdown(f"<h1><span class='neon-text'>{page}</span></h1>", unsafe_allow_html=True)
    st.info(f"The {page} module is currently under construction. Check back soon!")