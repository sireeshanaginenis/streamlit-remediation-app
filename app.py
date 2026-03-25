import streamlit as st
import streamlit.components.v1 as components
import os
import time
 
# Import agents directly (NO graph.invoke)
from remediation_backend import (
    ingestion_agent,
    classifier_agent,
    os_detection_agent,
    remediation_agents,
    summarization_agent,
    validation_agent,
    execution_agent,
    logging_agent
)
 
# -------------------------------------------------
# PAGE CONFIG
# -------------------------------------------------
st.set_page_config(layout="wide")
st.title("🛡 Autonomous Vulnerability Intelligence & Remediation")
 
 
if "auto_remediate_clicked" not in st.session_state:
    st.session_state.auto_remediate_clicked = False

st.markdown("""
<style>
div.stButton > button:first-child {
    background-color: #4da3ff;
    color: white;
}
</style>
""", unsafe_allow_html=True)


if st.button("🚀 Auto-Remediate All Steps"):
    st.session_state.auto_remediate_clicked = True
    st.session_state.pipeline_state["current_step"] = 1
    st.session_state.auto_run = True
# -------------------------------------------------
# Progress Renderer (UNCHANGED)
# -------------------------------------------------
def render_progress(current_step, state):

    step_names = [
        "Ingestion",
        "Classification Engine",
        "Distribution Analyzer",
        "Fix Analyzer",
        "Summarization",
        "Pre-Remediation Checks",
        "Auto Remediation & Validation",
        "Metrics & Reporting"
    ]

    # -----------------------------
    # Metrics pulled from state
    # -----------------------------
    metrics = {
        1: f"Vunerabilities : {len(state.get('dataframe', [])) if state.get('dataframe') is not None else 0}",

        2: f"Simple : {state.get('classified', {}).get('simple',0)}<br>"
           f"Medium : {state.get('classified', {}).get('medium',0)}<br>"
           f"Complex : {state.get('classified', {}).get('complex',0)}<br>",

        3: f"Win : {state.get('os_distribution',{}).get('windows_count',0)}<br>"
           f"Linux : {state.get('os_distribution',{}).get('linux_total',0)}",

        4: f"CVEs : {len(state.get('remediation_data',{}))}",

        5: f"Generated Fix's : {len(state.get('summarized_steps',{}))}",

        6: f"Validated : {len(state.get('validation_result',{}))}",

        7: f"Executed : {len(state.get('execution_result',{}))}",

        8: f"Logs : {len(state.get('logs',[]))}"
    }

    total_steps = len(step_names)

    if current_step > total_steps:
        progress_percent = 100
    else:
        progress_percent = ((current_step - 1) / (total_steps - 1)) * 100

    html = f"""
    <style>
    .progress-container {{
        display: flex;
        justify-content: space-between;
        position: relative;
        margin-top: 20px;
        margin-bottom: 20px;
    }}

    .progress-line {{
        position: absolute;
        top: 18px;
        left: 0;
        right: 0;
        height: 4px;
        background-color: #e0e0e0;
        z-index: 1;
    }}

    .progress-line-fill {{
        position: absolute;
        top: 18px;
        left: 0;
        height: 4px;
        background-color: #4CAF50;
        z-index: 2;
        transition: width 0.4s ease;
    }}

    .step {{
        text-align: center;
        z-index: 3;
        width: 12%;
    }}

    .circle {{
        height: 35px;
        width: 35px;
        border-radius: 50%;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        background-color: #ccc;
        color: white;
        font-weight: bold;
    }}

    .completed {{
        background-color: #4CAF50;
    }}

    .current {{
        background-color: #FF9800;
    }}

    .label {{
        font-size: 12px;
        margin-top: 5px;
        font-weight: 600;
    }}

    .metric {{
        font-size: 11px;
        color: #666;
    }}

    </style>

    <div class="progress-container">
        <div class="progress-line"></div>
        <div class="progress-line-fill" style="width:{progress_percent}%"></div>
    """

    for i, name in enumerate(step_names, start=1):

        if i < current_step:
            status = "completed"
            symbol = "✓"
        elif i == current_step:
            status = "current"
            symbol = "⏳"
        else:
            status = ""
            symbol = ""

        metric_text = metrics.get(i, "")

        html += f"""
        <div class="step">
            <div class="circle {status}">{symbol}</div>
            <div class="label">{name}</div>
            <div class="metric">{metric_text}</div>
        </div>
        """

    html += "</div>"

    components.html(html, height=170)
 
 
# -------------------------------------------------
# INITIALIZE SESSION STATE
# -------------------------------------------------
 
if "pipeline_state" not in st.session_state:
    st.session_state.pipeline_state = {
        "vulnerabilities": [],
        "dataframe": None,
        "classified": {},
        "os_distribution": {},
        "remediation_data": {},
        "agent_execution_summary": {},
        "summarized_steps": {},
        "validation_result": {},
        "approval_status": "",
        "execution_result": {},
        "logs": [],
        "current_step": 1
    }
 
state = st.session_state.pipeline_state
progress_placeholder = st.empty()

# -------------------------------------------------
# PROGRESS BAR (UNCHANGED)
# -------------------------------------------------
render_progress(min(state["current_step"], 8), state)
 
 
# =========================================================
# 1️⃣ INGESTION AGENT
# =========================================================
st.markdown("## 1️⃣ Ingestion Agent")
 
with st.expander("Ingestion Details", expanded=True):
 
    df = state.get("dataframe", None)
 
    if df is not None:
        st.write(f"Total vulnerabilities received from Excel: {len(df)}")
        st.dataframe(df.head())
    else:
        st.write("No ingestion data available.")
 
 
# =========================================================
# 2️⃣ CLASSIFIER AGENT
# =========================================================
with st.expander("Classification Summary", expanded=True):
    st.write("Severity Distribution:")
    st.json(state.get("classified", {}))

    # ✅ Add this
  #  st.write("DEBUG - Current Step:", state.get("current_step"))
 
 
# =========================================================
# 3️⃣ REMEDIATION ANALYZER
# =========================================================
st.markdown("## 3️⃣ Distribution Analyzer Agent")
 
with st.expander("OS Distribution", expanded=True):
 
    os_data = state.get("os_distribution", {})
 
    st.write("### OS-wise Vulnerabilities")
    st.write(f"Windows: {os_data.get('windows_count', 0)}")
    st.write(f"Linux: {os_data.get('linux_total', 0)}")
 
    st.write("### Linux Flavours")
    for flavour, count in os_data.get("flavour_counts", {}).items():
        if count > 0:
            st.write(f"{flavour} : {count}")
 
 
# =========================================================
# 4️⃣ PARALLEL REMEDIATION AGENTS
# =========================================================
st.markdown("## 4️⃣ Fix Analyzer Agents")
 
with st.expander("Remediation Fetch Status", expanded=True):
 
    remediation_data = state.get("remediation_data", {})
 
    st.write(f"Total CVEs Processed: {len(remediation_data)}")
 
    for cve in remediation_data.keys():
        st.write(f"✔ {cve}")
 
 
# =========================================================
# 5️⃣ SUMMARIZATION
# =========================================================
st.markdown("## 5️⃣ Remediation Summarization Agent")
 
summarized = state.get("summarized_steps", {})
 
if not summarized:
    st.write("No remediation summaries available.")
else:
    for cve_id, result in summarized.items():
        with st.expander(f"CVE: {cve_id}", expanded=False):
 
            st.write("📌 Summary:")
            st.code(result.get("summary"), language="text")
 
            st.write("🛠 Remediation:")
          #  st.markdown(result.get("remediation"))
            st.code(result.get("remediation"), language="bash")
 
            st.write("📚 Source:")
            st.write(result.get("sources"))
 
 
# =========================================================
# 6️⃣ VALIDATION
# =========================================================
st.markdown("## 6️⃣ Checks Agent")
 
with st.expander("Validation Results", expanded=True):
    st.json(state.get("validation_result", {}))
 
 
# =========================================================
# 7️⃣ EXECUTION
# =========================================================
st.markdown("## 7️⃣ Auto Remediation & Validation Agent")
 
with st.expander("Execution Status", expanded=True):
    st.json(state.get("execution_result", {}))
 
 
# =========================================================
# 8️⃣ FINAL STATUS
# =========================================================
st.markdown("## 8️⃣ Metrics & Reporting Agent")
 

FILE_PATH = "srs_data_sample.xlsx"

if os.path.exists(FILE_PATH) and st.session_state.get("auto_remediate_clicked", False):

    step = state["current_step"]

    # Run ONLY current step
    if step == 1:
        state = ingestion_agent(state)

    elif step == 2:
        state = classifier_agent(state)

    elif step == 3:
        state = os_detection_agent(state)

    elif step == 4:
        state = remediation_agents(state)

    elif step == 5:
        state = summarization_agent(state)

    elif step == 6:
        state = validation_agent(state)

    elif step == 7:
        state = execution_agent(state)

    elif step == 8:
        state = logging_agent(state)
        st.session_state.auto_remediate_clicked = False

    # Save state
    st.session_state.pipeline_state = state

    # Move to next step AFTER UI rendered
    if step < 8:
        time.sleep(1)
        st.session_state.pipeline_state["current_step"] = step + 1
        st.rerun()
