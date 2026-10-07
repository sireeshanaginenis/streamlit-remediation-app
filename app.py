
import streamlit as st
import streamlit.components.v1 as components
import os
import time
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# Import agents directly (NO graph.invoke)
from remediation_backend import (
    ingestion_agent,
    classifier_agent,
    os_detection_agent,
    remediation_agents,
    summarization_agent,
    validation_agent,
    execution_agent,
    logging_agent,
    generate_excel_report,
)


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(layout="wide")

st.title(
    "🛡 Autonomous Vulnerability Intelligence & Remediation"
)


# =========================================================
# SESSION STATE
# =========================================================

if "auto_remediate_clicked" not in st.session_state:
    st.session_state.auto_remediate_clicked = False


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
        "current_step": 1,
        "reporting_metrics": {},
    }


# =========================================================
# BUTTON STYLE
# =========================================================

st.markdown(
    """
    <style>
    div.stButton > button:first-child {
        background-color: #4da3ff;
        color: white;
        font-weight: 600;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# AUTO REMEDIATE BUTTON
# =========================================================

if st.button("🚀 Auto-Remediate All Steps"):

    st.session_state.auto_remediate_clicked = True

    st.session_state.pipeline_state["current_step"] = 1

    st.session_state.auto_run = True


# =========================================================
# PROGRESS RENDERER
# =========================================================

def render_progress(current_step, state):

    step_names = [
        "Ingestion",
        "Classification Engine",
        "Distribution Analyzer",
        "Fix Analyzer",
        "Summarization",
        "Pre-Remediation Checks",
        "Auto Remediation & Validation",
        "Metrics & Reporting",
    ]

    # -----------------------------------------------------
    # Get state data safely
    # -----------------------------------------------------

    dataframe = state.get("dataframe")

    classified = state.get(
        "classified",
        {}
    )

    os_distribution = state.get(
        "os_distribution",
        {}
    )

    remediation_data = state.get(
        "remediation_data",
        {}
    )

    summarized_steps = state.get(
        "summarized_steps",
        {}
    )

    validation_result = state.get(
        "validation_result",
        {}
    )

    execution_result = state.get(
        "execution_result",
        {}
    )

    reporting_metrics = state.get(
        "reporting_metrics",
        {}
    )

    kpis = reporting_metrics.get(
        "kpis",
        {}
    )

    # -----------------------------------------------------
    # Calculate metrics
    # -----------------------------------------------------

    total_vulnerabilities = (
        len(dataframe)
        if dataframe is not None
        else 0
    )

    metrics = {

        1: (
            f"Vulnerabilities: "
            f"{total_vulnerabilities}"
        ),

        2: (
            f"Simple: "
            f"{classified.get('simple', 0)}<br>"
            f"Medium: "
            f"{classified.get('medium', 0)}<br>"
            f"Complex: "
            f"{classified.get('complex', 0)}"
        ),

        3: (
            f"Windows: "
            f"{os_distribution.get('windows_count', 0)}<br>"
            f"Linux: "
            f"{os_distribution.get('linux_total', 0)}"
        ),

        4: (
            f"CVEs: "
            f"{len(remediation_data)}"
        ),

        5: (
            f"Fixes: "
            f"{len(summarized_steps)}"
        ),

        6: (
            f"Validated: "
            f"{len(validation_result)}"
        ),

        7: (
            f"Executed: "
            f"{len(execution_result)}"
        ),

        8: (
            f"Coverage: "
            f"{kpis.get('remediation_coverage', 0)}%"
        ),
    }

    # -----------------------------------------------------
    # Progress percentage
    # -----------------------------------------------------

    total_steps = len(step_names)

    if current_step >= total_steps:

        progress_percent = 100

    else:

        progress_percent = (
            (current_step - 1)
            / (total_steps - 1)
        ) * 100

    # -----------------------------------------------------
    # HTML
    # -----------------------------------------------------

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
        line-height: 1.4;
    }}

    </style>

    <div class="progress-container">

        <div class="progress-line"></div>

        <div
            class="progress-line-fill"
            style="width:{progress_percent}%">
        </div>
    """

    # -----------------------------------------------------
    # Render each step
    # -----------------------------------------------------

    for i, name in enumerate(
        step_names,
        start=1
    ):

        if i < current_step:

            status = "completed"
            symbol = "✓"

        elif i == current_step:

            status = "current"
            symbol = "⏳"

        else:

            status = ""
            symbol = ""

        metric_text = metrics.get(
            i,
            ""
        )

        html += f"""
        <div class="step">

            <div class="circle {status}">
                {symbol}
            </div>

            <div class="label">
                {name}
            </div>

            <div class="metric">
                {metric_text}
            </div>

        </div>
        """

    html += "</div>"

    components.html(
        html,
        height=170
    )


# =========================================================
# CURRENT STATE
# =========================================================

state = st.session_state.pipeline_state

progress_placeholder = st.empty()


# =========================================================
# PROGRESS BAR
# =========================================================

render_progress(
    min(state["current_step"], 8),
    state
)


# =========================================================
# 1️⃣ INGESTION AGENT
# =========================================================

st.markdown(
    "## 1️⃣ Ingestion Agent"
)

with st.expander(
    "Ingestion Details",
    expanded=True
):

    df = state.get(
        "dataframe",
        None
    )

    if df is not None:

        st.write(
            f"Total vulnerabilities received from Excel: "
            f"{len(df)}"
        )

        st.dataframe(
            df.head(),
            use_container_width=True
        )

    else:

        st.write(
            "No ingestion data available."
        )


# =========================================================
# 2️⃣ CLASSIFIER AGENT
# =========================================================

with st.expander(
    "Classification Summary",
    expanded=True
):

    st.write(
        "Severity Distribution:"
    )

    st.json(
        state.get(
            "classified",
            {}
        )
    )


# =========================================================
# 3️⃣ DISTRIBUTION ANALYZER
# =========================================================

st.markdown(
    "## 3️⃣ Distribution Analyzer Agent"
)

with st.expander(
    "OS Distribution",
    expanded=True
):

    os_data = state.get(
        "os_distribution",
        {}
    )

    st.write(
        "### OS-wise Vulnerabilities"
    )

    st.write(
        f"Windows: "
        f"{os_data.get('windows_count', 0)}"
    )

    st.write(
        f"Linux: "
        f"{os_data.get('linux_total', 0)}"
    )

    st.write(
        "### Linux Flavours"
    )

    for flavour, count in os_data.get(
        "flavour_counts",
        {}
    ).items():

        if count > 0:

            st.write(
                f"{flavour}: {count}"
            )


# =========================================================
# 4️⃣ PARALLEL REMEDIATION AGENTS
# =========================================================

st.markdown(
    "## 4️⃣ Fix Analyzer Agents"
)

with st.expander(
    "Remediation Fetch Status",
    expanded=True
):

    remediation_data = state.get(
        "remediation_data",
        {}
    )

    st.write(
        f"Total CVEs Processed: "
        f"{len(remediation_data)}"
    )

    for cve in remediation_data.keys():

        st.write(
            f"✔ {cve}"
        )


# =========================================================
# 5️⃣ SUMMARIZATION
# =========================================================

st.markdown(
    "## 5️⃣ Remediation Summarization Agent"
)

summarized = state.get(
    "summarized_steps",
    {}
)

if not summarized:

    st.write(
        "No remediation summaries available."
    )

else:

    for cve_id, result in summarized.items():

        with st.expander(
            f"CVE: {cve_id}",
            expanded=False
        ):

            st.write(
                "📌 Summary:"
            )

            st.code(
                result.get(
                    "summary",
                    ""
                ),
                language="text"
            )

            st.write(
                "🛠 Remediation:"
            )

            st.code(
                result.get(
                    "remediation",
                    ""
                ),
                language="bash"
            )

            st.write(
                "📚 Source:"
            )

            st.write(
                result.get(
                    "sources",
                    ""
                )
            )


# =========================================================
# 6️⃣ VALIDATION
# =========================================================

st.markdown(
    "## 6️⃣ Checks Agent"
)

with st.expander(
    "Validation Results",
    expanded=True
):

    st.json(
        state.get(
            "validation_result",
            {}
        )
    )


# =========================================================
# 7️⃣ EXECUTION
# =========================================================

st.markdown(
    "## 7️⃣ Auto Remediation & Validation Agent"
)

with st.expander(
    "Execution Status",
    expanded=True
):

    st.json(
        state.get(
            "execution_result",
            {}
        )
    )


# =========================================================
# 8️⃣ METRICS & REPORTING
# =========================================================

st.markdown(
    "## 8️⃣ Metrics & Reporting"
)

report = state.get(
    "reporting_metrics",
    {}
)


# =========================================================
# NO REPORT AVAILABLE
# =========================================================

if not report:

    st.info(
        "Metrics & reporting will be available "
        "after the remediation pipeline completes."
    )


# =========================================================
# REPORT AVAILABLE
# =========================================================

else:

    # -----------------------------------------------------
    # KPI DATA
    # -----------------------------------------------------

    kpis = report.get(
        "kpis",
        {}
    )
    
    excel_report = generate_excel_report(
        state
    )

    if excel_report is not None:

        st.download_button(
            label="📥 Download Metrics Report (Excel)",
            data=excel_report,
            file_name="vulnerability_remediation_metrics.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            use_container_width=False
        )

    # =====================================================
    # EXECUTIVE SUMMARY
    # =====================================================

    st.markdown(
        "### 📊 Executive Summary"
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "Total Vulnerabilities",
            kpis.get(
                "total_cves",
                0
            )
        )

    with col2:

        st.metric(
            "Simple Remediation Coverage",
            f"{kpis.get('remediation_coverage', 0)}%"
        )

    with col3:

        st.metric(
            "Validation Pass Rate",
            f"{kpis.get('validation_rate', 0)}%"
        )

    with col4:

        st.metric(
            "Execution Success",
            f"{kpis.get('execution_rate', 0)}%"
        )

    st.markdown("---")

    # =====================================================
    # SECONDARY KPI CARDS
    # =====================================================

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "Classified CVEs",
            kpis.get(
                "classified",
                0
            )
        )

    with col2:

        st.metric(
            "Remediation Found",
            kpis.get(
                "remediation_found",
                0
            )
        )

    with col3:

        st.metric(
            "RAG Hits",
            kpis.get(
                "rag_hits",
                0
            )
        )

    with col4:

        st.metric(
            "RAG Coverage",
            f"{kpis.get('rag_coverage', 0)}%"
        )

    # =====================================================
    # ROW 1 — SEVERITY + OS
    # =====================================================

    col1, col2 = st.columns(2)

    # -----------------------------------------------------
    # SEVERITY DISTRIBUTION
    # -----------------------------------------------------

    with col1:

        st.markdown(
            "### Severity Distribution"
        )

        severity = report.get(
            "severity_distribution",
            {}
        )

        severity_df = pd.DataFrame(
            {
                "Severity": list(
                    severity.keys()
                ),
                "Count": list(
                    severity.values()
                ),
            }
        )

        if not severity_df.empty:

            fig = px.bar(
                severity_df,
                x="Severity",
                y="Count",
                text="Count",
                title="Vulnerability Severity"
            )

            fig.update_layout(
                height=350,
                margin=dict(
                    l=20,
                    r=20,
                    t=50,
                    b=20
                ),
                showlegend=False
            )

            fig.update_traces(
                textposition="outside"
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        else:

            st.info(
                "No severity distribution data available."
            )

    # -----------------------------------------------------
    # OS DISTRIBUTION
    # -----------------------------------------------------

    with col2:

        st.markdown(
            "### Operating System Distribution"
        )

        os_distribution = report.get(
            "os_distribution",
            {}
        )

        os_df = pd.DataFrame(
            {
                "Operating System":
                    list(
                        os_distribution.keys()
                    ),

                "Vulnerabilities":
                    list(
                        os_distribution.values()
                    ),
            }
        )

        if not os_df.empty:

            fig = px.pie(
                os_df,
                names="Operating System",
                values="Vulnerabilities",
                hole=0.45,
                title="Vulnerabilities by OS"
            )

            fig.update_layout(
                height=350,
                margin=dict(
                    l=20,
                    r=20,
                    t=50,
                    b=20
                )
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        else:

            st.info(
                "No OS distribution data available."
            )

    # =====================================================
    # ROW 2 — REMEDIATION SOURCE + VALIDATION
    # =====================================================

    col1, col2 = st.columns(2)

    # -----------------------------------------------------
    # REMEDIATION SOURCE
    # -----------------------------------------------------

    with col1:

        st.markdown(
            "### Remediation Source Distribution"
        )

        source_distribution = report.get(
            "source_distribution",
            {}
        )

        source_df = pd.DataFrame(
            {
                "Source":
                    list(
                        source_distribution.keys()
                    ),

                "CVEs":
                    list(
                        source_distribution.values()
                    ),
            }
        )

        source_df = source_df[
            source_df["CVEs"] > 0
        ]

        if not source_df.empty:

            fig = px.bar(
                source_df,
                x="Source",
                y="CVEs",
                text="CVEs",
                title="Remediation Retrieval Sources"
            )

            fig.update_layout(
                height=350,
                margin=dict(
                    l=20,
                    r=20,
                    t=50,
                    b=20
                ),
                showlegend=False
            )

            fig.update_traces(
                textposition="outside"
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        else:

            st.info(
                "No remediation source data available."
            )

    # -----------------------------------------------------
    # VALIDATION OUTCOME
    # -----------------------------------------------------

    with col2:

        st.markdown(
            "### Validation Outcome"
        )

        validation_distribution = report.get(
            "validation_distribution",
            {}
        )

        validation_df = pd.DataFrame(
            {
                "Status":
                    list(
                        validation_distribution.keys()
                    ),

                "CVEs":
                    list(
                        validation_distribution.values()
                    ),
            }
        )

        if not validation_df.empty:

            fig = px.pie(
                validation_df,
                names="Status",
                values="CVEs",
                hole=0.45,
                title="Pre-Remediation Validation"
            )

            fig.update_layout(
                height=350,
                margin=dict(
                    l=20,
                    r=20,
                    t=50,
                    b=20
                )
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        else:

            st.info(
                "No validation outcome data available."
            )

    # =====================================================
    # PIPELINE FUNNEL
    # =====================================================

    st.markdown(
        "### 🔄 End-to-End Remediation Pipeline"
    )

    funnel = report.get(
        "pipeline_funnel",
        {}
    )

    funnel_df = pd.DataFrame(
        {
            "Stage":
                list(
                    funnel.keys()
                ),

            "CVEs":
                list(
                    funnel.values()
                ),
        }
    )

    if not funnel_df.empty:

        fig = go.Figure(
            go.Funnel(
                y=funnel_df["Stage"],
                x=funnel_df["CVEs"],
                textinfo="value+percent initial"
            )
        )

        fig.update_layout(
            height=400,
            margin=dict(
                l=30,
                r=30,
                t=30,
                b=30
            )
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    else:

        st.info(
            "No pipeline funnel data available."
        )

    # =====================================================
    # AGENT EXECUTION
    # =====================================================

    st.markdown(
        "### 🤖 Agent Execution & Retrieval"
    )

    agent_execution = report.get(
        "agent_execution",
        {}
    )

    agent_df = pd.DataFrame(
        {
            "Agent":
                list(
                    agent_execution.keys()
                ),

            "Executions / Hits":
                list(
                    agent_execution.values()
                ),
        }
    )

    if not agent_df.empty:

        fig = px.bar(
            agent_df,
            x="Agent",
            y="Executions / Hits",
            text="Executions / Hits",
            title="Agent Activity"
        )

        fig.update_layout(
            height=350,
            margin=dict(
                l=20,
                r=20,
                t=50,
                b=20
            ),
            showlegend=False
        )

        fig.update_traces(
            textposition="outside"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    else:

        st.info(
            "No agent execution data available."
        )

    # =====================================================
    # EXECUTION RESULT TABLE
    # =====================================================

    st.markdown(
        "### 📋 Remediation Execution Summary"
    )

    execution_result = state.get(
        "execution_result",
        {}
    )

    validation_result = state.get(
        "validation_result",
        {}
    )

    rows = []

    for cve in execution_result:

        rows.append(
            {
                "CVE": cve,

                "Validation":
                    validation_result.get(
                        cve,
                        "N/A"
                    ),

                "Execution":
                    execution_result.get(
                        cve,
                        "N/A"
                    ),
            }
        )

    if rows:

        result_df = pd.DataFrame(
            rows
        )

        st.dataframe(
            result_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No execution results available."
        )


# =========================================================
# PIPELINE EXECUTION
# =========================================================

FILE_PATH = "srs_data_sample.xlsx"


if (
    os.path.exists(FILE_PATH)
    and st.session_state.get(
        "auto_remediate_clicked",
        False
    )
):

    step = state["current_step"]

    # -----------------------------------------------------
    # Execute current step
    # -----------------------------------------------------

    if step == 1:

        state = ingestion_agent(
            state
        )

    elif step == 2:

        state = classifier_agent(
            state
        )

    elif step == 3:

        state = os_detection_agent(
            state
        )

    elif step == 4:

        state = remediation_agents(
            state
        )

    elif step == 5:

        state = summarization_agent(
            state
        )

    elif step == 6:

        state = validation_agent(
            state
        )

    elif step == 7:

        state = execution_agent(
            state
        )

    elif step == 8:

        # Generates reporting_metrics
        state = logging_agent(
            state
        )

        st.session_state.auto_remediate_clicked = False

    # -----------------------------------------------------
    # Save updated state
    # -----------------------------------------------------

    st.session_state.pipeline_state = state

    # -----------------------------------------------------
    # Move to next step
    # -----------------------------------------------------

    if step < 8:

        time.sleep(1)

        st.session_state.pipeline_state[
            "current_step"
        ] = step + 1

        st.rerun()

    else:

        st.session_state.pipeline_state[
            "current_step"
        ] = 8

        st.rerun()

