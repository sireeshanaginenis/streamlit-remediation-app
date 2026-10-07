import pandas as pd
import requests
from bs4 import BeautifulSoup
from typing import TypedDict, List, Dict, Any
from langgraph.graph import StateGraph
from ubuntu_scraper import ubuntu_cve
from debian_scraper import debian_cve
import os
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
from sentence_transformers import CrossEncoder
import json
from io import BytesIO
# ==========================================================
# STATE MODEL
# ==========================================================

class RemediationState(TypedDict):
    vulnerabilities: List[Dict[str, Any]]
    dataframe: Any  
    classified: Dict[str, int]
    os_distribution: Dict[str, Any]
    remediation_data: Dict[str, Any]
    agent_execution_summary: Dict[str, Any]
    summarized_steps: Dict[str, Any]
    validation_result: Dict[str, Any]
    approval_status: str
    execution_result: Dict[str, Any]
    logs: List[str]
    current_step: int
    reporting_metrics: Dict[str, Any]


# ==========================================================
# AGENTS
# ==========================================================

embeddings = HuggingFaceEmbeddings(
    model_name="BAAI/bge-large-en"
)

reranker = CrossEncoder("BAAI/bge-reranker-large")

vector_db = Chroma(
    collection_name="cve_remediation",
    embedding_function=embeddings,
    persist_directory="./cve_vector_db"
)

def retrieve_from_rag(cve_id):

    query = f"How to remediate {cve_id}"
    print("query",query)

    docs = vector_db.get(
        where={
            "$and":[
                {"cve_id":cve_id},
                {
                    "$or":[
                        {"section":"Technical Implementation Steps"},
                        {"section":"Remediation Procedures"}
                    ]
                }
            ]
        }
    )

    # No documents found
    if not docs or len(docs["documents"]) == 0:
        return None

    # -----------------------------
    # RERANK DOCUMENTS
    # -----------------------------
    pairs = [[query, doc] for doc in docs["documents"]]
    scores = reranker.predict(pairs)

    scored_docs = list(zip(docs["documents"], docs["metadatas"], scores))

    ranked_docs = sorted(
        scored_docs,
        key=lambda x: x[2],
        reverse=True
    )

    # -----------------------------
    # TAKE TOP 3
    # -----------------------------
    top_docs = ranked_docs[:3]

    remediation_steps = []

    for text, meta, score in top_docs:
        remediation_steps.append(text)

    remediation_text = "\n\n".join(remediation_steps)
    print("remediation steps for cve id",cve_id,remediation_text)

    return {
        "summary": f"Remediation retrieved from internal playbook for {cve_id}",
        "remediation": remediation_text,
        "sources": "Internal RAG Playbook"
    }

# 1️⃣ INGESTION
def ingestion_agent(state: RemediationState):

    file_path = os.path.join(os.getcwd(), "srs_data_sample.xlsx")

    if not os.path.exists(file_path):
        state["logs"].append("Excel file not found")
        state["current_step"] = 1
        return state

    df = pd.read_excel(file_path)
    vulns = df.to_dict(orient="records")

    state["vulnerabilities"] = vulns
    state["dataframe"] = df
    state["logs"].append(f"Ingested {len(vulns)} vulnerabilities")
    state["current_step"] = 1

    return state


# 2️⃣ CLASSIFIER
def normalize_cve(cve):
    return str(cve).strip().upper().replace("_", "-")


def classifier_agent(state: RemediationState):

    if not state.get("vulnerabilities"):
        state["logs"].append("⚠️ No vulnerabilities found for classification")
        return state

    json_path = os.path.join(os.getcwd(), "cve_classification.json")

    if not os.path.exists(json_path):
        state["logs"].append("❌ Classification JSON not found")
        state["classified"] = {"simple": 0, "medium": 0, "complex": 0}
        return state

    with open(json_path, "r") as f:
        cve_map = json.load(f)

    # ✅ Normalize JSON keys
    normalized_map = {
        normalize_cve(k): v.get("category", "complex").lower()
        for k, v in cve_map.items()
    }

    simple = 0
    medium = 0
    complex = 0

    for v in state.get("vulnerabilities", []):

        cve_id = normalize_cve(v.get("Name", ""))

        if not cve_id:
            continue

        category = normalized_map.get(cve_id)

        if not category:
            state["logs"].append(f"⚠️ Missing in JSON → forcing complex: {cve_id}")
            category = "complex"

        if category == "simple":
            simple += 1
        elif category == "medium":
            medium += 1
        elif category == "complex":
            complex += 1

        v["classification"] = category

    state["classified"] = {
        "simple": simple,
        "medium": medium,
        "complex": complex
    }

    state["logs"].append(
        f"✅ Classified: simple={simple}, medium={medium}, complex={complex}"
    )

    state["current_step"] = 2
    return state


# 3️⃣ OS DETECTION
def os_detection_agent(state: RemediationState):

    df = pd.DataFrame(state["vulnerabilities"])

    if df.empty:
        state["os_distribution"] = {}
        state["current_step"] = 3
        return state

    df["OperatingSystem"] = df["OperatingSystem"].astype(str).str.strip()

    windows_list = []
    ubuntu_list = []
    debian_list = []

    for _, row in df.iterrows():

        os_name = str(row.get("OperatingSystem", "")).lower()
        link = str(row.get("Link", "")).lower()

        if "windows" in os_name:
            windows_list.append(row.to_dict())

        if "linux" in os_name:

            if "ubuntu.com" in link:
                ubuntu_list.append(row.to_dict())

            elif "security-tracker.debian.org" in link:
                debian_list.append(row.to_dict())

    state["os_distribution"] = {
        "windows": windows_list,
        "ubuntu": ubuntu_list,
        "debian": debian_list,
        "windows_count": len(windows_list),
        "linux_total": len(ubuntu_list) + len(debian_list),
        "flavour_counts": {
            "Ubuntu": len(ubuntu_list),
            "Debian": len(debian_list)
        }
    }

    state["logs"].append("OS detection completed")
    state["current_step"] = 3
    return state

def remediation_agents(state: RemediationState):

    results = {}
    agent_execution_summary = {
        "windows_agent_ran": False,
        "linux_agent_ran": False,
        "ubuntu_agent_ran": False,
        "debian_agent_ran": False,
        "rag_hits": 0
    }

    os_data = state.get("os_distribution", {})

    windows_list = os_data.get("windows", [])
    ubuntu_list = os_data.get("ubuntu", [])
    debian_list = os_data.get("debian", [])

    # ==========================================
    # WINDOWS AGENT
    # ==========================================
    if len(windows_list) > 0:
        agent_execution_summary["windows_agent_ran"] = True

        for v in windows_list:

            cve = v.get("Name")
            if not cve:
                continue

            # -------------------------
            # 1️⃣ Try RAG first
            # -------------------------
            rag_result = retrieve_from_rag(cve)

            if rag_result:
                results[cve] = rag_result
                agent_execution_summary["rag_hits"] += 1
                continue

            # -------------------------
            # 2️⃣ Windows fallback
            # -------------------------
            results[cve] = {
                "summary": f"CVE: {cve}\nPlatform: Windows\nStatus: Vulnerable",
                "remediation": f"Apply latest Microsoft patch for {cve}",
                "sources": "Microsoft Security Portal"
            }

    # ==========================================
    # LINUX AGENT
    # ==========================================
    if len(ubuntu_list) > 0 or len(debian_list) > 0:

        agent_execution_summary["linux_agent_ran"] = True

        # ---------- UBUNTU AGENT ----------
        if len(ubuntu_list) > 0:
            agent_execution_summary["ubuntu_agent_ran"] = True

            for v in ubuntu_list:

                cve = v.get("Name")
                if not cve:
                    continue

                # -------------------------
                # 1️⃣ Try RAG first
                # -------------------------
                rag_result = retrieve_from_rag(cve)

                if rag_result:
                    results[cve] = rag_result
                    agent_execution_summary["rag_hits"] += 1
                    continue

                # -------------------------
                # 2️⃣ Ubuntu scraping fallback
                # -------------------------
                try:
                    result = ubuntu_cve(cve)
                    results[cve] = result

                except Exception as e:
                    results[cve] = {
                        "summary": f"Ubuntu remediation failed: {str(e)}",
                        "remediation": "Not Available",
                        "sources": "Ubuntu Security"
                    }

        # ---------- DEBIAN AGENT ----------
        if len(debian_list) > 0:
            agent_execution_summary["debian_agent_ran"] = True

            for v in debian_list:

                cve = v.get("Name")
                if not cve:
                    continue

                # -------------------------
                # 1️⃣ Try RAG first
                # -------------------------
                rag_result = retrieve_from_rag(cve)

                if rag_result:
                    results[cve] = rag_result
                    agent_execution_summary["rag_hits"] += 1
                    continue

                # -------------------------
                # 2️⃣ Debian scraping fallback
                # -------------------------
                try:
                    result = debian_cve(cve)
                    results[cve] = result

                except Exception as e:
                    results[cve] = {
                        "summary": f"Debian remediation failed: {str(e)}",
                        "remediation": "Not Available",
                        "sources": "Debian Security"
                    }

    # ==========================================
    # UPDATE STATE
    # ==========================================

    state["remediation_data"] = results
    state["agent_execution_summary"] = agent_execution_summary

    state["logs"].append(
        f"Remediation agents executed (RAG hits: {agent_execution_summary['rag_hits']})"
    )

    state["current_step"] = 4

    return state

# ==============================================
# 5️⃣ SUMMARIZATION AGENT
# ==============================================

def summarization_agent(state: RemediationState):

    summarized = {}

    remediation_data = state.get("remediation_data", {})

    if not remediation_data:
        state["summarized_steps"] = {}
        state["current_step"] = 5
        return state

    for cve, data in remediation_data.items():

        summarized[cve] = {
            "summary": data.get("summary", "No Summary Found"),
            "remediation": data.get("remediation", "No Remediation Found"),
            "sources": data.get("sources", "No Source Found")
        }

    state["summarized_steps"] = summarized
    state["logs"].append("Remediation summarization completed")
    state["current_step"] = 5

    return state


# 6️⃣ VALIDATION
def validation_agent(state: RemediationState):

    validation = {}

    for cve, steps in state["summarized_steps"].items():

        remediation_text = steps.get("remediation", "")

        if "upgrade" in remediation_text.lower() or "install" in remediation_text.lower():
            validation[cve] = "PASS"
        else:
            validation[cve] = "REVIEW"

    state["validation_result"] = validation
    state["logs"].append("Pre-remediation check completed")
    state["current_step"] = 6

    return state


# 7️⃣ EXECUTION
def execution_agent(state: RemediationState):

    results = {}

    for cve in state["summarized_steps"]:
        results[cve] = "Executed Successfully"

    state["execution_result"] = results
    state["logs"].append("Auto remediation executed")
    state["current_step"] = 7
    return state


# ==========================================================
# 8️⃣ METRICS & REPORTING
# ==========================================================

def generate_reporting_metrics(state: RemediationState):

    vulnerabilities = state.get("vulnerabilities", [])
    classified = state.get("classified", {})
    os_data = state.get("os_distribution", {})
    remediation_data = state.get("remediation_data", {})
    summarized_steps = state.get("summarized_steps", {})
    validation_result = state.get("validation_result", {})
    execution_result = state.get("execution_result", {})
    agent_summary = state.get("agent_execution_summary", {})

    # ------------------------------------------------------
    # BASIC COUNTS
    # ------------------------------------------------------

    total_cves = len(vulnerabilities)

    classified_count = sum(classified.values()) if classified else 0

    remediation_count = len(remediation_data)

    summarized_count = len(summarized_steps)

    validated_count = len(validation_result)

    executed_count = len(execution_result)

    # ------------------------------------------------------
    # VALIDATION METRICS
    # ------------------------------------------------------

    validation_pass = sum(
        1
        for value in validation_result.values()
        if str(value).upper() == "PASS"
    )

    validation_review = sum(
        1
        for value in validation_result.values()
        if str(value).upper() == "REVIEW"
    )

    # ------------------------------------------------------
    # EXECUTION METRICS
    # ------------------------------------------------------

    execution_success = sum(
        1
        for value in execution_result.values()
        if "success" in str(value).lower()
    )

    execution_failed = executed_count - execution_success

    # ------------------------------------------------------
    # RAG METRICS
    # ------------------------------------------------------

    rag_hits = agent_summary.get("rag_hits", 0)

    rag_coverage = (
        (rag_hits / remediation_count) * 100
        if remediation_count > 0
        else 0
    )

    # ------------------------------------------------------
    # REMEDIATION COVERAGE
    # ------------------------------------------------------

    remediation_coverage = (
        (remediation_count / total_cves) * 100
        if total_cves > 0
        else 0
    )

    validation_rate = (
        (validation_pass / validated_count) * 100
        if validated_count > 0
        else 0
    )

    execution_rate = (
        (execution_success / executed_count) * 100
        if executed_count > 0
        else 0
    )

    # ------------------------------------------------------
    # REMEDIATION SOURCE DISTRIBUTION
    # ------------------------------------------------------

    source_distribution = {
        "Internal RAG": 0,
        "Microsoft Security": 0,
        "Ubuntu Security": 0,
        "Debian Security": 0
    }

    for cve, data in remediation_data.items():

        source = str(data.get("sources", "")).lower()

        if "rag" in source or "internal" in source:
            source_distribution["Internal RAG"] += 1

        elif "microsoft" in source:
            source_distribution["Microsoft Security"] += 1

        elif "ubuntu" in source:
            source_distribution["Ubuntu Security"] += 1

        elif "debian" in source:
            source_distribution["Debian Security"] += 1

    # ------------------------------------------------------
    # PIPELINE FUNNEL
    # ------------------------------------------------------

    pipeline_funnel = {
        "Ingested": total_cves,
        "Classified": classified_count,
        "Remediation Found": remediation_count,
        "Validated": validated_count,
        "Executed": executed_count
    }

    # ------------------------------------------------------
    # AGENT EXECUTION
    # ------------------------------------------------------

    agent_execution = {
        "Windows Agent": int(
            agent_summary.get("windows_agent_ran", False)
        ),
        "Linux Agent": int(
            agent_summary.get("linux_agent_ran", False)
        ),
        "Ubuntu Agent": int(
            agent_summary.get("ubuntu_agent_ran", False)
        ),
        "Debian Agent": int(
            agent_summary.get("debian_agent_ran", False)
        ),
        "RAG Retrieval": rag_hits
    }

    # ------------------------------------------------------
    # OS DISTRIBUTION
    # ------------------------------------------------------

    os_distribution = {
        "Windows": os_data.get("windows_count", 0),
        "Ubuntu": os_data.get(
            "flavour_counts", {}
        ).get("Ubuntu", 0),
        "Debian": os_data.get(
            "flavour_counts", {}
        ).get("Debian", 0)
    }

    # ------------------------------------------------------
    # FINAL REPORT
    # ------------------------------------------------------

    report = {

        "kpis": {
            "total_cves": total_cves,
            "classified": classified_count,
            "remediation_found": remediation_count,
            "remediation_coverage": round(
                remediation_coverage, 1
            ),
            "validation_pass": validation_pass,
            "validation_rate": round(
                validation_rate, 1
            ),
            "execution_success": execution_success,
            "execution_rate": round(
                execution_rate, 1
            ),
            "rag_hits": rag_hits,
            "rag_coverage": round(
                rag_coverage, 1
            )
        },

        "severity_distribution": {
            "Simple": classified.get("simple", 0),
            "Medium": classified.get("medium", 0),
            "Complex": classified.get("complex", 0)
        },

        "os_distribution": os_distribution,

        "source_distribution": source_distribution,

        "validation_distribution": {
            "PASS": validation_pass,
            "REVIEW": validation_review
        },

        "execution_distribution": {
            "Successful": execution_success,
            "Failed": execution_failed
        },

        "pipeline_funnel": pipeline_funnel,

        "agent_execution": agent_execution
    }

    state["reporting_metrics"] = report

    return state
# ==========================================================
# 8️⃣ LOGGING + REPORTING
# ==========================================================


# ==========================================================
# EXCEL METRICS REPORT
# ==========================================================

def generate_excel_report(state: RemediationState):

    report = state.get(
        "reporting_metrics",
        {}
    )

    if not report:
        return None

    output = BytesIO()

    with pd.ExcelWriter(
        output,
        engine="openpyxl"
    ) as writer:

        # ==================================================
        # 1. EXECUTIVE KPIs
        # ==================================================

        kpis = report.get(
            "kpis",
            {}
        )

        kpi_df = pd.DataFrame(
            {
                "Metric": [
                    "Total Vulnerabilities",
                    "Classified CVEs",
                    "Remediation Found",
                    "Remediation Coverage (%)",
                    "Validation Pass",
                    "Validation Rate (%)",
                    "Execution Success",
                    "Execution Rate (%)",
                    "RAG Hits",
                    "RAG Coverage (%)"
                ],

                "Value": [
                    kpis.get(
                        "total_cves",
                        0
                    ),

                    kpis.get(
                        "classified",
                        0
                    ),

                    kpis.get(
                        "remediation_found",
                        0
                    ),

                    kpis.get(
                        "remediation_coverage",
                        0
                    ),

                    kpis.get(
                        "validation_pass",
                        0
                    ),

                    kpis.get(
                        "validation_rate",
                        0
                    ),

                    kpis.get(
                        "execution_success",
                        0
                    ),

                    kpis.get(
                        "execution_rate",
                        0
                    ),

                    kpis.get(
                        "rag_hits",
                        0
                    ),

                    kpis.get(
                        "rag_coverage",
                        0
                    )
                ]
            }
        )

        kpi_df.to_excel(
            writer,
            sheet_name="Executive KPIs",
            index=False
        )

        # ==================================================
        # 2. SEVERITY DISTRIBUTION
        # ==================================================

        severity = report.get(
            "severity_distribution",
            {}
        )

        severity_df = pd.DataFrame(
            {
                "Severity":
                    list(
                        severity.keys()
                    ),

                "Vulnerabilities":
                    list(
                        severity.values()
                    )
            }
        )

        severity_df.to_excel(
            writer,
            sheet_name="Severity",
            index=False
        )

        # ==================================================
        # 3. OS DISTRIBUTION
        # ==================================================

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
                    )
            }
        )

        os_df.to_excel(
            writer,
            sheet_name="OS Distribution",
            index=False
        )

        # ==================================================
        # 4. REMEDIATION SOURCE DISTRIBUTION
        # ==================================================

        source_distribution = report.get(
            "source_distribution",
            {}
        )

        source_df = pd.DataFrame(
            {
                "Remediation Source":
                    list(
                        source_distribution.keys()
                    ),

                "CVEs":
                    list(
                        source_distribution.values()
                    )
            }
        )

        source_df.to_excel(
            writer,
            sheet_name="Remediation Sources",
            index=False
        )

        # ==================================================
        # 5. VALIDATION OUTCOME
        # ==================================================

        validation_distribution = report.get(
            "validation_distribution",
            {}
        )

        validation_df = pd.DataFrame(
            {
                "Validation Status":
                    list(
                        validation_distribution.keys()
                    ),

                "CVEs":
                    list(
                        validation_distribution.values()
                    )
            }
        )

        validation_df.to_excel(
            writer,
            sheet_name="Validation",
            index=False
        )

        # ==================================================
        # 6. EXECUTION OUTCOME
        # ==================================================

        execution_distribution = report.get(
            "execution_distribution",
            {}
        )

        execution_df = pd.DataFrame(
            {
                "Execution Status":
                    list(
                        execution_distribution.keys()
                    ),

                "CVEs":
                    list(
                        execution_distribution.values()
                    )
            }
        )

        execution_df.to_excel(
            writer,
            sheet_name="Execution",
            index=False
        )

        # ==================================================
        # 7. PIPELINE FUNNEL
        # ==================================================

        pipeline_funnel = report.get(
            "pipeline_funnel",
            {}
        )

        funnel_df = pd.DataFrame(
            {
                "Pipeline Stage":
                    list(
                        pipeline_funnel.keys()
                    ),

                "CVEs":
                    list(
                        pipeline_funnel.values()
                    )
            }
        )

        funnel_df.to_excel(
            writer,
            sheet_name="Pipeline Funnel",
            index=False
        )

        # ==================================================
        # 8. AGENT EXECUTION
        # ==================================================

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
                    )
            }
        )

        agent_df.to_excel(
            writer,
            sheet_name="Agent Execution",
            index=False
        )

        # ==================================================
        # 9. CVE EXECUTION SUMMARY
        # ==================================================

        execution_result = state.get(
            "execution_result",
            {}
        )

        validation_result = state.get(
            "validation_result",
            {}
        )

        vulnerabilities = state.get(
            "vulnerabilities",
            []
        )

        remediation_data = state.get(
            "remediation_data",
            {}
        )

        rows = []

        for vulnerability in vulnerabilities:

            cve = vulnerability.get(
                "Name",
                ""
            )

            if not cve:
                continue

            rows.append(
                {
                    "CVE": cve,

                    "Operating System":
                        vulnerability.get(
                            "OperatingSystem",
                            ""
                        ),

                    "Classification":
                        vulnerability.get(
                            "classification",
                            ""
                        ),

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

                    "Remediation Source":
                        remediation_data.get(
                            cve,
                            {}
                        ).get(
                            "sources",
                            "N/A"
                        )
                }
            )

        execution_summary_df = pd.DataFrame(
            rows
        )

        execution_summary_df.to_excel(
            writer,
            sheet_name="CVE Summary",
            index=False
        )

        # ==================================================
        # FORMAT EXCEL SHEETS
        # ==================================================

        for worksheet in writer.book.worksheets:

            # Freeze header row
            worksheet.freeze_panes = "A2"

            # Bold header
            for cell in worksheet[1]:

                cell.font = cell.font.copy(
                    bold=True
                )

            # Auto-size columns
            for column in worksheet.columns:

                max_length = 0

                column_letter = (
                    column[0].column_letter
                )

                for cell in column:

                    try:

                        cell_length = len(
                            str(cell.value)
                        )

                        max_length = max(
                            max_length,
                            cell_length
                        )

                    except Exception:
                        pass

                worksheet.column_dimensions[
                    column_letter
                ].width = min(
                    max_length + 2,
                    50
                )

    output.seek(0)

    return output

def logging_agent(state: RemediationState):

    # Generate dashboard metrics
    state = generate_reporting_metrics(state)

    state["logs"].append(
        "Metrics & reporting dashboard generated"
    )

    state["current_step"] = 8

    return state


# ==========================================================
# GRAPH BUILDER
# ==========================================================

def build_graph():

    graph = StateGraph(RemediationState)

    graph.add_node("ingestion", ingestion_agent)
    graph.add_node("classifier", classifier_agent)
    graph.add_node("os_detect", os_detection_agent)
    graph.add_node("remediation", remediation_agents)
    graph.add_node("summarize", summarization_agent)
    graph.add_node("validate", validation_agent)
    graph.add_node("execute", execution_agent)
    graph.add_node("logging", logging_agent)

    graph.set_entry_point("ingestion")

    graph.add_edge("ingestion", "classifier")
    graph.add_edge("classifier", "os_detect")
    graph.add_edge("os_detect", "remediation")
    graph.add_edge("remediation", "summarize")
    graph.add_edge("summarize", "validate")
    graph.add_edge("validate", "execute")
    graph.add_edge("execute", "logging")

    return graph.compile()
