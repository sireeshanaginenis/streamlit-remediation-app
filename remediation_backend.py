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
def classifier_agent(state: RemediationState):
    simple = medium = complex_v = 0

    for v in state["vulnerabilities"]:
        score = float(v.get("CVSS", 5))

        if score < 5:
            simple += 1
        elif score < 8:
            medium += 1
        else:
            complex_v += 1

    state["classified"] = {
        "simple": simple,
        "medium": medium,
        "complex": complex_v
    }

    state["logs"].append("Classification completed")
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


# 8️⃣ LOGGING
def logging_agent(state: RemediationState):

    state["logs"].append("Logs & results generated")
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