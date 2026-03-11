from docx import Document
import re

from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings


path = r"Playbooks for remediation of identified CVEs for Azure Function Apps 2.docx"


# -----------------------------
# READ DOCX
# -----------------------------
def read_file(path):

    doc = Document(path)

    paragraphs = []
    buffer = ""

    for p in doc.paragraphs:

        text = p.text.strip()

        if not text:
            continue

        # If line is only a list number like "1." or "2."
        if re.match(r"^\d+\.$", text):
            buffer += text + " "
            continue

        # If previous buffer contains a number prefix
        if buffer:
            buffer += text
            paragraphs.append(buffer.strip())
            buffer = ""
            continue

        # Normal paragraph
        paragraphs.append(text)

    # Flush remaining buffer
    if buffer:
        paragraphs.append(buffer.strip())

    return "\n".join(paragraphs)


# -----------------------------
# SPLIT BY CVE
# -----------------------------
def split_by_cve(document):

    pattern = r"\n(CVE-\d{4}-\d+)"
   # splits = re.split(pattern, document)
    splits = re.split(pattern, "\n" + document)

    cve_sections = []

    for i in range(1, len(splits), 2):

        cve_id = splits[i]
        content = splits[i + 1]

        cve_sections.append({
            "cve_id": cve_id,
            "content": content.strip()
        })

    return cve_sections


# -----------------------------
# SPLIT BY SECTION HEADERS
# -----------------------------
def split_sections(text):

  #  section_pattern = r"(Scope|Technical Implementation Steps|Manual Remediation Process|Remediation Steps|Automation|Change Management.*|Verification|Reference.*)"
    section_pattern = r"(?m)^(Scope|Technical Implementation Steps|Manual Remediation Process|Remediation Steps|Automation|Change Management and Documentation|Verification|Reference|References)$"
    matches = list(re.finditer(section_pattern, text))

    sections = []

    for i in range(len(matches)):

        start = matches[i].end()

        if i + 1 < len(matches):
            end = matches[i + 1].start()
        else:
            end = len(text)

        section_name = matches[i].group()
        section_text = text[start:end].strip()

        sections.append({
            "section": section_name,
            "text": section_text
        })

    return sections


def create_chunks(cve_sections):

    all_chunks = []

    for cve in cve_sections:

        sections = split_sections(cve["content"])

        for i, section in enumerate(sections):

            all_chunks.append({
                "text": section["text"],
                "metadata": {
                    "cve_id": cve["cve_id"],
                    "section": section["section"],
                    "chunk_id": i,
                    "source": "cve_playbook"
                }
            })

    return all_chunks


# -----------------------------
# EMBEDDING MODEL
# -----------------------------
embeddings = HuggingFaceEmbeddings(
    model_name="BAAI/bge-large-en"
)


# -----------------------------
# VECTOR DATABASE
# -----------------------------

# clear old data
vector_db = Chroma(
    collection_name="cve_remediation",
    embedding_function=embeddings,
    persist_directory="./cve_vector_db"
)
vector_db.delete_collection()

vector_db = Chroma(
    collection_name="cve_remediation",
    embedding_function=embeddings,
    persist_directory="./cve_vector_db"
)


# -----------------------------
# INSERT INTO VECTOR DB
# -----------------------------
def insert_into_db(chunks):

    texts = [c["text"] for c in chunks]
    metadatas = [c["metadata"] for c in chunks]

    vector_db.add_texts(
        texts=texts,
        metadatas=metadatas
    )

  #  vector_db.persist()


# -----------------------------
# INGESTION PIPELINE
# -----------------------------
document = read_file(path)

cve_sections = split_by_cve(document)

chunks = create_chunks(cve_sections)

insert_into_db(chunks)

print("Ingestion Complete")


# -----------------------------
# RETRIEVAL
# -----------------------------

# # Query
# query = "How to remediate CVE-2013-3900"

# # Retriever with CVE + Section filter
# docs = vector_db.get(
#     where={
#         "$and":[
#             {"cve_id":"CVE-2013-3900"},
#             {
#                 "$or":[
#                     {"section":"Technical Implementation Steps"},
#                     {"section":"Manual Remediation Process"}
#                 ]
#             }
#         ]
#     }
# )
# for text, meta in zip(docs["documents"], docs["metadatas"]):

#     print("\nCVE:", meta["cve_id"])
#     print("SECTION:", meta["section"])
#     print(text)
#     print("-----------")