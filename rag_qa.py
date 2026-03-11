from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
from sentence_transformers import CrossEncoder

# Same embedding model used during ingestion
embeddings = HuggingFaceEmbeddings(
    model_name="BAAI/bge-large-en"
)

reranker = CrossEncoder("BAAI/bge-reranker-large")

def rerank_documents(query, docs, top_k=3):
    pairs = []
    for text in docs["documents"]:
        pairs.append([query, text])

    scores = reranker.predict(pairs)
    scored_docs = list(zip(docs["documents"], docs["metadatas"], scores))
    # sort by score
    ranked = sorted(scored_docs, key=lambda x: x[2], reverse=True)
    return ranked[:top_k]
# Load existing vector DB
vector_db = Chroma(
    collection_name="cve_remediation",
    embedding_function=embeddings,
    persist_directory="./cve_vector_db"
)

# Query
query = "How to remediate CVE-2018-6829"

# Retriever with CVE + Section filter
docs = vector_db.get(
    where={
        "$and":[
            {"cve_id":"CVE-2018-6829"},
            {
                "$or":[
                    {"section":"Technical Implementation Steps"},
                    {"section":"Remediation Procedures"}
                ]
            }
        ]
    }
)

ranked_docs = rerank_documents(query, docs, top_k=3)

for text, meta, score in ranked_docs:

    print("\nCVE:", meta["cve_id"])
    print("SECTION:", meta["section"])
    print("Score:", score)
    print(text)
    print("-----------")

# for text, meta in zip(docs["documents"], docs["metadatas"]):

#     print("\nCVE:", meta["cve_id"])
#     print("SECTION:", meta["section"])
#     print(text)
#     print("-----------")