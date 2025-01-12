import pinecone
from constants import INDEX_NAME

pinecone.init(
    api_key="6c238e88-50d1-4140-a4f1-8f74a1852ed0",
    environment="eu-west1-gcp"
    # api_key="e36f49bd-fdfc-4a10-8c52-87698f7d4cab",
    # environment="us-west4-gcp-free"
#     api_key="c5777c0b-5f55-45bb-b8c6-0510b4a89d4d",
#     environment="eu-west1-gcp"
)

def createIndex(dimension):
    if 'chatfast' not in pinecone.list_indexes():
        print("creating index")
        pinecone.create_index('chatfast', dimension=dimension)

def saveEmbeddings(vectors):
    index = pinecone.Index('aitools')
    index.upsert(vectors=list(vectors))
    
def queryEmbeddings(vector, user_id):
    index = pinecone.Index('aitools')
    res = index.query(vector, filter={"user_id": {"$eq": user_id}},
                      top_k=1, include_metadata=True)
    return res

def index_content(doc_texts):
    pinecone

def delete_vector(namespace,user_id):
    # Search for vectors with matching metadata
    metadata_key="user_id"
    index = pinecone.Index(INDEX_NAME)
    index.delete(
    namespace=namespace,
    filter={
        "source_id": {"$eq":user_id}
    }
    )

