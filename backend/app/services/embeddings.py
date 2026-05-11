import os
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_ollama import OllamaEmbeddings
from app.db.pgvector import get_connection
from dotenv import load_dotenv

load_dotenv()

KNOWLEDGE_BASE_PATH = os.path.join(os.path.dirname(__file__), "../../data/knowledge_base")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL")

#Get the embedding object read to convert text into vectors
def get_embeddings(): 
    return OllamaEmbeddings(
        model="nomic-embed-text",
        base_url=OLLAMA_BASE_URL
    )

#Saves the chunk text, its vector, and the source filename to PostgreSQL
# %s is a placeholder — psycopg2 safely substitutes the values to prevent SQL injection
def ingest_documents():
    # Step 1: Load the documents from the knowledge base directory
    loader = DirectoryLoader(
        KNOWLEDGE_BASE_PATH, 
        glob="**/*.md",
        loader_cls=TextLoader
    )
    documents = loader.load()
    
    # Step 2: Split the document into chunks bc LLMS get overwhelmed with too much text at once. 
    # We want to break it into smaller pieces (chunks) that are easier to process. 
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=500, 
        chunk_overlap=50
    )
    chunks = splitter.split_documents(documents)
    
    # Step 3: Create the embeddings object
    embeddings = get_embeddings()
    
    # Step 4: Open a connection to the PostgreSQL database
    conn = get_connection()
    cursor = conn.cursor()
    
    # Step 5: For each chunk, generate its embedding vector and insert the chunk
    for chunk in chunks: 
        #Convert the chunk of text into a vector
        embedding = embeddings.embed_query(chunk.page_content)
        
        # Step 6: Save to PostgreSQL
        cursor.execute(
            "INSERT INTO documents (content, embedding, source) VALUES (%s, %s, %s)",
            (chunk.page_content, embedding, chunk.metadata.get("source", "unknown"))
        ) 
    # Step 7: Commit and close
    conn.commit()
    cursor.close()
    conn.close()
    # Step 8: Print a message confirming the ingestion is complete
    print(f"Ingested {len(chunks)} chunks into pgvector")

if __name__ == "__main__":
    ingest_documents()
