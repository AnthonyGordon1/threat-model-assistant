import os
from langchain_groq import ChatGroq
from app.db.pgvector import get_connection
from app.services.embeddings import get_embeddings
from dotenv import load_dotenv

load_dotenv()


# Step 1: Search similar documents in pgvector using the query embedding
def search_similar_documents(query: str, top_k: int = 5):
     # Convert query text using Ollama
    embeddings = get_embeddings()
    query_vector = embeddings.embed_query(query)
    
    conn = get_connection()
    cursor = conn.cursor() 
    
    # Send that vector to pgvector, which 
    # compares it against every stored embedding using <=>
    cursor.execute("""
        SELECT content, source 
        FROM documents 
        ORDER BY embedding <=> %s::vector 
        LIMIT %s
        """,(query_vector, top_k))
        
    results = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return results

# Step 2: Build a prompt that includes the retrieved documents and the original query
def build_prompt(architecture: str, feature: str, context: str):
    # Write the prompt
    return f"""You are a security expert using STRIDE to identify threats in software systems.

Architecture: {architecture}
Feature: {feature}

Relevant security knowledge:
{context}

Return a JSON array of threats. Each threat must have exactly these fields:
- threat: specific description of the threat (not just the category name)
- category: one of Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
- likelihood: High, Medium, or Low
- mitigation: specific mitigation steps for this threat
- mitre_mapping: a single string with the MITRE technique ID and name e.g. "T1190 Exploit Public-Facing Application"
- attack_mechanism: a single string describing how an attacker exploits this step by step
- real_world_example: a real breach or incident where this threat was exploited
- kill_chain: array of kill chain stages this threat enables e.g. ["Initial Access", "Exfiltration"]
- code_example: a one sentence description of the vulnerable pattern to avoid

Return ONLY valid JSON. No markdown. No explanation. Just the JSON array."""
# Step 3: Run the prompt through the Ollama LLM to generate a response
def run_rag_pipeline(architecture: str, feature: str):
    # Get the context
    chunks = search_similar_documents(f"{architecture} {feature}")    
    
    # Join the retrieved documents into a single string with newlines in between
    context = "\n\n".join(chunk["content"] for chunk in chunks)
    
    # Build the prompt 
    prompt = build_prompt(architecture, feature, context)
    
    # Create the LLM using the environment variables for the model and base URL
    llm = ChatGroq(model="llama-3.1-8b-instant", temperature=0, max_tokens=4000)
    
    # Send the prompt and return the content of the response
    response = llm.invoke(prompt)
    return response.content
