import os
from langchain_groq import ChatGroq
from app.db.pgvector import get_connection
from app.services.embeddings import get_embeddings
from dotenv import load_dotenv

load_dotenv()


# Step 1: Search similar documents in pgvector using the query embedding
def search_similar_documents(query: str, top_k: int = 20):
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
    return f"""You are a senior security engineer performing a comprehensive STRIDE threat model.

Architecture: {architecture}
Feature: {feature}

Relevant security knowledge:
{context}

Your task is to perform a COMPLETE and SYSTEMATIC threat analysis. You MUST generate at least one threat for EACH of the following STRIDE categories:
- Spoofing
- Tampering  
- Repudiation
- Information Disclosure
- Denial of Service
- Elevation of Privilege

For each major component in the architecture (API layer, database, authentication, file storage, network layer) apply STRIDE and identify threats. Do not stop at 3-5 threats. A complete analysis should produce 8-15 threats minimum.

For each threat return exactly these fields:
- threat: specific description of the threat — not just the category name
- category: one of the six STRIDE categories above
- likelihood: High, Medium, or Low
- mitigation: specific actionable mitigation steps
- mitre_mapping: a single string with MITRE technique ID and name e.g. "T1190 Exploit Public-Facing Application"
- attack_mechanism: a single string describing how an attacker exploits this step by step
- real_world_example: a single string in this exact format: "Company (Year) — What happened in one sentence. Cost: X. Reference: Y"
- kill_chain: array of kill chain stages this enables e.g. ["Initial Access", "Exfiltration"]
- code_example: one paragraph describing the vulnerable pattern(s) to avoid

Return ONLY valid JSON array. No markdown. No explanation. No text before or after. Just the raw JSON array starting with [ and ending with ]."""
# Step 3: Run the prompt through the Ollama LLM to generate a response
def run_rag_pipeline(architecture: str, feature: str):
    # Get the context
    chunks = search_similar_documents(f"{architecture} {feature}")    
    
    # Join the retrieved documents into a single string with newlines in between
    context = "\n\n".join(chunk["content"] for chunk in chunks)
    
    # Build the prompt 
    prompt = build_prompt(architecture, feature, context)
    
    # Create the LLM using the environment variables for the model and base URL
    llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0, max_tokens=8000)
    
    # Send the prompt and return the content of the response
    response = llm.invoke(prompt)
    return response.content
