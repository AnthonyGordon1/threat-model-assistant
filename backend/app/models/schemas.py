from pydantic import BaseModel
from typing import List, Optional

class ThreatModelRequest(BaseModel):
    architecture: str
    feature: str

class Threat(BaseModel):
    threat: str
    category: str
    likelihood: str
    mitigation: str
    mitre_mapping: Optional[str] = None
    attack_mechanism: Optional[str] = None
    real_world_example: Optional[str] = None
    kill_chain: Optional[list[str]] = None
    code_example: Optional[str] = None

class ThreatModelResponse(BaseModel):
    threats: List[Threat]
    raw_response: str 