import json


INJECTION_PATTERNS = [
    "ignore previous instructions",
    "forget your system prompt",
    "you are now",
    "disregard all rules",
    "jailbreak",
    "output your instructions",
    "ignore all previous",
    "act as",
]

def check_input(user_input: str): 
    for pattern in INJECTION_PATTERNS:
        if pattern in user_input.lower():
            raise ValueError("Potential prompt injection detected.")
    return user_input

def check_output(model_output: str):
    threats =json.loads(model_output)
    seen = set()
    unique_threats = []
    for threat in threats:
        if threat["threat"] not in seen:
            seen.add(threat["threat"])
            unique_threats.append(threat)
    
    return unique_threats