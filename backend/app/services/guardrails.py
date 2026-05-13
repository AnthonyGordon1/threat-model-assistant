import json
import base64
import codecs
from app.services.logger import log_security_event


INJECTION_PATTERNS = [
    "ignore previous instructions",
    "forget your system prompt",
    "you are now",
    "disregard all rules",
    "jailbreak",
    "output your instructions",
    "ignore all previous",
    "act as",
    "reveal your system prompt",
    "forget all instructions",
]

def check_encoded(text: str, ip_address: str = None):
    try:
        decoded_b64 = base64.b64decode(text).decode('utf-8')
        if decoded_b64 != text:
            for pattern in INJECTION_PATTERNS:
                if pattern in decoded_b64.lower():
                    log_security_event(
                        event_type="encoded_injection_base64",
                        ip_address=ip_address,
                        input_text=text,
                        pattern_matched=pattern,
                        status_code=400
                    )
                    raise ValueError("Potential prompt injection detected in encoded input.")
    except ValueError:
        raise
    except Exception:
        pass

    try:
        decoded_rot13 = codecs.decode(text, 'rot_13')
        for pattern in INJECTION_PATTERNS:
            if pattern in decoded_rot13.lower():
                log_security_event(
                    event_type="encoded_injection_rot13",
                    ip_address=ip_address,
                    input_text=text,
                    pattern_matched=pattern,
                    status_code=400
                )
                raise ValueError("Potential prompt injection detected in encoded input.")
    except ValueError:
        raise
    except Exception:
        pass

def check_input(user_input: str, ip_address: str = None):
    for pattern in INJECTION_PATTERNS:
        if pattern in user_input.lower():
            log_security_event(
                event_type="prompt_injection",
                ip_address=ip_address,
                input_text=user_input,
                pattern_matched=pattern,
                status_code=400
            )
            raise ValueError("Potential prompt injection detected.")

    check_encoded(user_input, ip_address)
    return user_input

def check_output(model_output: str):
    threats = json.loads(model_output)
    seen = set()
    unique_threats = []
    for threat in threats:
        if threat["threat"] not in seen:
            seen.add(threat["threat"])
            unique_threats.append(threat)
    return unique_threats