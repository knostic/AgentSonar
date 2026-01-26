#!/usr/bin/env python3
"""
Simple domain-based classifier for sai.
Reads JSON lines from stdin, writes ai_score scores to stdout.
"""

import json
import sys

AI_DOMAIN_PATTERNS = [
    "openai.com",
    "anthropic.com",
    "cohere.ai",
    "huggingface.co",
    "replicate.com",
]

def score_domain(domain):
    domain = domain.lower()
    for pattern in AI_DOMAIN_PATTERNS:
        if domain.endswith(pattern):
            return 0.8
    if "ai" in domain or "llm" in domain or "gpt" in domain:
        return 0.5
    return 0.0

def main():
    for line in sys.stdin:
        try:
            data = json.loads(line)
            domain = data.get("domain", "")
            ai_score = score_domain(domain)
            print(json.dumps({"ai_score": ai_score}), flush=True)
        except json.JSONDecodeError:
            print(json.dumps({"ai_score": 0}), flush=True)

if __name__ == "__main__":
    main()
