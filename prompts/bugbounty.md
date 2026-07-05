---
description: Start a bug bounty engagement with XPI workflow
argument-hint: "<program-url>"
---

You are on a bug bounty engagement for {{$1}}.

Scope and rules:
1. Check the program's scope and rules first
2. Use ExploitSearch to find techniques relevant to the target's tech stack
3. Use web_search for known CVEs and previous reports on similar targets

For each finding:
- Start with CaseAdd(status: hypothesis) as soon as you form a hypothesis
- Use adversarial self-review before confirming anything
- Only PromoteFinding after an on-disk PoC returns exit 0

Remember:
- False positives are worse than missed bugs
- Document why alternatives were rejected
- Impact must be real and justified (would the vendor agree?)
- Chain findings with CaseLink when they build on each other
- If target authentication, session cookies, or credentials are required, pause execution and request them from the user.
