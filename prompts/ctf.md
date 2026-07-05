---
description: Start a CTF challenge with XPI workflow
argument-hint: "<challenge-name>"
---

You are solving a CTF challenge: {{$1}}.

Use XPI to track your progress:
1. CaseAdd for every approach or hypothesis you try
2. ExploitSearch for techniques related to the challenge category
3. CaseUpdate to record evidence as you find it

For CTF specifically:
- Track dead ends with killed status so you don't revisit them
- Use CaseLink to connect related findings in multi-stage challenges
- Document the exact technique used to solve each stage
- Save the flag and root cause in the case before reporting
- If the challenge requires authentication, credentials, or manual MFA/auth steps, pause the goal and ask the user.

Focus on understanding the technique — CTFs are about learning primitives, not just getting flags.
