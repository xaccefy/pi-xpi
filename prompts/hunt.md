---
description: Automated bug hunting pipeline - auditor finds flaws, exploit-dev verifies with a PoC
---
Launch a sequential audit using the Agent tool:

1. First, call Agent with subagent_type "auditor" to scan the codebase for security flaws or reachability paths matching: $@
2. Then, call Agent with subagent_type "exploit-dev" to write and execute a local PoC verifying the auditor's finding from the previous step.
