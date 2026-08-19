---
description: Conduct broad, multi-source, citation-heavy research with Arlong. Use for comparisons, high-stakes questions, technical investigations, or requests that need corroboration across independent sources.
---

# Deep research with Arlong

Use `arlong_deep` with 15 to 20 results. Prefer official or academic sources when the question calls for them. Inspect the returned relevance, reputation, threat, and corroboration fields before writing.

Do not treat the number of retrieved pages as agreement. Prefer independent domains and primary evidence. Do not synthesize or cite blocked sources. Clearly separate supported findings, disagreements, and evidence gaps. If a page is needed in full, call `arlong_extract` only after it passes Arlong's security gate.

Research question: $ARGUMENTS
