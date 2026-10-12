"""The admin "LLM Providers" section (the multi-provider Add LLM Provider flow: OpenAI/Anthropic/OpenRouter/Grok/
Mistral/Ollama) must be its own card, separate from "Remote Ollama Configuration" — not nested inside it. Nesting it
made a general, any-provider feature look like an Ollama-only sub-feature, which is exactly the bug a user hit ("I
only see Remote Ollama, no other Providers").

  python tests/test_admin_llm_providers_card.py
"""
import os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)

ADMIN_PAGE = os.path.join(ROOT, "..", "frontend", "src", "app", "(app)", "admin", "page.tsx")
SRC = open(ADMIN_PAGE, encoding="utf-8").read()

t("the admin page has an 'LLM Providers' heading (its own section, not folded into Ollama's)",
  "LLM Providers</h3>" in SRC)
t("its description names multiple real providers, not just Ollama",
  all(p in SRC for p in ["OpenAI", "Anthropic", "OpenRouter", "Grok", "Mistral"]))
t("the description no longer falsely claims these profiles only use the Remote Ollama endpoint",
  "profiles that use this Remote Ollama endpoint" not in SRC)

# structural check: "LLM Providers" must open its OWN card div, as a sibling of (not nested inside) the Ollama card.
i = SRC.index("Remote Ollama Configuration")
card_start = SRC.rindex('className="card"', 0, i)
j = SRC.index("LLM Providers</h3>")
# walk div depth from the Ollama card's own opening to the LLM Providers heading; if it's a sibling card, depth must
# return to 0 (fully closed) at some point between the two, then open a new card before reaching the heading.
between = SRC[card_start:j]
depth, closed_once = 0, False
for m in re.finditer(r"<div\b|</div>", between):
    depth += 1 if m.group(0) == "<div" else -1
    if depth == 0:
        closed_once = True
t("the Ollama card is FULLY CLOSED before the LLM Providers card opens (siblings, not nested)",
  closed_once, "never returned to depth 0 between the two cards — still nested")

print(f"\nRESULT: {P} passed, {F} failed")
sys.exit(1 if F else 0)
