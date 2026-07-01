"""Shared taxonomy and text-normalization helpers for the job-title classifier.

Every script (generate_data, train, classify, refine) imports from here so the
department set, abbreviation lookup, and normalization logic stay in one place.

Design note: ``Unknown`` is deliberately NOT in ``DEPARTMENTS``. It is never a
label the model learns; it is a post-hoc decision made at inference time when the
top softmax probability falls below a threshold. Keeping it out of the trainable
set is what makes that possible.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Department taxonomy
# ---------------------------------------------------------------------------

UNKNOWN_LABEL = "Unknown"

# Ordered mapping of trainable department -> short guidance used when prompting
# the LLM for synthetic titles. The guidance doubles as human documentation of
# what each bucket is meant to capture for red-team target prioritization.
DEPARTMENTS: dict[str, str] = {
    "Executive": (
        "Top-level company leadership and ownership: CEO, CTO, CFO, COO, "
        "President, Founder, Managing Director, Partner, Board Member. "
        "General C-suite and cross-functional executive roles."
    ),
    "Executive Assistant": (
        "Assistants and support staff attached to executives: Executive "
        "Assistant, Personal Assistant, Chief of Staff, Administrative "
        "Assistant to the CEO, Office Manager supporting leadership."
    ),
    "IT": (
        "Infrastructure and IT operations (not software product development): "
        "SysAdmin, IT Manager, Network Engineer, Systems Engineer, IT Analyst, "
        "Infrastructure Engineer, Directory Services, endpoint/server admin."
    ),
    "Helpdesk": (
        "Front-line end-user support: IT Support, Help Desk, Desktop Support, "
        "Service Desk, Technical Support Specialist, Field Support technician."
    ),
    "Software Engineer": (
        "Software product development and delivery: Software Engineer, "
        "Developer, Architect, DevOps, SRE, Platform Engineer, Data Engineer, "
        "Mobile/Frontend/Backend/Full-Stack Engineer, Engineering Manager."
    ),
    "Security": (
        "Cybersecurity and risk: CISO, Security Engineer, SOC Analyst, "
        "Penetration Tester, Threat Intel, GRC, IAM, AppSec, Security "
        "Architect, Incident Response, Security Operations."
    ),
    "Finance": (
        "Finance and accounting: CFO, Controller, FP&A, Accountant, Treasurer, "
        "Auditor, Financial Analyst, Bookkeeper, AP/AR, Tax."
    ),
    "HR": (
        "People operations and talent: CHRO, Recruiter, HR Business Partner, "
        "Talent Acquisition, Learning & Development, Payroll, Compensation & "
        "Benefits, People Operations."
    ),
    "Sales": (
        "Revenue generation and account management: Account Executive, SDR, "
        "BDR, VP Sales, Account Manager, Sales Engineer, Regional Sales "
        "Director, Business Development."
    ),
    "Marketing": (
        "Brand, demand, and product marketing: CMO, Growth, Brand, Demand "
        "Generation, Content, Product Marketing, SEO/SEM, Communications, "
        "Social Media, Field Marketing."
    ),
    "Legal": (
        "Legal, compliance, and privacy: General Counsel, Corporate Counsel, "
        "Attorney, Paralegal, Compliance Officer, Privacy Officer, Contracts "
        "Manager, Regulatory Affairs."
    ),
}

# Convenience: the trainable labels in a stable order.
DEPARTMENT_NAMES: list[str] = list(DEPARTMENTS.keys())

# All labels a batch output CSV can contain (trainable + the post-hoc bucket).
ALL_LABELS: list[str] = DEPARTMENT_NAMES + [UNKNOWN_LABEL]


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

# Small, deliberately-focused abbreviation lookup. Keys are matched on whole,
# lowercased tokens after punctuation is stripped. Kept short on purpose: the
# sentence-transformer embedding handles most variation; this only smooths out
# the highest-impact abbreviations that embeddings tokenize poorly.
ABBREVIATIONS: dict[str, str] = {
    # seniority
    "vp": "vice president",
    "svp": "senior vice president",
    "evp": "executive vice president",
    "avp": "assistant vice president",
    "sr": "senior",
    "snr": "senior",
    "jr": "junior",
    "mgr": "manager",
    "mgmt": "management",
    "dir": "director",
    "asst": "assistant",
    "admin": "administrator",
    "assoc": "associate",
    "coord": "coordinator",
    "spec": "specialist",
    "eng": "engineer",
    "engg": "engineering",
    "dev": "developer",
    "arch": "architect",
    "ops": "operations",
    "acct": "account",
    "acctg": "accounting",
    # C-suite / leadership initialisms
    "ceo": "chief executive officer",
    "cfo": "chief financial officer",
    "coo": "chief operating officer",
    "cto": "chief technology officer",
    "cio": "chief information officer",
    "ciso": "chief information security officer",
    "cmo": "chief marketing officer",
    "chro": "chief human resources officer",
    "cro": "chief revenue officer",
    "cpo": "chief product officer",
    "cdo": "chief data officer",
    "gc": "general counsel",
    "md": "managing director",
    # functional initialisms
    "it": "information technology",
    "hr": "human resources",
    "swe": "software engineer",
    "sre": "site reliability engineer",
    "sde": "software development engineer",
    "qa": "quality assurance",
    "sdet": "software development engineer in test",
    "ux": "user experience",
    "ui": "user interface",
    "pm": "product manager",
    "po": "product owner",
    "ba": "business analyst",
    "sdr": "sales development representative",
    "bdr": "business development representative",
    "ae": "account executive",
    "am": "account manager",
    "se": "sales engineer",
    "csm": "customer success manager",
    "ea": "executive assistant",
    "pa": "personal assistant",
    "hrbp": "human resources business partner",
    "ld": "learning and development",  # from "l&d" after & -> "and" -> stripped
    "ta": "talent acquisition",
    "soc": "security operations center",
    "iam": "identity and access management",
    "grc": "governance risk and compliance",
    "appsec": "application security",
    "infosec": "information security",
    "netsec": "network security",
    "fpa": "financial planning and analysis",  # from "fp&a"
    "ap": "accounts payable",
    "ar": "accounts receivable",
    "sysadmin": "system administrator",
    "netadmin": "network administrator",
    "dba": "database administrator",
    "ml": "machine learning",
    "ai": "artificial intelligence",
    "bi": "business intelligence",
}

_PUNCT_RE = re.compile(r"[^a-z0-9\s]")
_WS_RE = re.compile(r"\s+")


def normalize(title: str) -> str:
    """Normalize a raw job title for embedding.

    Steps: lowercase -> expand ``&`` to ``and`` -> strip remaining punctuation ->
    collapse whitespace -> expand known abbreviations token-by-token.

    The abbreviation expansion runs last so it operates on clean, punctuation-free
    tokens (e.g. ``VP`` -> ``vice president``, ``FP&A`` -> ``fpa`` ->
    ``financial planning and analysis``).
    """
    if title is None:
        return ""
    text = title.lower()
    text = text.replace("&", " and ")
    text = _PUNCT_RE.sub(" ", text)
    text = _WS_RE.sub(" ", text).strip()
    if not text:
        return ""
    tokens = [ABBREVIATIONS.get(tok, tok) for tok in text.split(" ")]
    return " ".join(tokens)
