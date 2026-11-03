
import streamlit as st
from html import escape

from src.rag import (
    generate_answer,
    validate_question,
    detect_prompt_injection,
    extract_product_target,
)
from src.cloud_setup import initialize_cloud_knowledge_base
from src.catalog_analytics import get_catalog_analytics


# --------------------------------------------------
# Page configuration

# --------------------------------------------------

st.set_page_config(
    page_title="CyberStream RAG | Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# --------------------------------------------------
# Cloud knowledge-base initialization
# --------------------------------------------------

try:
    knowledge_base_status = initialize_cloud_knowledge_base()
except Exception as error:
    st.error(f"Knowledge-base initialization failed: {error}")
    st.stop()


# --------------------------------------------------
# Professional dark theme + rainbow gradient
# --------------------------------------------------

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

    :root {
        --bg: #06101f;
        --panel: #0b1b30;
        --panel-light: #10243d;
        --border: #203c5c;
        --text: #eaf3ff;
        --muted: #91a8c5;
        --cyan: #19e6ff;
        --pink: #ff36d1;
        --green: #38f99a;
    }

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    .stApp {
        background:
            radial-gradient(ellipse at 50% -15%, #173d70 0%, transparent 42%),
            linear-gradient(145deg, #06101f 0%, #08172b 55%, #050d19 100%);
        color: var(--text);
    }

    [data-testid="stHeader"] {
        background: rgba(6, 16, 31, 0.92);
    }

    [data-testid="stToolbar"] {
        right: 1rem;
    }

    .block-container {
        max-width: 1500px;
        padding-top: 1.2rem !important;
        padding-bottom: 3rem !important;
    }

    h1, h2, h3, p, label {
        color: var(--text);
    }

    .rainbow-title {
        background: linear-gradient(
            90deg,
            #19e6ff 0%,
            #5977ff 20%,
            #d84cff 42%,
            #ff4f91 60%,
            #ffca55 77%,
            #43f5a6 100%
        );
        -webkit-background-clip: text;
        background-clip: text;
        color: transparent !important;
        font-weight: 800;
        letter-spacing: -1.5px;
        line-height: 1.15;
    }

    .eyebrow {
        color: #19e6ff;
        font-size: 0.76rem;
        font-weight: 800;
        letter-spacing: 2px;
        text-transform: uppercase;
        margin-bottom: 12px;
    }

    .hero {
        position: relative;
        overflow: hidden;
        padding: 2rem 2.2rem;
        margin-bottom: 1.6rem;
        border: 1px solid #24496d;
        border-radius: 22px;
        background:
            radial-gradient(ellipse at 100% 0%, rgba(119, 42, 255, .24), transparent 40%),
            radial-gradient(ellipse at 0% 100%, rgba(0, 210, 255, .12), transparent 45%),
            linear-gradient(120deg, #0c2038, #0a1428 70%);
        box-shadow: 0 16px 55px rgba(0, 0, 0, .22);
    }

    .hero:after {
        content: "";
        display: block;
        height: 3px;
        margin-top: 1.5rem;
        border-radius: 10px;
        background: linear-gradient(
            90deg, #19e6ff, #655dff, #ff36d1, #ffbd59, #38f99a
        );
    }

    .hero-description {
        color: #b8cce6;
        font-size: 1rem;
        line-height: 1.8;
        max-width: 850px;
        margin-top: .8rem;
    }

    .section-title {
        font-size: 1.45rem;
        font-weight: 800;
        margin: 1.5rem 0 .8rem 0;
    }

    .panel {
        padding: 1.35rem;
        border-radius: 17px;
        border: 1px solid var(--border);
        background: linear-gradient(145deg, #0c2037, #09182b);
        margin-bottom: 1.2rem;
    }

    .metric-card {
        min-height: 115px;
        padding: 1rem 1.1rem;
        border: 1px solid #214565;
        border-radius: 15px;
        background: linear-gradient(145deg, #102844, #09182b);
    }

    .metric-label {
        color: #a9bfd9;
        font-size: .82rem;
        font-weight: 600;
    }

    .metric-value {
        font-size: 1.8rem;
        font-weight: 800;
        margin-top: .3rem;
        color: #19e6ff;
    }

    .metric-pink .metric-value {
        color: #ff53d8;
    }

    .metric-green .metric-value {
        color: #38f99a;
    }

    /* CyberStream search input */

    .stTextInput input::placeholder {
    color: #9bb4d1 !important;
    opacity: 1 !important;
}

.stTextInput input {
    background: #10243b !important;
    color: #ffffff !important;
    -webkit-text-fill-color: #ffffff !important;
    border: 1px solid #2875a5 !important;
    border-radius: 10px !important;
    min-height: 46px !important;
    padding: 10px 14px !important;
    font-size: 14px !important;
    font-weight: 500 !important;
}

/* Visible placeholder */
.stTextInput input::placeholder {
    color: #a9c3df !important;
    -webkit-text-fill-color: #a9c3df !important;
    opacity: 1 !important;
}

/* Focus effect */
.stTextInput input:focus {
    border: 1px solid #16d9f2 !important;
    box-shadow: 0 0 12px rgba(22, 217, 242, 0.25) !important;
    outline: none !important;
}

    /* Search and example buttons */
.stButton > button,
div[data-testid="stFormSubmitButton"] button {
    width: 100%;
    min-height: 48px !important;
    background: linear-gradient(
        100deg,
        #087cf5,
        #713cff,
        #d82fc9
    ) !important;
    color: #ffffff !important;
    -webkit-text-fill-color: #ffffff !important;
    border: 1px solid #19e6ff !important;
    border-radius: 11px !important;
    font-weight: 700 !important;
    box-shadow: 0 5px 18px rgba(25, 100, 255, .2);
    transition: .25s ease;
}

/* Button hover */
.stButton > button:hover,
div[data-testid="stFormSubmitButton"] button:hover {
    background: linear-gradient(
        100deg,
        #119cff,
        #874cff,
        #ed3bd4
    ) !important;
    color: #ffffff !important;
    -webkit-text-fill-color: #ffffff !important;
    border-color: #ffffff !important;
    box-shadow: 0 0 22px rgba(25, 230, 255, .35);
    transform: translateY(-2px);
}

/* Ensure button text remains visible */
.stButton > button p,
div[data-testid="stFormSubmitButton"] button p {
    color: #ffffff !important;
    -webkit-text-fill-color: #ffffff !important;
    font-weight: 700 !important;
}

/* Answer container */
div[data-testid="stVerticalBlockBorderWrapper"] {
    background: linear-gradient(
        145deg,
        #102844,
        #09182b
    ) !important;
    border: 1px solid #285477 !important;
    border-radius: 16px !important;
    padding: 1rem 1.2rem !important;
}
    div[data-testid="stExpander"] {
        border: 1px solid #254462;
        border-radius: 12px;
        background: rgba(11, 27, 48, .85);
        margin-bottom: .5rem;
    }

    div[data-testid="stExpander"] summary p {
        color: #eaf3ff !important;
        font-weight: 600;
    }

    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #061322, #081a2e);
        border-right: 1px solid #203a56;
    }

    [data-testid="stSidebar"] .block-container {
        padding-top: 1.5rem !important;
    }

    .sidebar-brand {
        font-size: 1.35rem;
        font-weight: 800;
        color: #f3f8ff;
        margin-bottom: .3rem;
    }

    .sidebar-subtitle {
        font-size: .72rem;
        letter-spacing: 1px;
        color: #8fa6c2;
        text-transform: uppercase;
    }

    .pipeline-item {
        color: #b5c9e2;
        padding: .35rem 0;
        font-size: .88rem;
    }

    .source-tag {
        display: inline-block;
        padding: 4px 9px;
        margin: 3px 4px 3px 0;
        color: #7beeff;
        border: 1px solid #20536d;
        border-radius: 20px;
        background: #0b2940;
        font-size: .75rem;
    }

    .notice {
        padding: 1rem 1.1rem;
        border-radius: 12px;
        background: #0d2439;
        border: 1px solid #254d6b;
        color: #c5d9ef;
        line-height: 1.7;
    }

    .footer {
        color: #7189a6;
        border-top: 1px solid #1b3048;
        padding-top: 1rem;
        margin-top: 2rem;
        font-size: .78rem;
    }

    @media (max-width: 700px) {
        .hero {
            padding: 1.3rem;
        }
        .rainbow-title {
            letter-spacing: -.6px;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# Session state
# --------------------------------------------------

if "question" not in st.session_state:
    st.session_state.question = ""

if "answer" not in st.session_state:
    st.session_state.answer = ""

if "evidence" not in st.session_state:
    st.session_state.evidence = []

if "searched" not in st.session_state:
    st.session_state.searched = False

if "last_error" not in st.session_state:
    st.session_state.last_error = ""

if "guardrail_status" not in st.session_state:
    st.session_state.guardrail_status = "ready"


# --------------------------------------------------
# Sidebar
# --------------------------------------------------

with st.sidebar:
    st.markdown(
        """
        <div class="sidebar-brand">🛡️ CyberStream</div>
        <div class="sidebar-subtitle">Threat Intelligence Platform</div>
        """,
        unsafe_allow_html=True,
    )

    st.divider()

    st.markdown("### Search pipeline")

    pipeline_items = [
        ("🔎", "Hybrid retrieval"),
        ("🧠", "Semantic + keyword search"),
        ("🎯", "Reciprocal Rank Fusion"),
        ("⚡", "FlashRank reranking"),
        ("✨", "Gemini model fallback"),
        ("🛡️", "Input validation"),
        ("🚫", "Prompt-injection detection"),
        ("🎯", "Product relevance filtering"),
        ("📊", "Answer-quality evaluation"),
        ("🔭", "LangSmith tracing"),
    ]

    for symbol, item in pipeline_items:
        st.markdown(
            f'<div class="pipeline-item">{symbol} &nbsp; {item}</div>',
            unsafe_allow_html=True,
        )

    st.divider()

    st.markdown("### Data source")
    st.markdown("**CISA Known Exploited Vulnerabilities**")
    st.caption(
        "Answers are grounded in retrieved, indexed records. "
        "Always verify critical security findings against official advisories."
    )

    st.divider()

    st.caption("CyberStream RAG · AI Engineer Portfolio Project")


# --------------------------------------------------
# Hero section
# --------------------------------------------------

st.markdown(
    """
    <div class="hero">
        <div class="eyebrow">CYBERSECURITY · THREAT RESEARCH · AI INSIGHTS</div>
        <h1 class="rainbow-title" style="font-size:clamp(2.2rem, 5vw, 3.5rem);">
            🛡️ CyberStream RAG
        </h1>
        <div class="hero-description">
            Investigate known exploited vulnerabilities with hybrid search,
            Reciprocal Rank Fusion, FlashRank reranking, and evidence-grounded
            AI answers — all in one threat intelligence workspace.
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# Search form
# --------------------------------------------------

st.markdown(
    '<div class="section-title">🔎 Investigate a threat</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div style="color:#9eb6d2;margin-bottom:12px;">'
    'Search by vendor, product, CVE identifier, or cybersecurity topic.'
    '</div>',
    unsafe_allow_html=True,
)

with st.form("threat_search_form", clear_on_submit=False):
    question = st.text_input(
        "Your question",
        value=st.session_state.question,
        placeholder="e.g. Which vulnerabilities affect Microsoft SharePoint?",
        max_chars=1000,
        label_visibility="collapsed",
    )

    submitted = st.form_submit_button(
        "🔍  Search threat intelligence",
        use_container_width=True,
    )


# --------------------------------------------------
# Example questions
# --------------------------------------------------

st.markdown(
    '<div style="color:#19e6ff;font-weight:700;margin:10px 0;">'
    '💡 Try an example'
    '</div>',
    unsafe_allow_html=True,
)

examples = [
    "Which vulnerabilities affect Microsoft SharePoint?",
    "Which vulnerabilities affect Adobe products?",
    "Which vulnerabilities affect Ivanti Connect Secure?",
]

example_columns = st.columns(3)

for index, example in enumerate(examples):
    with example_columns[index]:
        if st.button(example, key=f"example_{index}", use_container_width=True):
            st.session_state.question = example
            st.session_state["run_example_search"] = True
            st.rerun()


# --------------------------------------------------
# Run search with visible guardrail feedback
# --------------------------------------------------

run_example_search = st.session_state.pop("run_example_search", False)

if submitted or run_example_search:
    selected_question = (
        st.session_state.question if run_example_search else question
    )

    st.session_state.question = selected_question
    st.session_state.answer = ""
    st.session_state.evidence = []
    st.session_state.last_error = ""
    st.session_state.guardrail_status = "ready"
    st.session_state.searched = False

    # Run the same validation functions used by src.rag.
    validation_error = validate_question(selected_question)

    if validation_error:
        st.session_state.answer = validation_error
        st.session_state.guardrail_status = "input_blocked"
        st.session_state.searched = True

    else:
        injection_warning = detect_prompt_injection(selected_question)

        if injection_warning:
            st.session_state.answer = (
                "Your question was blocked by CyberStream RAG's security "
                "guardrail because it contains a potential prompt-injection "
                "instruction. Please submit a normal cybersecurity question."
            )
            st.session_state.guardrail_status = "injection_blocked"
            st.session_state.searched = True

        else:
            with st.spinner(
                "Searching CISA threat intelligence, reranking sources, "
                "and generating an evidence-grounded answer..."
            ):
                try:
                    answer, evidence = generate_answer(selected_question)

                    st.session_state.answer = answer
                    st.session_state.evidence = evidence
                    st.session_state.searched = True

                    # The RAG pipeline returns no evidence when its
                    # product/vendor metadata relevance check fails.
                    target = extract_product_target(selected_question)

                    if (
                        target
                        and not evidence
                        and answer.startswith("No relevant CVE evidence")
                    ):
                        st.session_state.guardrail_status = "relevance_blocked"
                    elif not evidence:
                        st.session_state.guardrail_status = "no_evidence"
                    else:
                        st.session_state.guardrail_status = "success"

                except Exception as error:
                    st.session_state.last_error = str(error)
                    st.session_state.searched = False
                    st.session_state.guardrail_status = "error"


# --------------------------------------------------
# Intelligence report
# --------------------------------------------------

st.markdown(
    '<div class="section-title">📑 Intelligence report</div>',
    unsafe_allow_html=True,
)

evidence = st.session_state.evidence
answer = st.session_state.answer

source_count = len(evidence)
unique_cves = len({
    item.get("cve_id")
    for item in evidence
    if item.get("cve_id")
})

guardrail_status = st.session_state.guardrail_status

status_labels = {
    "ready": "Ready",
    "success": "Complete",
    "input_blocked": "Input blocked",
    "injection_blocked": "Blocked",
    "relevance_blocked": "No relevant evidence",
    "no_evidence": "No evidence",
    "error": "Error",
}

status = status_labels.get(guardrail_status, "Ready")

metric_columns = st.columns(3)

metrics = [
    ("Sources retrieved", str(source_count), ""),
    ("Unique CVEs", str(unique_cves), "metric-pink"),
    ("Answer status", status, "metric-green"),
]

for column, (label, value, css_class) in zip(metric_columns, metrics):
    with column:
        st.markdown(
            f"""
            <div class="metric-card {css_class}">
                <div class="metric-label">{escape(label)}</div>
                <div class="metric-value">{escape(value)}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


# --------------------------------------------------
# Display answer
# --------------------------------------------------

if st.session_state.last_error:
    st.error("The search could not be completed.")
    st.code(st.session_state.last_error)

elif st.session_state.searched and answer:
    if guardrail_status == "input_blocked":
        st.warning(f"Input validation: {answer}")

    elif guardrail_status == "injection_blocked":
        st.error("Security guardrail blocked this request.")
        st.warning(answer)

    elif guardrail_status == "relevance_blocked":
        st.warning("Evidence relevance check: no matching product/vendor evidence.")
        st.info(answer)

    elif guardrail_status == "no_evidence":
        st.info(answer)

    st.markdown(
        '<div class="section-title">✨ Answer</div>',
        unsafe_allow_html=True,
    )

    if "Gemini is temporarily unavailable" in answer or (
        "Gemini answer generation failed" in answer
    ):
        st.warning(
            "The AI generation service was unavailable. "
            "Review the retrieved evidence below; it is not a generated conclusion."
        )

    with st.container(border=True):
        st.markdown(answer)

    if evidence:
        st.markdown(
            '<div class="section-title">📚 Retrieved sources</div>',
            unsafe_allow_html=True,
        )

        st.markdown(
            '<div style="color:#91a8c5;margin-bottom:12px;">'
            'Inspect the original indexed evidence behind the answer.'
            '</div>',
            unsafe_allow_html=True,
        )

        for index, item in enumerate(evidence, start=1):
            cve_id = str(item.get("cve_id", "Unknown CVE"))
            name = str(item.get("name", "Unknown vulnerability"))

            with st.expander(f"{index}. {cve_id} — {name}"):
                detail_columns = st.columns(2)

                with detail_columns[0]:
                    st.markdown("**Vendor**")
                    st.write(item.get("vendor") or "Not available")

                    st.markdown("**Product**")
                    st.write(item.get("product") or "Not available")

                with detail_columns[1]:
                    st.markdown("**Date added to CISA catalog**")
                    st.write(item.get("date_added") or "Not available")

                    if item.get("rerank_score") is not None:
                        st.markdown("**FlashRank score**")
                        st.write(f"{item['rerank_score']:.4f}")

                    if item.get("rrf_score") is not None:
                        st.markdown("**RRF score**")
                        st.write(f"{item['rrf_score']:.6f}")

                details = item.get("details")
                if details:
                    st.markdown("**Evidence details**")
                    st.write(details)

                st.caption(
                    "Source: locally indexed CISA Known Exploited Vulnerabilities catalog"
                )

        cve_ids = [
            str(item.get("cve_id"))
            for item in evidence
            if item.get("cve_id")
        ]

        if cve_ids:
            st.markdown("**CVE identifiers in retrieved evidence**")
            st.markdown(
                " ".join(
                    f'<span class="source-tag">{escape(cve)}</span>'
                    for cve in cve_ids
                ),
                unsafe_allow_html=True,
            )

else:
    st.markdown(
        """
        <div class="panel">
            <div class="eyebrow">READY FOR INVESTIGATION</div>
            <h3 class="rainbow-title" style="font-size:1.7rem;">
                Start with a threat question
            </h3>
            <p style="color:#b8cce6;line-height:1.8;">
                Enter a question above or choose an example to investigate
                known exploited vulnerabilities. Your answer and source evidence
                will appear here.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


# --------------------------------------------------
# Catalog-wide vulnerability analytics
# --------------------------------------------------

st.markdown(
    '<div class="section-title">📊 CISA catalog analytics</div>',
    unsafe_allow_html=True,
)
st.caption(
    "Catalog-wide analysis of all records stored in SQLite. "
    "Categories are estimated using keyword rules, not official CISA classifications."
)

@st.cache_data(ttl=3600, show_spinner=False)
def load_catalog_analytics_cached():
    return get_catalog_analytics()

try:
    with st.spinner("Analyzing the indexed CISA catalog..."):
        analytics = load_catalog_analytics_cached()

    total_records = analytics["total_records"]
    classified_records = analytics["classified_records"]
    categories = analytics["categories"]

    analytics_metrics = st.columns(2)
    analytics_metrics[0].metric("Catalog records analyzed", f"{total_records:,}")
    analytics_metrics[1].metric("Records with a classification", f"{classified_records:,}")

    if not categories.empty:
        chart_data = categories.set_index("Vulnerability Type")["Record Count"]
        st.bar_chart(chart_data)
        st.dataframe(
            categories,
            use_container_width=True,
        )
    else:
        st.info("No catalog records are available for classification.")

    st.caption(analytics["classification_method"])
    st.caption(
        "A CVE may match more than one category, so category counts and percentages "
        "are not mutually exclusive and may add up to more than 100%. "
        "Unclassified records are grouped under Other / Unclassified."
    )

except Exception as analytics_error:
    st.warning(f"Catalog analytics are temporarily unavailable: {analytics_error}")


# --------------------------------------------------
# Footer
# --------------------------------------------------

st.markdown(
    """
    <div class="footer">
        <strong>CyberStream RAG</strong> · CISA threat evidence · Hybrid retrieval
        · FlashRank reranking · Gemini model fallback · Security guardrails
        · Evidence relevance filtering · Answer evaluation
        <br><br>
        For research and educational use. Validate security decisions against
        official advisories and vendor guidance.
    </div>
    """,
    unsafe_allow_html=True,
)
