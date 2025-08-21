# ai.py  (Blueprint version with report-scoped voice assistant)
import os
import uuid
import asyncio
import time
from datetime import timedelta
import fitz  # PyMuPDF
from flask import Blueprint, request, jsonify, send_from_directory, url_for
from openai import OpenAI, OpenAIError
import edge_tts
import re

# ==== CONFIG (retained) ====
client = OpenAI(api_key="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")
MODEL = "gpt-3.5-turbo-0125"
EDGE_VOICE = "hi-IN-SwaraNeural"
ALLOWED_EXTENSIONS = {'pdf', 'txt'}

STATIC_DIR = "static"
AUDIO_DIR = os.path.join(STATIC_DIR, "audio")
UPLOAD_DIR = os.path.join(STATIC_DIR, "uploads")
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(AUDIO_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

# === Blueprint ===
bp = Blueprint("ai", __name__)

# === In-memory contexts (context_id -> dict). Persist if you prefer DB.
CONTEXTS = {}
CONTEXT_TTL_SECONDS = int(timedelta(hours=24).total_seconds())

def _now_s():
    return int(time.time())

def _prune_contexts():
    now = _now_s()
    to_delete = [cid for cid, c in CONTEXTS.items() if now - c.get("created_at", now) > CONTEXT_TTL_SECONDS]
    for cid in to_delete:
        CONTEXTS.pop(cid, None)

def _new_context_id():
    return uuid.uuid4().hex

# ==== Helper Functions (retained/expanded) ====
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

async def _edge_tts_to_file(text: str, out_path: str):
    tts = edge_tts.Communicate(text, voice=EDGE_VOICE)
    await tts.save(out_path)

def edge_tts_to_file(text: str, out_path: str):
    asyncio.run(_edge_tts_to_file(text, out_path))

def extract_text_from_pdf(file_path):
    """Slightly better page extraction."""
    try:
        doc = fitz.open(file_path)
        text = []
        for page in doc:
            text.append(page.get_text("text"))
        return "\n".join(text).strip()
    except Exception as e:
        return f"Failed to extract PDF text: {e}"

def _force_bullets_if_needed(text: str) -> str:
    """If the LLM returns a paragraph instead of bullets, split to short bullet lines."""
    if not text:
        return text
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    # If already looks like bullets (starts with digit., -, •), keep as is
    bullet_like = any(re.match(r"^(\d+\.|[-•])\s+", ln) for ln in lines[:3])
    if bullet_like:
        return "\n".join(lines)
    # Otherwise, split sentences and prefix
    out = []
    for seg in re.split(r"(?<=[.!?])\s+", " ".join(lines)):
        s = seg.strip()
        if s:
            out.append(f"- {s}")
    return "\n".join(out)

def interpret_file(file_path):
    """
    Returns (summary, recommendations, raw_text, keywords)
    """
    try:
        ext = os.path.splitext(file_path)[1].lower()

        if ext == '.pdf':
            raw = extract_text_from_pdf(file_path)
        else:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                raw = f.read()

        # ===== CHANGED PROMPT: force 8–10 bullet points =====
        prompt = (
            "You are a medical explainer. Read the health report below and produce structured, patient-friendly output.\n"
            "1) Under the heading 'Interpretation:', write EXACTLY 8 to 10 numbered bullet points (1., 2., ...).\n"
            "   - Each point must be <= 22 words, simple, and non-alarming.\n"
            "   - Summarize key findings, what is normal/high/low, and what it could mean (avoid diagnosis terms unless mentioned in the report).\n"
            "2) Under 'Recommendations:', give 3–5 concise, practical food/lifestyle tips aligned with the findings.\n"
            "3) Under 'Keywords:', give a short comma-separated list of important terms/metrics mentioned in the report.\n\n"
            f"REPORT:\n{raw}\n\n"
            "Return in this exact format:\n"
            "Interpretation:\n1. <point 1>\n2. <point 2>\n...\n\n"
            "Recommendations:\n- <tip 1>\n- <tip 2>\n...\n\n"
            "Keywords:\n<kw1, kw2, ...>"
        )

        response = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            timeout=30
        )

        content = response.choices[0].message.content.strip()

        # Parse sections (support both 'Interpretation:' and older 'Summary:' just in case)
        def _after(tag, text):
            if tag in text:
                return text.split(tag, 1)[1].strip()
            return ""

        # Defaults
        interpretation = content
        recommendations = "No recommendations section found."
        keywords_csv = ""

        # Prefer Interpretation:
        if "Interpretation:" in content:
            interpretation = _after("Interpretation:", content)
            # split tail
            if "Recommendations:" in interpretation:
                interpretation, tail = interpretation.split("Recommendations:", 1)
                interpretation = interpretation.strip()
                content_tail = "Recommendations:" + tail
            else:
                content_tail = ""
        elif "Summary:" in content:
            # Backward-compat
            interpretation = _after("Summary:", content)
            if "Recommendations:" in interpretation:
                interpretation, tail = interpretation.split("Recommendations:", 1)
                interpretation = interpretation.strip()
                content_tail = "Recommendations:" + tail
            else:
                content_tail = ""
        else:
            content_tail = ""

        if content_tail:
            recommendations = _after("Recommendations:", content_tail)
            if "Keywords:" in recommendations:
                recommendations, kw_tail = recommendations.split("Keywords:", 1)
                recommendations = recommendations.strip()
                keywords_csv = kw_tail.strip()
        else:
            if "Recommendations:" in content:
                recommendations = _after("Recommendations:", content)
            if "Keywords:" in content:
                keywords_csv = _after("Keywords:", content)

        # Normalize outputs
        interpretation = _force_bullets_if_needed(interpretation.strip())
        recommendations = recommendations.strip()
        keywords = [k.strip() for k in keywords_csv.split(",") if k.strip()]

        # Return 'interpretation' in the summary slot so your UI shows it under AI Interpretation
        return interpretation, recommendations, raw, keywords

    except OpenAIError as e:
        return f"OpenAI API error: {e}", "", "", []
    except Exception as e:
        return f"Error processing file: {e}", "", "", []

# ==== Basic lab extraction for better Q&A (rough ranges; non-diagnostic) ====
REF = {
    "hb_g_dl": (12.0, 16.0),          # generic adult band
    "pcv_pct": (36.0, 46.0),
    "wbc_10e3_ul": (4.0, 11.0),
    "platelets_10e3_ul": (150.0, 450.0)
}

LAB_PATTERNS = {
    "hb_g_dl": r"\b(Hb|Hemoglobin)\b[^0-9\-]*([0-9]+(?:\.[0-9]+)?)\s*(g/?dL)\b",
    "pcv_pct": r"\b(PCV|Hematocrit)\b[^0-9\-]*([0-9]+(?:\.[0-9]+)?)\s*%\b",
    "wbc_10e3_ul": r"\b(WBC|Total\s*WBC|Total\s*Leukocyte\s*Count)\b[^0-9\-]*([0-9]+(?:\.[0-9]+)?)\s*(?:x?\s*10\^?3|\*?10\^?3)?\s*/?\s*(?:µL|uL|UL|ml|mL)?\b",
    "platelets_10e3_ul": r"\b(Platelet[s]?\s*Count|Platelets)\b[^0-9\-]*([0-9]+(?:\.[0-9]+)?)\s*(?:x?\s*10\^?3|\*?10\^?3)?\s*/?\s*(?:µL|uL|UL|ml|mL)?\b",
}

def extract_labs(raw_text: str):
    labs = {}
    for key, pat in LAB_PATTERNS.items():
        m = re.search(pat, raw_text or "", flags=re.IGNORECASE)
        if m:
            try:
                val = float(m.group(2))
                labs[key] = val
            except Exception:
                pass
    flags = {}
    for k, (lo, hi) in REF.items():
        v = labs.get(k)
        if v is None:
            continue
        if v < lo: flags[k] = "low"
        elif v > hi: flags[k] = "high"
        else: flags[k] = "normal"
    return {"values": labs, "flags": flags, "note": "Reference ranges vary by lab/age/sex; general information only."}

def _build_guardrailed_messages(user_text: str, ctx: dict):
    """
    Improved:
    - Reply in the SAME language as the user's question when possible (e.g., Hindi).
    - Allow language/meta requests (translate, 'speak Hindi') without refusal.
    - For medical details missing in report: say 'Not explicitly mentioned in your report.'
      + one short, general note (marked as general) + 1 clarifying question.
    - Never invent numbers/diagnoses.
    """
    system = (
        "You are a Health Report Voice Assistant. The user is the patient. "
        "Reply in the same language the user used when possible (e.g., if the user writes in Hindi, reply in Hindi). "
        "Use ONLY the provided report context (SUMMARY, RECOMMENDATIONS, KEYWORDS, RAW_TEXT, STRUCTURED_LABS) for medical content. "
        "If the user's request is about language, translation, or explaining findings in another language, you may fulfill it directly. "
        "If the user asks for a medical detail that is not present in the report, say exactly: 'Not explicitly mentioned in your report.' "
        "Then add one short general guidance line (clearly marked as general, not personalized) and end with one clarifying follow-up question. "
        "NEVER fabricate lab numbers or diagnoses. If you cite a lab, include its name and value (with unit) if present. "
        "Be concise, friendly, and avoid repeating the same refusal line."
    )

    structured = ctx.get("structured") or {}
    labs_blob = f"{structured}" if structured else "{}"

    context_blob = (
        f"SUMMARY:\n{ctx.get('summary','')}\n\n"
        f"RECOMMENDATIONS:\n{ctx.get('recommendations','')}\n\n"
        f"KEYWORDS:\n{', '.join(ctx.get('keywords', []))}\n\n"
        f"STRUCTURED_LABS (parsed):\n{labs_blob}\n\n"
        f"RAW_TEXT (may be noisy, truncated):\n{ctx.get('raw','')[:8000]}"
    )

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": f"Report context for this session:\n{context_blob}"},
        {"role": "user", "content": f"User question:\n{user_text}"},
    ]
    return messages

# === helper so app.py can create a context without calling /analyze-report
def register_context_from_parts(summary: str, recommendations: str, raw_text: str, keywords=None):
    if keywords is None:
        keywords = []
    structured = extract_labs(raw_text or "")
    cid = _new_context_id()
    CONTEXTS[cid] = {
        "created_at": _now_s(),
        "file": None,
        "summary": summary or "",
        "recommendations": recommendations or "",
        "raw": raw_text or "",
        "keywords": keywords or [],
        "structured": structured,
    }
    return cid

# ==== Routes ====
@bp.post("/ask-text")
def ask_text():
    _prune_contexts()

    data = request.get_json(silent=True) or {}
    user_text = (data.get("text") or "").strip()
    context_id = (data.get("context_id") or "").strip()

    if not user_text:
        return jsonify({"error": "Missing 'text'"}), 400
    if not context_id or context_id not in CONTEXTS:
        return jsonify({"error": "Missing or invalid 'context_id'. Analyze a report first."}), 400

    ctx = CONTEXTS[context_id]

    try:
        try:
            resp = client.chat.completions.create(
                model=MODEL,
                messages=_build_guardrailed_messages(user_text, ctx),
                temperature=0.2,
                timeout=30
            )
        except AttributeError:
            resp = client.chat.completions.create(
                model=MODEL,
                messages=_build_guardrailed_messages(user_text, ctx),
                temperature=0.2,
                timeout=30
            )

        reply = (resp.choices[0].message.content or "").strip() or \
            "Not explicitly mentioned in your report. Generally speaking, I can share typical guidance if you tell me the exact lab values or findings you want to discuss (e.g., Hb, WBC, Platelets)."

        # TTS (clip long text for safety)
        audio_id = f"{uuid.uuid4()}.mp3"
        out_path = os.path.join(AUDIO_DIR, audio_id)
        try:
            tts_text = reply[:4000]
            edge_tts_to_file(tts_text, out_path)
            audio_url = url_for("ai.get_audio", fname=audio_id)
            return jsonify({"reply": reply, "audio_url": audio_url}), 200
        except Exception as e:
            return jsonify({"reply": reply, "audio_url": None, "tts_error": str(e)}), 200

    except OpenAIError as e:
        return jsonify({"error": f"OpenAI API error: {e}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@bp.post("/analyze-report")
def analyze_report():
    _prune_contexts()

    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file and allowed_file(file.filename):
        filename = f"{uuid.uuid4()}{os.path.splitext(file.filename)[1]}"
        filepath = os.path.join(UPLOAD_DIR, filename)
        file.save(filepath)

        summary, recommendations, raw_text, keywords = interpret_file(filepath)
        structured = extract_labs(raw_text or "")

        # Build and store context
        context_id = _new_context_id()
        CONTEXTS[context_id] = {
            "created_at": _now_s(),
            "file": filename,
            "summary": summary,               # <-- interpretation bullets here
            "recommendations": recommendations,
            "raw": raw_text,
            "keywords": keywords,
            "structured": structured,
        }

        # Optional: immediate audio of the combined result
        full_response = f"Summary:\n{summary}\n\nRecommendations:\n{recommendations}"
        audio_id = f"{uuid.uuid4()}.mp3"
        out_path = os.path.join(AUDIO_DIR, audio_id)
        audio_url = None
        tts_error = None
        try:
            tts_text = full_response[:4000]
            edge_tts_to_file(tts_text, out_path)
            audio_url = url_for("ai.get_audio", fname=audio_id)
        except Exception as e:
            tts_error = str(e)

        return jsonify({
            "summary": summary,
            "recommendations": recommendations,
            "keywords": keywords,
            "audio_url": audio_url,
            "context_id": context_id,
            "expires_in_seconds": CONTEXT_TTL_SECONDS,
            "tts_error": tts_error
        }), 200
    else:
        return jsonify({"error": "Invalid file type"}), 400

@bp.get("/audio/<fname>")
def get_audio(fname):
    return send_from_directory(AUDIO_DIR, fname, as_attachment=False)

@bp.post("/clear-context")
def clear_context():
    """Optional endpoint to delete a context explicitly."""
    data = request.get_json(silent=True) or {}
    context_id = (data.get("context_id") or "").strip()
    if not context_id:
        return jsonify({"error": "Missing 'context_id'"}), 400
    CONTEXTS.pop(context_id, None)
    return jsonify({"ok": True}), 200
