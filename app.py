from flask import Flask, render_template, request, jsonify

from detector import analyze_url
from website_checker import check_website
from lookalike_detector import detect_lookalike


app = Flask(__name__)


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# =========================================================
# URL CHECK API
# =========================================================

@app.route(
    "/api/check",
    methods=["POST"]
)
def check_url():

    data = request.get_json()


    # -----------------------------------------------------
    # VALIDATE REQUEST
    # -----------------------------------------------------

    if not data or "url" not in data:

        return jsonify({
            "error": "URL is required."
        }), 400


    url = data["url"].strip()


    if not url:

        return jsonify({
            "error": "Please enter a URL."
        }), 400


    # =====================================================
    # BASIC URL ANALYSIS
    # =====================================================

    result = analyze_url(
        url
    )


    # =====================================================
    # LIVE WEBSITE VERIFICATION
    # =====================================================

    website_result = check_website(
        url
    )


    result[
        "website_verification"
    ] = website_result


    # =====================================================
    # LOOKALIKE / TYPOSQUATTING DETECTION
    # =====================================================

    lookalike_result = detect_lookalike(
        url
    )


    result[
        "lookalike_detection"
    ] = lookalike_result


    # =====================================================
    # ADD LOOKALIKE TO DETECTION REASONS
    # =====================================================

    if lookalike_result["detected"]:

        reason = (
            lookalike_result["reason"]
        )


        if "reasons" not in result:

            result["reasons"] = []


        result["reasons"].append(
            reason
        )


        # -------------------------------------------------
        # CURRENT SCORE
        # -------------------------------------------------

        current_score = int(
            result.get(
                "score",
                0
            )
        )


        # -------------------------------------------------
        # MIXED CASE
        # -------------------------------------------------

        if (
            lookalike_result["mixed_case"]
            and
            not lookalike_result["matched_brand"]
        ):

            result["score"] = min(
                100,
                current_score + 5
            )


        # -------------------------------------------------
        # ACTUAL LOOKALIKE
        # -------------------------------------------------

        else:

            result["score"] = min(
                100,
                current_score + 25
            )


        # -------------------------------------------------
        # UPDATE RISK LEVEL
        # -------------------------------------------------

        if result["score"] >= 60:

            result["level"] = "high"

        elif result["score"] >= 30:

            result["level"] = "medium"

        else:

            result["level"] = "low"


    # =====================================================
    # RETURN RESULT
    # =====================================================

    return jsonify(
        result
    )


# =========================================================
# RUN SERVER
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )