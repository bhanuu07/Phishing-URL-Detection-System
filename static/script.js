// =========================================================
// PHISHING URL DETECTION SYSTEM
// Frontend JavaScript
// =========================================================


// =========================================================
// GET HTML ELEMENTS
// =========================================================

const urlInput = document.getElementById("urlInput");
const checkButton = document.getElementById("checkButton");

const resultSection =
    document.getElementById("resultSection");

const loading =
    document.getElementById("loading");

const errorMessage =
    document.getElementById("errorMessage");


// =========================================================
// PAGE LOAD
// =========================================================

document.addEventListener(
    "DOMContentLoaded",
    function () {

        displayHistory();

    }
);


// =========================================================
// SCAN BUTTON
// =========================================================

if (checkButton) {

    checkButton.addEventListener(
        "click",
        function () {

            checkURL();

        }
    );

}


// =========================================================
// ENTER KEY
// =========================================================

if (urlInput) {

    urlInput.addEventListener(
        "keypress",
        function (event) {

            if (event.key === "Enter") {

                checkURL();

            }

        }
    );

}


// =========================================================
// SAFE EXAMPLE
// =========================================================

const safeExample =
    document.getElementById("safeExample");

if (safeExample) {

    safeExample.addEventListener(
        "click",
        function () {

            urlInput.value =
                "https://www.google.com";

            checkURL();

        }
    );

}


// =========================================================
// SUSPICIOUS EXAMPLE
// =========================================================

const suspiciousExample =
    document.getElementById("suspiciousExample");

if (suspiciousExample) {

    suspiciousExample.addEventListener(
        "click",
        function () {

            urlInput.value =
                "http://secure-login-verify-account-example.com/login";

            checkURL();

        }
    );

}


// =========================================================
// IP ADDRESS EXAMPLE
// =========================================================

const ipExample =
    document.getElementById("ipExample");

if (ipExample) {

    ipExample.addEventListener(
        "click",
        function () {

            urlInput.value =
                "http://192.168.1.10/login";

            checkURL();

        }
    );

}


// =========================================================
// CLEAR HISTORY
// =========================================================

const clearHistoryButton =
    document.getElementById("clearHistory");

if (clearHistoryButton) {

    clearHistoryButton.addEventListener(
        "click",
        function () {

            clearHistory();

        }
    );

}


// =========================================================
// MAIN URL CHECK FUNCTION
// =========================================================

async function checkURL() {

    const url =
        urlInput.value.trim();


    // Clear previous error

    errorMessage.textContent = "";


    // Validate input

    if (!url) {

        resultSection.classList.add(
            "hidden"
        );

        errorMessage.textContent =
            "Please enter a URL.";

        return;
    }


    // Show loading

    loading.classList.remove(
        "hidden"
    );

    resultSection.classList.add(
        "hidden"
    );


    // Disable button while scanning

    checkButton.disabled = true;

    checkButton.style.opacity = "0.7";


    try {

        console.log(
            "Sending URL to server:",
            url
        );


        const response =
            await fetch(
                "/api/check",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        url: url
                    })
                }
            );


        console.log(
            "Server response status:",
            response.status
        );


        // Get response text first

        const responseText =
            await response.text();


        console.log(
            "Server response:",
            responseText
        );


        // Check if server returned an error

        if (!response.ok) {

            let errorMessageText =
                "Server error: " +
                response.status;


            try {

                const errorData =
                    JSON.parse(
                        responseText
                    );


                if (errorData.error) {

                    errorMessageText =
                        errorData.error;

                }

            }

            catch (error) {

                // Response was not JSON

            }


            throw new Error(
                errorMessageText
            );

        }


        // Convert response to JSON

        let data;

        try {

            data =
                JSON.parse(
                    responseText
                );

        }

        catch (error) {

            throw new Error(
                "The server returned an invalid response."
            );

        }


        // Check backend error

        if (data.error) {

            throw new Error(
                data.error
            );

        }


        // Display result

        displayResult(data);


        // Save scan

        saveToHistory(data);

    }

    catch (error) {

        console.error(
            "Scan error:",
            error
        );


        resultSection.classList.add(
            "hidden"
        );


        errorMessage.textContent =
            "Unable to analyze URL: " +
            error.message;

    }

    finally {

        // Hide loading

        loading.classList.add(
            "hidden"
        );


        // Enable button

        checkButton.disabled = false;

        checkButton.style.opacity = "1";

    }

}


// =========================================================
// DISPLAY RESULT
// =========================================================

function displayResult(data) {

    console.log(
        "Displaying result:",
        data
    );


    resultSection.classList.remove(
        "hidden"
    );


    // =====================================================
    // RISK RESULT
    // =====================================================

    const resultTitle =
        document.getElementById(
            "resultTitle"
        );


    const resultDescription =
        document.getElementById(
            "resultDescription"
        );


    if (data.level === "low") {

        resultTitle.textContent =
            "Low Risk";

        resultTitle.style.color =
            "#22c55e";


        resultDescription.textContent =
            "No major suspicious characteristics were detected.";

    }

    else if (data.level === "medium") {

        resultTitle.textContent =
            "Suspicious";

        resultTitle.style.color =
            "#f59e0b";


        resultDescription.textContent =
            "Some characteristics commonly associated with suspicious URLs were detected.";

    }

    else {

        resultTitle.textContent =
            "High Risk";

        resultTitle.style.color =
            "#ef4444";


        resultDescription.textContent =
            "Several characteristics commonly associated with phishing URLs were detected.";

    }


    // =====================================================
    // SCORE
    // =====================================================

    document
        .getElementById("score")
        .textContent =
            data.score;


    updateRiskBar(
        data.score
    );


    // =====================================================
    // URL BREAKDOWN
    // =====================================================

    const breakdown =
        data.breakdown || {};


    document
        .getElementById("protocol")
        .textContent =
            breakdown.protocol || "-";


    document
        .getElementById("domain")
        .textContent =
            breakdown.domain || "-";


    document
        .getElementById("path")
        .textContent =
            breakdown.path || "/";


    document
        .getElementById("query")
        .textContent =
            breakdown.query || "None";


    // =====================================================
    // FEATURES
    // =====================================================

    const features =
        data.features || {};


    const featureStatus =
        data.feature_status || {};


    // HTTPS

    updateSecurityStatus(
        "httpsStatus",

        featureStatus.https,

        features.https
            ? "HTTPS enabled"
            : "HTTPS not detected"
    );


    // IP ADDRESS

    updateSecurityStatus(
        "ipStatus",

        featureStatus.ip_address,

        features.ip_address
            ? "IP address detected"
            : "Domain name used"
    );


    // SUSPICIOUS KEYWORDS

    let keywordText =
        "No suspicious keywords";


    if (
        Array.isArray(
            features.suspicious_keywords
        ) &&
        features.suspicious_keywords.length > 0
    ) {

        keywordText =
            features.suspicious_keywords.join(
                ", "
            );

    }


    updateSecurityStatus(
        "keywordStatus",

        featureStatus.suspicious_keywords,

        keywordText
    );


    // SUBDOMAINS

    updateSecurityStatus(
        "subdomainStatus",

        featureStatus.subdomains,

        String(
            features.subdomains ?? 0
        ) +
        " subdomain(s)"
    );


    // @ SYMBOL

    updateSecurityStatus(
        "atStatus",

        featureStatus.at_symbol,

        features.at_symbol
            ? "@ symbol detected"
            : "No @ symbol"
    );


    // URL SHORTENER

    updateSecurityStatus(
        "shortenedStatus",

        featureStatus.shortened_url,

        features.shortened_url
            ? "Shortener detected"
            : "No shortener detected"
    );


    // PUNYCODE

    updateSecurityStatus(
        "punycodeStatus",

        featureStatus.punycode,

        features.punycode
            ? "Punycode detected"
            : "No punycode detected"
    );


    // PORT

    let portText =
        "Default port";


    if (features.port) {

        portText =
            "Port " +
            features.port;

    }


    updateSecurityStatus(
        "portStatus",

        featureStatus.non_standard_port,

        portText
    );


    // =====================================================
    // FEATURE TABLE
    // =====================================================

    setText(
        "lengthFeature",
        features.url_length
    );


    setText(
        "domainLengthFeature",
        features.domain_length
    );


    setText(
        "pathLengthFeature",
        features.path_length
    );


    setText(
        "subdomainFeature",
        features.subdomains
    );


    setText(
        "digitFeature",
        features.digits
    );


    setText(
        "digitRatioFeature",

        features.digit_ratio !== undefined
            ? features.digit_ratio + "%"
            : "-"
    );


    setText(
        "dotFeature",
        features.dots
    );


    setText(
        "hyphenFeature",
        features.hyphens
    );


    setText(
        "specialFeature",
        features.special_characters
    );


    setText(
        "queryFeature",
        features.query_parameters
    );


    setText(
        "portFeature",
        features.port || "Default"
    );


    // =====================================================
    // DETECTION REASONS
    // =====================================================

    displayReasons(
        data.reasons || []
    );


    // =====================================================
    // LIVE WEBSITE VERIFICATION
    // =====================================================

    displayWebsiteVerification(
        data.website_verification
    );


    // =====================================================
    // SCROLL TO RESULTS
    // =====================================================

    setTimeout(
        function () {

            resultSection.scrollIntoView({

                behavior: "smooth",

                block: "start"

            });

        },
        100
    );

}


// =========================================================
// LIVE WEBSITE VERIFICATION
// =========================================================

function displayWebsiteVerification(data) {

    if (!data) {

        console.warn(
            "No website verification data received."
        );

        return;
    }


    // =====================================================
    // DNS STATUS
    // =====================================================

    if (data.dns_status === "success") {

        updateLiveStatus(
            "dnsStatus",
            "success",
            "Domain exists"
        );

    }

    else {

        updateLiveStatus(
            "dnsStatus",
            "warning",
            "Domain not found"
        );

    }


    // =====================================================
    // WEBSITE STATUS
    // =====================================================

    if (
        data.website_status ===
        "reachable"
    ) {

        updateLiveStatus(
            "websiteStatus",
            "success",
            "Website reachable"
        );

    }

    else if (
        data.website_status ===
        "unreachable"
    ) {

        updateLiveStatus(
            "websiteStatus",
            "warning",
            "Website unreachable"
        );

    }

    else if (
        data.website_status ===
        "timeout"
    ) {

        updateLiveStatus(
            "websiteStatus",
            "warning",
            "Connection timed out"
        );

    }

    else if (
        data.website_status ===
        "blocked"
    ) {

        updateLiveStatus(
            "websiteStatus",
            "warning",
            "Connection blocked"
        );

    }

    else {

        updateLiveStatus(
            "websiteStatus",
            "warning",
            "Unable to verify"
        );

    }


    // =====================================================
    // HTTP STATUS
    // =====================================================

    if (data.http_status) {

        let statusText =
            String(
                data.http_status
            );


        if (
            data.http_status >= 200 &&
            data.http_status < 300
        ) {

            statusText +=
                " OK";

        }

        else if (
            data.http_status >= 300 &&
            data.http_status < 400
        ) {

            statusText +=
                " Redirect";

        }

        else if (
            data.http_status === 404
        ) {

            statusText +=
                " Not Found";

        }

        else if (
            data.http_status >= 400 &&
            data.http_status < 500
        ) {

            statusText +=
                " Client Error";

        }

        else if (
            data.http_status >= 500
        ) {

            statusText +=
                " Server Error";

        }


        updateLiveStatus(

            "httpStatus",

            data.http_status >= 400
                ? "warning"
                : "success",

            statusText

        );

    }

    else {

        updateLiveStatus(
            "httpStatus",
            "neutral",
            "Not available"
        );

    }


    // =====================================================
    // HTTPS
    // =====================================================

    if (data.https === true) {

        updateLiveStatus(
            "liveHttpsStatus",
            "success",
            "HTTPS enabled"
        );

    }

    else {

        updateLiveStatus(
            "liveHttpsStatus",
            "warning",
            "HTTPS not detected"
        );

    }


    // =====================================================
    // REDIRECTS
    // =====================================================

    const redirects =
        data.redirect_count ?? 0;


    if (redirects === 0) {

        updateLiveStatus(
            "redirectStatus",
            "success",
            "No redirects"
        );

    }

    else {

        updateLiveStatus(
            "redirectStatus",
            "warning",

            redirects +
            (
                redirects === 1
                    ? " redirect"
                    : " redirects"
            )
        );

    }


    // =====================================================
    // RESPONSE TIME
    // =====================================================

    if (
        data.response_time !== null &&
        data.response_time !== undefined
    ) {

        updateLiveStatus(
            "responseTimeStatus",
            "success",
            data.response_time +
            " ms"
        );

    }

    else {

        updateLiveStatus(
            "responseTimeStatus",
            "neutral",
            "Not available"
        );

    }


    // =====================================================
    // IP ADDRESS
    // =====================================================

    setText(
        "liveIpAddress",
        data.ip_address || "-"
    );


    // =====================================================
    // FINAL URL
    // =====================================================

    setText(
        "finalUrl",
        data.final_url || "-"
    );

}


// =========================================================
// LIVE STATUS CARD
// =========================================================

function updateLiveStatus(
    elementId,
    status,
    text
) {

    const element =
        document.getElementById(
            elementId
        );


    if (!element) {

        console.warn(
            "Live status element not found:",
            elementId
        );

        return;
    }


    const value =
        element.querySelector(
            "span"
        );


    if (!value) {

        console.warn(
            "Live status text not found:",
            elementId
        );

        return;
    }


    element.classList.remove(
        "security-safe",
        "security-warning"
    );


    if (status === "success") {

        element.classList.add(
            "security-safe"
        );

    }

    else if (status === "warning") {

        element.classList.add(
            "security-warning"
        );

    }


    value.textContent =
        text;

}


// =========================================================
// SAFE TEXT UPDATE
// =========================================================

function setText(
    elementId,
    value
) {

    const element =
        document.getElementById(
            elementId
        );


    if (!element) {

        console.warn(
            "Element not found:",
            elementId
        );

        return;
    }


    if (
        value === undefined ||
        value === null
    ) {

        element.textContent =
            "-";

    }

    else {

        element.textContent =
            value;

    }

}


// =========================================================
// SECURITY STATUS
// =========================================================

function updateSecurityStatus(
    elementId,
    statusData,
    valueText
) {

    const element =
        document.getElementById(
            elementId
        );


    if (!element) {

        console.warn(
            "Security element not found:",
            elementId
        );

        return;
    }


    const statusText =
        element.querySelector(
            "span"
        );


    if (!statusText) {

        console.warn(
            "Status text not found:",
            elementId
        );

        return;
    }


    // Remove previous classes

    element.classList.remove(
        "security-safe",
        "security-warning"
    );


    // Determine status

    if (
        statusData &&
        statusData.status === "warning"
    ) {

        element.classList.add(
            "security-warning"
        );

    }

    else {

        element.classList.add(
            "security-safe"
        );

    }


    statusText.textContent =
        valueText;

}


// =========================================================
// RISK BAR
// =========================================================

function updateRiskBar(score) {

    const riskBar =
        document.getElementById(
            "riskBarFill"
        );


    if (!riskBar) {

        return;
    }


    const safeScore =
        Math.max(
            0,
            Math.min(
                100,
                Number(score) || 0
            )
        );


    // The dark overlay hides the
    // unused portion of the bar.

    riskBar.style.width =
        (100 - safeScore) +
        "%";


    const riskScore =
        document.querySelector(
            ".score-number"
        );


    if (!riskScore) {

        return;
    }


    if (safeScore >= 60) {

        riskScore.style.color =
            "#ef4444";

    }

    else if (safeScore >= 30) {

        riskScore.style.color =
            "#f59e0b";

    }

    else {

        riskScore.style.color =
            "#22c55e";

    }

}


// =========================================================
// DETECTION REASONS
// =========================================================

function displayReasons(
    reasons
) {

    const list =
        document.getElementById(
            "reasonsList"
        );


    if (!list) {

        return;
    }


    list.innerHTML = "";


    if (
        !Array.isArray(reasons) ||
        reasons.length === 0
    ) {

        const item =
            document.createElement(
                "li"
            );


        item.classList.add(
            "safe-reason"
        );


        item.textContent =
            "No major suspicious characteristics were detected.";


        list.appendChild(
            item
        );


        return;
    }


    reasons.forEach(
        function (reason) {

            const item =
                document.createElement(
                    "li"
                );


            item.textContent =
                reason;


            list.appendChild(
                item
            );

        }
    );

}


// =========================================================
// SAVE SCAN HISTORY
// =========================================================

function saveToHistory(
    data
) {

    let history;


    try {

        history =
            JSON.parse(
                localStorage.getItem(
                    "phishingScanHistory"
                )
            ) || [];

    }

    catch (error) {

        history = [];

    }


    const scan = {

        url:
            data.url,

        result:
            data.result ||
            "Unknown",

        level:
            data.level ||
            "low",

        score:
            data.score ||
            0,

        time:
            new Date().toLocaleString()

    };


    history.unshift(
        scan
    );


    // Keep only last 10 scans

    history =
        history.slice(
            0,
            10
        );


    localStorage.setItem(

        "phishingScanHistory",

        JSON.stringify(
            history
        )

    );


    displayHistory();

}


// =========================================================
// DISPLAY HISTORY
// =========================================================

function displayHistory() {

    const container =
        document.getElementById(
            "historyList"
        );


    if (!container) {

        return;
    }


    let history;


    try {

        history =
            JSON.parse(
                localStorage.getItem(
                    "phishingScanHistory"
                )
            ) || [];

    }

    catch (error) {

        history = [];

    }


    container.innerHTML = "";


    if (history.length === 0) {

        container.innerHTML =
            `
            <p class="empty-history">
                No scans yet.
            </p>
            `;

        return;
    }


    history.forEach(
        function (scan) {

            const item =
                document.createElement(
                    "div"
                );


            item.className =
                "history-item";


            // URL

            const url =
                document.createElement(
                    "span"
                );


            url.className =
                "history-url";


            url.textContent =
                scan.url;


            url.title =
                scan.url;


            // Result

            const result =
                document.createElement(
                    "span"
                );


            result.className =
                "history-result " +
                getHistoryClass(
                    scan.level
                );


            result.textContent =
                scan.score +
                " · " +
                getDisplayLevel(
                    scan.level
                );


            item.appendChild(
                url
            );


            item.appendChild(
                result
            );


            container.appendChild(
                item
            );

        }
    );

}


// =========================================================
// HISTORY LEVEL
// =========================================================

function getHistoryClass(
    level
) {

    if (level === "high") {

        return "history-high";

    }


    if (level === "medium") {

        return "history-medium";

    }


    return "history-low";

}


// =========================================================
// DISPLAY LEVEL
// =========================================================

function getDisplayLevel(
    level
) {

    if (level === "high") {

        return "High Risk";

    }


    if (level === "medium") {

        return "Suspicious";

    }


    return "Low Risk";

}


// =========================================================
// CLEAR HISTORY
// =========================================================

function clearHistory() {

    localStorage.removeItem(
        "phishingScanHistory"
    );


    displayHistory();

}