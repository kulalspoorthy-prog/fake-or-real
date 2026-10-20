
"use strict";

/* =========================================
   FAKE OR REAL — SCAM DETECTION
   Explainable risk scoring + URL checking
   ========================================= */

// ---------- Find page elements ----------

const checkerForm = document.getElementById("checkerForm");
const messageInput = document.getElementById("messageInput");
const analyzeButton = document.getElementById("analyzeButton");

const result = document.getElementById("result");
const scoreElement = document.getElementById("score");
const riskLevelElement = document.getElementById("riskLevel");
const riskBadge = document.getElementById("riskBadge");
const resultSummary = document.getElementById("resultSummary");
const warningsElement = document.getElementById("warnings");
const adviceElement = document.getElementById("advice");
const scoreCircle = document.getElementById("scoreCircle");
const checkAgain = document.getElementById("checkAgain");

let currentMode = "message";

// ---------- Risk level helper ----------

function getRiskLevel(score) {
    if (score >= 60) return "High";
    if (score >= 30) return "Medium";
    return "Low";
}

// ---------- Message detection rules ----------

const messageRules = [
    {
        category: "Sensitive information request",
        points: 30,
        pattern: /\b(?:share|send|tell|reveal|provide|enter|confirm|submit)\b.{0,55}\b(?:otp|one[- ]time password|pin|password|cvv|card number|bank details)\b|\b(?:otp|one[- ]time password|pin|password|cvv)\b.{0,40}\b(?:share|send|tell|reveal|provide|enter|confirm|submit)\b/i,
        reason: "The message appears to request sensitive credentials or financial information."
    },
    {
        category: "Urgent pressure",
        points: 15,
        pattern: /\b(?:act now|immediately|urgent|final warning|last chance|account will be blocked|account suspended|will be closed|expire today|within \d+ minutes)\b/i,
        reason: "Urgent language may pressure you to act before verifying the request."
    },
    {
        category: "Prize or reward claim",
        points: 20,
        pattern: /\b(?:you have won|you won|winner selected|claim your prize|free gift|lucky winner|cash prize|lottery winner|claim your reward)\b/i,
        reason: "An unexpected prize or reward claim can be used to lure people into scams."
    },
    {
        category: "Suspicious payment request",
        points: 25,
        pattern: /\b(?:processing fee|release fee|pay to unlock|pay a fee to claim|send money to receive|deposit to verify|transfer money urgently|pay .*? to receive your prize)\b/i,
        reason: "The message may request payment before providing a promised benefit or service."
    },
    {
        category: "Impersonation warning",
        points: 20,
        pattern: /\b(?:kyc expired|verify your kyc|bank account blocked|digital arrest|police case against you|customs parcel held|electricity disconnected|sim card blocked)\b/i,
        reason: "The message resembles common impersonation or account-threat tactics. Verify through an official channel."
    },
    {
        category: "Suspicious link",
        points: 20,
        pattern: /https?:\/\/[^\s]+|www\.[^\s]+|\b[a-z0-9-]+\.(?:xyz|top|click|work|buzz)\b/i,
        reason: "A link or unusual domain was detected. A link alone does not prove a scam."
    },
    {
        category: "Secrecy or remote access",
        points: 20,
        pattern: /\b(?:don't tell anyone|do not tell anyone|keep this confidential|install anydesk|install teamviewer|give remote access|share your screen)\b/i,
        reason: "Requests for secrecy or remote access can be used to compromise devices or accounts."
    },
    {
        category: "Threatening language",
        points: 15,
        pattern: /\b(?:arrest warrant|you will be arrested|police will arrest|legal action today|pay or face arrest|account permanently deleted)\b/i,
        reason: "Threatening language may be intended to frighten you into acting quickly."
    }
];

// ---------- Analyze a message ----------

function analyzeMessage(input) {
    const text = String(input || "").trim();

    if (!text) {
        return {
            source: "message",
            score: 0,
            level: "Unknown",
            warnings: [],
            evidence: [],
            advice: "Enter a message before starting the analysis.",
            summary: "No message was entered."
        };
    }

    const evidence = [];

    for (const rule of messageRules) {
        if (rule.pattern.test(text)) {
            evidence.push({
                category: rule.category,
                points: rule.points,
                reason: rule.reason
            });
        }
    }

    const score = Math.min(
        100,
        evidence.reduce((total, item) => total + item.points, 0)
    );

    const level = getRiskLevel(score);

    const warnings = evidence.map(item =>
        `${item.category} (+${item.points} points): ${item.reason}`
    );

    let summary;
    let advice;

    if (score >= 60) {
        summary =
            "Multiple warning signs were detected. Treat this message as high risk until independently verified.";

        advice =
            "Do not click links, send money, or reply with sensitive information. Verify the request through an official app or independently verified contact.";
    } else if (score >= 30) {
        summary =
            "Some warning signs were detected. Review the evidence before responding.";

        advice =
            "Pause and verify the sender independently. Never share an OTP, PIN, password, or CVV. Avoid payments until the request is confirmed.";
    } else if (score > 0) {
        summary =
            "A potential warning sign was detected. Stay cautious.";

        advice =
            "Check the sender and verify important claims through official channels before taking action.";
    } else {
        summary =
            "No warning signs from this rule set were detected. This does not guarantee that the message is genuine.";

        advice =
            "Continue to be cautious. Verify unusual requests independently, even when no warning signs are detected.";
    }

    if (
        evidence.some(item =>
            item.category === "Sensitive information request"
        )
    ) {
        advice =
            "Never share an OTP, PIN, password, or CVV. Contact your bank or service provider using its official app or verified number.";
    }

    return {
        source: "message",
        score,
        level,
        warnings,
        evidence,
        advice,
        summary
    };
}

// ---------- Normalize and validate a URL ----------

function normalizeUrl(value) {
    const input = String(value || "").trim();

    if (!input) {
        throw new Error("Please enter a website address.");
    }

    if (/\s/.test(input)) {
        throw new Error("The website address must not contain spaces.");
    }

    const normalized = /^https?:\/\//i.test(input)
        ? input
        : "https://" + input;

    let parsed;

    try {
        parsed = new URL(normalized);
    } catch {
        throw new Error("Enter a valid website address, such as https://example.com.");
    }

    if (!["http:", "https:"].includes(parsed.protocol)) {
        throw new Error("Only HTTP and HTTPS addresses are supported.");
    }

    if (
        !parsed.hostname.includes(".") ||
        parsed.hostname.startsWith(".") ||
        parsed.hostname.endsWith(".")
    ) {
        throw new Error("Enter a complete website address, such as https://example.com.");
    }

    if (parsed.username || parsed.password) {
        throw new Error("For safety, URLs containing embedded login credentials are not accepted.");
    }

    return parsed.href;
}

// ---------- Basic URL pattern analysis ----------

function analyzeUrlPatterns(input) {
    const url = normalizeUrl(input);
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();

    let points = 0;
    const evidence = [];

    function addWarning(category, amount, reason) {
        evidence.push({ category, points: amount, reason });
        points += amount;
    }

    const shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "ow.ly",
        "shorturl.at"
    ];

    if (shorteners.includes(host)) {
        addWarning(
            "URL shortener",
            25,
            "This shortened link hides its final destination."
        );
    }

    if (parsed.protocol === "http:") {
        addWarning(
            "Unencrypted connection",
            15,
            "This address uses HTTP. HTTPS is preferable, although HTTPS alone does not prove a site is trustworthy."
        );
    }

    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
        addWarning(
            "Direct IP address",
            25,
            "The website uses an IP address instead of a normal domain name. Verify its legitimacy."
        );
    }

    if (host.includes("xn--")) {
        addWarning(
            "Encoded domain characters",
            20,
            "The domain contains encoded international characters. Check for possible look-alike characters."
        );
    }

    if (/@/.test(input)) {
        addWarning(
            "Misleading URL format",
            25,
            "The address contains an @ symbol, which can make the actual destination harder to recognize."
        );
    }

    if (
        /\b(?:login|verify|verification|account|password|wallet|claim|prize|gift|free|secure-login|update-payment)\b/i
            .test(parsed.hostname + parsed.pathname)
    ) {
        addWarning(
            "Potential lure wording",
            15,
            "The address contains words often used in account, payment, or prize lures. This alone does not prove fraud."
        );
    }

    if (host.split(".").length >= 5) {
        addWarning(
            "Many subdomains",
            10,
            "The domain has multiple subdomain levels. Check the actual registered domain carefully."
        );
    }

    const score = Math.min(100, points);
    const level = getRiskLevel(score);

    let advice;

    if (score >= 60) {
        advice =
            "Do not enter credentials or payment information. Verify the destination through the organization's official website or app.";
    } else if (score >= 30) {
        advice =
            "Be cautious. Check the exact domain through a trusted, independent source before proceeding.";
    } else {
        advice =
            "Few listed warning signs were found. This is not proof that the website is safe.";
    }

    return {
        source: "url",
        url,
        score,
        level,
        evidence,
        warnings: evidence.map(item =>
            `${item.category} (+${item.points} points): ${item.reason}`
        ),
        advice,
        summary:
            "This is a URL pattern analysis. A low score does not establish that a website is safe."
    };
}

// ---------- Optional live URL reputation check ----------
// Requires your existing server.js POST /api/check-url route.

async function checkUrlWithBackend(url) {
    const response = await fetch("/api/check-url", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ url })
    });

    let data;

    try {
        data = await response.json();
    } catch {
        throw new Error("The URL checking service returned an invalid response.");
    }

    if (!response.ok) {
        throw new Error(
            data.error || "The online URL check could not be completed."
        );
    }

    return data;
}

async function analyzeUrl(input) {
    const localReport = analyzeUrlPatterns(input);

    try {
        const online = await checkUrlWithBackend(localReport.url);

        if (online.foundThreat === true) {
            localReport.score = Math.max(localReport.score, 85);
            localReport.level = getRiskLevel(localReport.score);
            localReport.summary =
                "The online reputation check reported a potential threat. Avoid visiting this URL.";
            localReport.advice =
                "Do not open the link or enter information. Verify the destination independently and report the message if appropriate.";

            localReport.warnings.unshift(
                "Online reputation service reported a potential threat."
            );

            localReport.evidence.unshift({
                category: "Online threat report",
                points: 85,
                reason: "The configured online reputation service reported a potential threat. This is a warning, not a complete investigation."
            });
        } else if (online.checked === true) {
            localReport.summary =
                "No threat was reported by the online reputation check. This does not guarantee that the URL is safe.";
        }
    } catch (error) {
        // Keep local results available when the online service fails.
        localReport.summary =
            "Local URL pattern analysis completed. The online reputation check was unavailable, so the URL was not fully verified.";

        localReport.warnings.push(
            "Online reputation check unavailable. This result is based on local URL patterns only."
        );
    }

    localReport.score = Math.min(100, localReport.score);
    localReport.level = getRiskLevel(localReport.score);

    return localReport;
}

// ---------- Render results safely ----------

function showResult(report) {
    const score = Math.max(
        0,
        Math.min(100, Number(report.score) || 0)
    );

    const level = getRiskLevel(score);

    // Avoid duplicate "Risk" in the main heading.
    scoreElement.textContent = String(score);
    riskLevelElement.textContent = level + " Risk";
    riskBadge.textContent = level + " Risk";

    resultSummary.textContent =
        report.summary ||
        "Review the warning signs below before taking action.";

    warningsElement.replaceChildren();

    const warnings = Array.isArray(report.warnings)
        ? report.warnings
        : [];

    if (warnings.length === 0) {
        const item = document.createElement("li");
        item.textContent =
            "No matching warning signs were found. This does not prove the message or website is safe.";
        warningsElement.appendChild(item);
    } else {
        for (const warning of warnings) {
            const item = document.createElement("li");
            item.textContent = String(warning);
            warningsElement.appendChild(item);
        }
    }

    adviceElement.textContent =
        report.advice ||
        "Verify the sender or website independently before taking action.";

    const degrees = score * 3.6;

    let color = "#9af5c7";

    if (score >= 60) {
        color = "#ff777f";
    } else if (score >= 30) {
        color = "#ffc66d";
    }

    scoreCircle.style.background =
        `conic-gradient(${color} ${degrees}deg, #2c3850 ${degrees}deg)`;

    riskBadge.style.color = color;
    riskBadge.style.borderColor = color;

    // Create or update the explanation panel.
    let breakdown = document.getElementById("scoreBreakdown");

    if (!breakdown) {
        breakdown = document.createElement("section");
        breakdown.id = "scoreBreakdown";
        breakdown.className = "score-breakdown";

        const adviceContainer = adviceElement.parentElement;

        if (adviceContainer && adviceContainer.parentElement) {
            adviceContainer.parentElement.insertBefore(
                breakdown,
                adviceContainer
            );
        } else {
            result.appendChild(breakdown);
        }
    }

    breakdown.replaceChildren();

    const heading = document.createElement("h3");
    heading.textContent = "Why this score?";
    breakdown.appendChild(heading);

    const explanation = document.createElement("p");
    explanation.textContent =
        `Risk score: ${score}/100 — ${level} Risk. ` +
        "This score reflects detected warning signs; it is not a probability of fraud.";
    breakdown.appendChild(explanation);

    const evidence = Array.isArray(report.evidence)
        ? report.evidence
        : [];

    if (evidence.length > 0) {
        for (const item of evidence) {
            const row = document.createElement("div");
            row.className = "evidence-row";

            const title = document.createElement("strong");
            title.textContent =
                `${item.category || "Warning sign"} (+${Number(item.points) || 0} points)`;

            const detail = document.createElement("p");
            detail.textContent = item.reason || "";
            detail.style.marginBottom = "10px";

            row.append(title, detail);
            breakdown.appendChild(row);
        }
    } else {
        const note = document.createElement("p");
        note.textContent =
            "No matching rules were found. Scams can still be missed by this detector.";
        breakdown.appendChild(note);
    }

    result.hidden = false;

    // Preserve the existing dashboard if installed.
    if (typeof updateDashboard === "function") {
        try {
            updateDashboard(report);
        } catch (error) {
            console.error("Dashboard update failed:", error);
        }
    }

    requestAnimationFrame(() => {
        result.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });
    });
}

// ---------- Mode selection ----------

function setMode(mode) {
    currentMode = mode === "url" ? "url" : "message";

    document.querySelectorAll("[data-mode]").forEach(button => {
        const active = button.dataset.mode === currentMode;

        button.classList.toggle("active", active);
        button.setAttribute("aria-pressed", String(active));
    });

    if (messageInput) {
        messageInput.placeholder =
            currentMode === "url"
                ? "Paste a website URL, e.g. https://example.com"
                : "Paste a suspicious SMS, email, or message here...";

        messageInput.setAttribute(
            "aria-label",
            currentMode === "url"
                ? "Website URL to check"
                : "Message to analyze"
        );
    }

    if (analyzeButton) {
        analyzeButton.textContent =
            currentMode === "url"
                ? "Check Website"
                : "Analyze Message";
    }
}

document.querySelectorAll("[data-mode]").forEach(button => {
    button.addEventListener("click", () => {
        setMode(button.dataset.mode);
    });
});

// ---------- Main form handler ----------

if (checkerForm && messageInput) {
    checkerForm.addEventListener("submit", async event => {
        event.preventDefault();

        const input = messageInput.value.trim();

        if (!input) {
            messageInput.focus();
            return;
        }

        if (analyzeButton) {
            analyzeButton.disabled = true;
            analyzeButton.textContent = "Analyzing...";
        }

        try {
            let report;

            if (currentMode === "url") {
                report = await analyzeUrl(input);
            } else {
                report = analyzeMessage(input);
            }

            showResult(report);
        } catch (error) {
            showResult({
                source: currentMode,
                score: 0,
                warnings: [],
                evidence: [],
                summary: error.message || "The input could not be analyzed.",
                advice: "Check the input and try again."
            });
        } finally {
            if (analyzeButton) {
                analyzeButton.disabled = false;
                analyzeButton.textContent =
                    currentMode === "url"
                        ? "Check Website"
                        : "Analyze Message";
            }
        }
    });
}

// ---------- Check-again button ----------

if (checkAgain && messageInput) {
    checkAgain.addEventListener("click", () => {
        if (result) {
            result.hidden = true;
        }

        messageInput.value = "";
        messageInput.focus();
    });
}

// ---------- Dashboard history ----------

function getDashboardHistory() {
    try {
        const saved = JSON.parse(
            localStorage.getItem("fakeOrRealHistory") || "[]"
        );

        return Array.isArray(saved) ? saved : [];
    } catch {
        return [];
    }
}

function updateDashboard(report) {
    const history = getDashboardHistory();

    history.unshift({
        score: Number(report.score) || 0,
        level: getRiskLevel(Number(report.score) || 0),
        source: report.source || "message",
        date: new Date().toLocaleString()
    });

    const recent = history.slice(0, 20);

    try {
        localStorage.setItem(
            "fakeOrRealHistory",
            JSON.stringify(recent)
        );
    } catch (error) {
        console.warn("Could not save dashboard history:", error);
    }

    renderDashboard(recent);
}

function renderDashboard(history = getDashboardHistory()) {
    const totalChecks = document.getElementById("totalChecks");
    const highRiskChecks = document.getElementById("highRiskChecks");
    const latestScore = document.getElementById("latestScore");
    const latestStatus = document.getElementById("latestStatus");
    const recentChecks = document.getElementById("recentChecks");

    if (totalChecks) {
        totalChecks.textContent = String(history.length);
    }

    if (highRiskChecks) {
        highRiskChecks.textContent = String(
            history.filter(item => item.score >= 60).length
        );
    }

    if (latestScore) {
        latestScore.textContent = history.length
            ? String(history[0].score)
            : "—";
    }

    if (latestStatus) {
        latestStatus.textContent = history.length
            ? history[0].level + " Risk"
            : "No checks yet";
    }

    if (recentChecks) {
        recentChecks.replaceChildren();

        if (history.length === 0) {
            const item = document.createElement("li");
            item.textContent = "Your recent scans will appear here.";
            recentChecks.appendChild(item);
        } else {
            history.slice(0, 5).forEach(entry => {
                const item = document.createElement("li");
                item.textContent =
                    `${entry.source === "url" ? "URL" : "Message"} — ` +
                    `${entry.score}/100 — ${entry.level} Risk — ${entry.date}`;
                recentChecks.appendChild(item);
            });
        }
    }
}

// ---------- Initialize ----------

setMode("message");
renderDashboard();

/* =========================================
   SCAM DETECTION TEST LAB
   ========================================= */

const scamTestCases = [
    {
        name: "OTP theft attempt",
        expected: "High",
        message:
            "URGENT! Your bank account will be blocked. Share your OTP immediately to verify your account. Claim your prize now."
    },
    {
        name: "Prize lure",
        expected: "Medium",
        message:
            "Congratulations! You have won a free gift. Claim your prize today."
    },
    {
        name: "Payment lure",
        expected: "Medium",
        message:
            "Pay a processing fee to claim your prize."
    },
    {
        name: "Remote access request",
        expected: "Low",
        message:
            "Please install AnyDesk and give remote access to your device."
    },
    {
        name: "Ordinary study message",
        expected: "Low",
        message:
            "Hi, our study group meeting is at 4 PM tomorrow. Please bring your notebook."
    },
    {
        name: "Ordinary lunch message",
        expected: "Low",
        message:
            "Would you like to have lunch together tomorrow? Let me know what time works for you."
    },
    {
        name: "Normal class reminder",
        expected: "Low",
        message:
            "Reminder: our computer science class starts at 10 AM. Please bring your assignment."
    },
    {
        name: "Ordinary family message",
        expected: "Low",
        message:
            "Hi, I reached home safely. See you this evening."
    }
];

function runScamDetectionTests() {
    const resultsContainer = document.getElementById("testResults");
    const summary = document.getElementById("testLabSummary");
    const metrics = document.getElementById("testMetrics");

    if (!resultsContainer || !summary || !metrics) {
        console.error(
            "Test Lab elements not found. Check the HTML IDs in index.html."
        );
        return;
    }

    resultsContainer.replaceChildren();

    let passed = 0;
    let failed = 0;

    let truePositive = 0;
    let trueNegative = 0;
    let falsePositive = 0;
    let falseNegative = 0;

    for (const test of scamTestCases) {
        const report = analyzeMessage(test.message);
        const actual = getRiskLevel(report.score);

        const expectedScam = test.expected !== "Low";
        const predictedScam = report.score >= 30;

        const isPass = actual === test.expected;

        if (isPass) {
            passed++;
        } else {
            failed++;
        }

        if (expectedScam && predictedScam) {
            truePositive++;
        } else if (!expectedScam && !predictedScam) {
            trueNegative++;
        } else if (!expectedScam && predictedScam) {
            falsePositive++;
        } else {
            falseNegative++;
        }

        const card = document.createElement("article");
        card.className = "test-case";

        const heading = document.createElement("h3");
        heading.textContent = test.name;

        const message = document.createElement("p");
        message.textContent = test.message;

        const expected = document.createElement("p");
        expected.textContent = `Expected category: ${test.expected}`;

        const actualResult = document.createElement("p");
        actualResult.textContent =
            `Actual result: ${actual} Risk (${report.score}/100)`;

        const status = document.createElement("p");
        status.className = "test-case-status " +
            (isPass ? "test-pass" : "test-fail");

        status.textContent = isPass
            ? "✓ PASS — category matched"
            : "✗ REVIEW — category did not match";

        card.append(
            heading,
            message,
            expected,
            actualResult,
            status
        );

        resultsContainer.appendChild(card);
    }

    document.getElementById("testsPassed").textContent =
        String(passed);

    document.getElementById("testsFailed").textContent =
        String(failed);

    document.getElementById("falsePositives").textContent =
        String(falsePositive);

    document.getElementById("falseNegatives").textContent =
        String(falseNegative);

    metrics.hidden = false;

    const accuracy = Math.round(
        (passed / scamTestCases.length) * 100
    );

    summary.textContent =
        `Completed ${scamTestCases.length} tests. ` +
        `${passed} category matches, ${failed} category mismatches. ` +
        `Sample-set category match rate: ${accuracy}%.`;

    // Add a confusion-matrix summary for the demo.
    const matrix = document.createElement("p");
    matrix.textContent =
        `Binary classification at the 30-point threshold — ` +
        `True positives: ${truePositive}; ` +
        `True negatives: ${trueNegative}; ` +
        `False positives: ${falsePositive}; ` +
        `False negatives: ${falseNegative}.`;

    resultsContainer.prepend(matrix);
}

const runTestsButton = document.getElementById("runTestsButton");

if (runTestsButton) {
    runTestsButton.addEventListener("click", () => {
        runTestsButton.disabled = true;
        runTestsButton.textContent = "Running tests...";

        try {
            runScamDetectionTests();
        } catch (error) {
            console.error("Test Lab failed:", error);

            const summary =
                document.getElementById("testLabSummary");

            if (summary) {
                summary.textContent =
                    "The tests could not run. Check the browser console for errors.";
            }
        } finally {
            runTestsButton.disabled = false;
            runTestsButton.textContent = "Run All Tests";
        }
    });
}
