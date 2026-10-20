
"use strict";

const form = document.getElementById("checkerForm");
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
const charCount = document.getElementById("charCount");
const inputLabel = document.getElementById("inputLabel");
const inputDescription = document.getElementById("inputDescription");
const inputHint = document.getElementById("inputHint");
const checkAgain = document.getElementById("checkAgain");
const modeButtons = document.querySelectorAll("[data-mode]");

let currentMode = "message";

const scamRules = [
  {
    pattern: /\b(otp|one[- ]time password|verification code)\b/i,
    score: 25,
    warning: "The message mentions an OTP or verification code. Never share these codes."
  },
  {
    pattern: /\b(password|pin number|bank details|card details)\b/i,
    score: 25,
    warning: "The message mentions sensitive account information."
  },
  {
    pattern: /\b(won|winner|prize|lottery|free gift|claim your reward)\b/i,
    score: 15,
    warning: "Unexpected prizes or rewards can be used to attract victims."
  },
  {
    pattern: /\b(urgent|immediately|act now|limited time|expires today)\b/i,
    score: 15,
    warning: "Urgent language may be pressuring you to act without checking."
  },
  {
    pattern: /\b(click here|verify your account|account suspended|account blocked)\b/i,
    score: 15,
    warning: "The message asks you to click or verify an account."
  },
  {
    pattern: /\b(send money|transfer money|pay a fee|processing fee)\b/i,
    score: 20,
    warning: "The message asks for money or a payment."
  },
  {
    pattern: /\b(gift card|crypto|cryptocurrency|investment returns)\b/i,
    score: 15,
    warning: "Gift cards, cryptocurrency, or promised investment returns can be scam signals."
  },
  {
    pattern: /\b(keep this secret|do not tell anyone|don't tell anyone)\b/i,
    score: 15,
    warning: "The message asks for secrecy, which can be a manipulation tactic."
  },
  {
    pattern: /\b(remote access|install this app|download this app)\b/i,
    score: 15,
    warning: "The message asks you to install software or allow access."
  }
];

function getRiskLevel(score) {
  if (score >= 60) return "High Risk";
  if (score >= 30) return "Medium Risk";
  return "Low Risk";
}

function getAdvice(score, warnings) {
  if (score >= 60) {
    return "Do not click links, pay money, download attachments, or share private information. Contact the organization through its official website or phone number.";
  }

  if (score >= 30) {
    return "Be cautious. Verify the sender using a separate, trusted channel. Do not share OTPs, passwords, or payment details.";
  }

  if (warnings.length > 0) {
    return "Some warning signs were found. Check the sender and verify all claims independently before taking action.";
  }

  return "No common warning signs were detected by these simple checks. This does not prove the message is genuine. Verify unexpected requests independently.";
}

function analyzeMessage(text) {
  let score = 0;
  const warnings = [];

  for (const rule of scamRules) {
    if (rule.pattern.test(text)) {
      score += rule.score;
      warnings.push(rule.warning);
    }
  }

  const links = text.match(/https?:\/\/[^\s<>"']+|www\.[^\s<>"']+/gi) || [];

  if (links.length > 0) {
    warnings.push("The text contains a web link. Check the exact domain before opening it.");
    score += 10;
  }

  if (/\b(bit\.ly|tinyurl\.com|t\.co|is\.gd)\b/i.test(text)) {
    warnings.push("A URL-shortening service was detected. It can hide the destination address.");
    score += 15;
  }

  if (/[A-Z]{5,}/.test(text)) {
    warnings.push("The message contains unusually prominent capital letters.");
    score += 5;
  }

  if (warnings.length === 0) {
    warnings.push("No obvious warning signs matched the current rules.");
  }

  score = Math.min(100, score);

  return {
    score,
    warnings,
    advice: getAdvice(score, warnings),
    source: "message"
  };
}

function getUrlWarnings(url) {
  const warnings = [];
  let score = 0;

  try {
    const parsed = new URL(url);

    if (parsed.protocol !== "https:") {
      warnings.push("The address does not use HTTPS encryption.");
      score += 15;
    }

    if (parsed.username || parsed.password) {
      warnings.push("The address contains text before the domain that may disguise the destination.");
      score += 25;
    }

    if (parsed.hostname.startsWith("xn--") || parsed.hostname.includes(".xn--")) {
      warnings.push("The domain uses encoded characters. Carefully verify that it is not impersonating another site.");
      score += 20;
    }

    if (parsed.hostname.split(".").length >= 5) {
      warnings.push("The domain has several subdomain levels. Check the actual registered domain.");
      score += 10;
    }

    if (/\d{5,}/.test(parsed.hostname)) {
      warnings.push("The domain contains a long sequence of numbers.");
      score += 10;
    }

    if (/\.(zip|mov)$/i.test(parsed.hostname)) {
      warnings.push("This domain ending may be unexpected for the service you intend to visit. Verify the domain carefully.");
      score += 5;
    }

    if (warnings.length === 0) {
      warnings.push("No obvious URL warning signs matched the basic checks. The website has not been proven safe.");
    }
  } catch {
    warnings.push("The URL could not be parsed. Enter a complete address such as https://example.com.");
    score = 35;
  }

  score = Math.min(100, score);

  return {
    score,
    warnings,
    advice: getAdvice(score, warnings),
    source: "url"
  };
}

function showResult(report) {
  scoreElement.textContent = String(report.score);
  riskLevelElement.textContent = getRiskLevel(report.score);
  riskBadge.textContent = getRiskLevel(report.score);
  resultSummary.textContent =
    report.source === "url"
      ? "Your URL check is complete. Review the warning signs below."
      : "Your message check is complete. Review the warning signs below.";

  warningsElement.replaceChildren();

  for (const warning of report.warnings) {
    const li = document.createElement("li");
    li.textContent = warning;
    warningsElement.appendChild(li);
  }

  adviceElement.textContent = report.advice;

  const degrees = report.score * 3.6;
  let color = "#9af5c7";

  if (report.score >= 60) {
    color = "#ff777f";
  } else if (report.score >= 30) {
    color = "#ffc66d";
  }

  scoreCircle.style.background =
    `conic-gradient(${color} ${degrees}deg, #2c3850 ${degrees}deg)`;

  riskBadge.style.color = color;
  riskBadge.style.borderColor = color;

  result.hidden = false;
  updateDashboard(report);

  requestAnimationFrame(() => {
    result.scrollIntoView({ behavior: "smooth", block: "start" });
  });
}

function normalizeUrl(value) {
  let url = value.trim();

  if (!/^https?:\/\//i.test(url)) {
    url = "https://" + url;
  }

  const parsed = new URL(url);

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only HTTP and HTTPS website addresses are allowed.");
  }

  if (!parsed.hostname.includes(".")) {
    throw new Error("Enter a complete website address, such as https://example.com.");
  }

  return parsed.href;
}

async function checkUrlWithBackend(url) {
  const response = await fetch("/api/check-url", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || "URL checking failed. Check your backend and API key.");
  }

  return data;
}

function switchMode(mode) {
  currentMode = mode;
  result.hidden = true;

  modeButtons.forEach(button => {
    const selected = button.dataset.mode === mode;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-selected", String(selected));
  });

  if (mode === "url") {
    inputLabel.textContent = "Enter a website URL";
    inputDescription.textContent = "Enter the full address of the website you want to check.";
    inputHint.textContent = "Example: https://example.com";
    messageInput.placeholder = "https://example.com";
  } else {
    inputLabel.textContent = "Paste your message";
    inputDescription.textContent = "Include the complete text you want to check.";
    inputHint.textContent = "Your text is analyzed for common warning signs.";
    messageInput.placeholder =
      "Example: Congratulations! You won a prize. Click this link immediately to claim your reward...";
  }
}

modeButtons.forEach(button => {
  button.addEventListener("click", () => switchMode(button.dataset.mode));
});

messageInput.addEventListener("input", () => {
  charCount.textContent = `${messageInput.value.length} characters`;
});

form.addEventListener("submit", async event => {
  event.preventDefault();

  const value = messageInput.value.trim();

  if (!value) {
    messageInput.focus();
    return;
  }

  const originalButtonText = analyzeButton.innerHTML;
  analyzeButton.disabled = true;
  analyzeButton.innerHTML = "<span>Checking...</span><span>⏳</span>";

  try {
    if (currentMode === "message") {
      showResult(analyzeMessage(value));
    } else {
      const url = normalizeUrl(value);
      const localReport = getUrlWarnings(url);

      try {
        const apiReport = await checkUrlWithBackend(url);
        const threats = Array.isArray(apiReport.threats)
          ? apiReport.threats
          : [];

        if (apiReport.foundThreat) {
          localReport.score = Math.max(localReport.score, 85);
          localReport.warnings.push(
            "The Safe Browsing service reported a potential threat for this URL."
          );
          localReport.warnings.push(
            ...threats.map(item =>
              `Threat category: ${item.threatType || "Unspecified threat"}`
            )
          );
          localReport.advice =
            "Avoid visiting this address. Do not enter passwords or payment details. If you believe this is a false alarm, verify the URL independently.";
        } else {
          localReport.warnings.push(
            "The Safe Browsing service did not report a matching threat in this check. This is not a guarantee that the URL is safe."
          );
        }
      } catch (error) {
        localReport.warnings.push(
          `Online threat check unavailable: ${error.message}`
        );
        localReport.warnings.push(
          "Only basic local URL checks were completed. The website's safety has not been confirmed."
        );
      }

      localReport.advice = getAdvice(localReport.score, localReport.warnings);
      showResult(localReport);
    }
  } catch (error) {
    showResult({
      score: 35,
      warnings: [error.message || "The input could not be checked."],
      advice: "Check the input and try again. Never enter sensitive information on a suspicious website.",
      source: currentMode
    });
  } finally {
    analyzeButton.disabled = false;
    analyzeButton.innerHTML = originalButtonText;
  }
});

checkAgain.addEventListener("click", () => {
  result.hidden = true;
  messageInput.value = "";
  charCount.textContent = "0 characters";
  messageInput.focus();
  document.querySelector(".checker").scrollIntoView({
    behavior: "smooth",
    block: "start"
  });
});

switchMode("message");

/* ===== Dashboard stats and recent activity ===== */

const dashboardStorageKey = "fakeOrRealDashboardHistory";

function getDashboardHistory() {
  try {
    const saved = JSON.parse(
      localStorage.getItem(dashboardStorageKey) || "[]"
    );

    return Array.isArray(saved) ? saved : [];
  } catch {
    return [];
  }
}

function updateDashboard(report) {
  const history = getDashboardHistory();
  const score = Math.max(0, Math.min(100, Number(report.score) || 0));

  const entry = {
    type: report.source === "url" ? "URL" : "Message",
    score,
    risk: getRiskLevel(score),
    preview: messageInput.value.trim().slice(0, 100),
    time: new Date().toLocaleString()
  };

  history.unshift(entry);

  // Keep only the latest 20 checks.
  const recentHistory = history.slice(0, 20);

  try {
    localStorage.setItem(
      dashboardStorageKey,
      JSON.stringify(recentHistory)
    );
  } catch {
    // The current result can still be displayed if storage is unavailable.
  }

  renderDashboard(recentHistory);
}

function renderDashboard(history = getDashboardHistory()) {
  const totalElement = document.getElementById("totalChecks");
  const highRiskElement = document.getElementById("highRiskChecks");
  const latestScoreElement = document.getElementById("latestScore");
  const latestStatusElement = document.getElementById("latestStatus");
  const recentChecksElement = document.getElementById("recentChecks");

  if (!totalElement || !highRiskElement ||
      !latestScoreElement || !latestStatusElement ||
      !recentChecksElement) {
    return;
  }

  totalElement.textContent = history.length;

  highRiskElement.textContent = history.filter(
    item => Number(item.score) >= 60
  ).length;

  if (history.length > 0) {
    const latest = history[0];
    const score = Number(latest.score) || 0;

    latestScoreElement.textContent = score;
    latestScoreElement.style.color =
      score >= 60 ? "#ff9298" :
      score >= 30 ? "#ffc66d" : "#9af5c7";

    latestStatusElement.textContent = latest.risk || getRiskLevel(score);
  } else {
    latestScoreElement.textContent = "--";
    latestScoreElement.style.color = "#f4f7ff";
    latestStatusElement.textContent = "Waiting for first scan";
  }

  recentChecksElement.replaceChildren();

  if (history.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-activity";

    const icon = document.createElement("span");
    icon.className = "empty-icon";
    icon.textContent = "⌕";

    const title = document.createElement("p");
    title.textContent = "No checks yet.";

    const description = document.createElement("small");
    description.textContent = "Your analysis history will appear here.";

    empty.append(icon, title, description);
    recentChecksElement.appendChild(empty);
    return;
  }

  history.slice(0, 5).forEach(item => {
    const row = document.createElement("div");
    row.className = "recent-item";

    const typeIcon = document.createElement("span");
    typeIcon.className = "recent-type-icon";
    typeIcon.textContent = item.type === "URL" ? "↗" : "✉";

    const details = document.createElement("div");
    details.className = "recent-details";

    const name = document.createElement("strong");
    name.textContent = item.type === "URL"
      ? "Website URL check"
      : "Message analysis";
    name.title = item.preview || "";

    const date = document.createElement("small");
    date.textContent = item.time || "Previous check";

    details.append(name, date);

    const score = document.createElement("span");
    score.className = "recent-score";
    score.textContent = `${item.score}/100`;
    score.style.color =
      item.score >= 60 ? "#ff9298" :
      item.score >= 30 ? "#ffc66d" : "#9af5c7";

    row.append(typeIcon, details, score);
    recentChecksElement.appendChild(row);
  });
}

// Restore dashboard history when the page opens.
renderDashboard();
