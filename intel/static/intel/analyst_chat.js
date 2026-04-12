(function () {
    const bootstrapEl = document.getElementById("analyst-chat-bootstrap");
    const form = document.getElementById("assistant-chat-form");
    const thread = document.getElementById("assistant-thread");
    const input = document.getElementById("assistant-chat-input");
    const modeSelect = document.getElementById("assistant-summary-mode");
    const statusEl = document.getElementById("assistant-chat-status");
    const promptGrid = document.getElementById("assistant-prompt-grid");

    if (!bootstrapEl || !form || !thread || !input || !modeSelect || !statusEl || !promptGrid) {
        return;
    }

    const bootstrap = JSON.parse(bootstrapEl.textContent || "{}");

    function getCsrfToken() {
        const match = document.cookie.match(/(?:^|; )csrftoken=([^;]+)/);
        return match ? decodeURIComponent(match[1]) : "";
    }

    function setStatus(text) {
        statusEl.textContent = text;
    }

    function escapeHtml(value) {
        return String(value || "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }

    function renderList(title, items) {
        if (!items || !items.length) {
            return "";
        }
        return [
            '<section class="assistant-response-section">',
            `<h4>${escapeHtml(title)}</h4>`,
            "<ul>",
            items.map((item) => `<li>${escapeHtml(item)}</li>`).join(""),
            "</ul>",
            "</section>",
        ].join("");
    }

    function renderRecords(records) {
        if (!records || !records.length) {
            return "";
        }

        const rows = records
            .map((record) => {
                const valueHtml = record.detail_url
                    ? `<a href="${escapeHtml(record.detail_url)}">${escapeHtml(record.value)}</a>`
                    : escapeHtml(record.value);
                return [
                    "<tr>",
                    `<td>${valueHtml}</td>`,
                    `<td>${escapeHtml(record.value_type)}</td>`,
                    `<td>${escapeHtml(record.source_name)}</td>`,
                    `<td>${escapeHtml(record.confidence_level ?? "N/A")}</td>`,
                    `<td>${escapeHtml(record.threat_type)}</td>`,
                    `<td>${escapeHtml(record.malware_family)}</td>`,
                    "</tr>",
                ].join("");
            })
            .join("");

        return [
            '<section class="assistant-response-section">',
            "<h4>Supporting records</h4>",
            '<div class="table-wrap assistant-table-wrap">',
            '<table class="intel-table assistant-support-table">',
            "<thead><tr><th>IOC</th><th>Type</th><th>Source</th><th>Confidence</th><th>Threat</th><th>Cluster</th></tr></thead>",
            `<tbody>${rows}</tbody>`,
            "</table>",
            "</div>",
            "</section>",
        ].join("");
    }

    function renderMessage(role, payload) {
        const wrapper = document.createElement("article");
        wrapper.className = role === "user" ? "assistant-message assistant-message-user" : "assistant-message";

        if (role === "user") {
            wrapper.innerHTML = [
                '<div class="assistant-message-heading">You</div>',
                `<p class="assistant-message-text">${escapeHtml(payload)}</p>`,
            ].join("");
            thread.appendChild(wrapper);
            thread.scrollTop = thread.scrollHeight;
            return;
        }

        const support = payload.supporting_data || {};
        const supportLines = [];
        if (support.source_breakdown && support.source_breakdown.length) {
            supportLines.push(
                "Sources: " +
                    support.source_breakdown
                        .slice(0, 3)
                        .map((item) => `${item.source} (${item.count})`)
                        .join(", ")
            );
        }
        if (support.cluster_breakdown && support.cluster_breakdown.length) {
            supportLines.push(
                "Clusters: " +
                    support.cluster_breakdown
                        .slice(0, 3)
                        .map((item) => `${item.cluster} (${item.count})`)
                        .join(", ")
            );
        }

        wrapper.innerHTML = [
            '<div class="assistant-message-heading">Analyst Chat</div>',
            `<div class="assistant-message-meta">Mode: ${escapeHtml(payload.summary_mode)} | Provider: ${escapeHtml(payload.provider)} | Source of truth: ${escapeHtml(payload.source_of_truth)}</div>`,
            `<p class="assistant-message-text">${escapeHtml(payload.answer)}</p>`,
            renderList("Key findings", payload.key_findings),
            renderList("Recommended actions", payload.recommended_actions),
            renderList("Uncertainty", payload.uncertainty),
            supportLines.length ? `<p class="assistant-support-copy">${escapeHtml(supportLines.join(" | "))}</p>` : "",
            renderRecords(payload.supporting_records),
        ].join("");

        thread.appendChild(wrapper);
        thread.scrollTop = thread.scrollHeight;
    }

    async function submitPrompt(prompt) {
        renderMessage("user", prompt);
        setStatus("Querying IOC database...");

        try {
            const response = await fetch(bootstrap.api_url, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": getCsrfToken(),
                },
                body: JSON.stringify({
                    prompt: prompt,
                    summary_mode: modeSelect.value,
                    dashboard_filters: bootstrap.filters || {},
                }),
            });

            const payload = await response.json();
            if (!response.ok || !payload.ok) {
                throw new Error(payload.error || "Chat request failed.");
            }

            renderMessage("assistant", payload.response);
            setStatus("Ready");
        } catch (error) {
            renderMessage("assistant", {
                answer: error.message || "Chat request failed.",
                summary_mode: modeSelect.value || "auto",
                provider: "error",
                source_of_truth: "database",
                key_findings: [],
                recommended_actions: [],
                uncertainty: [],
                supporting_records: [],
                supporting_data: {},
            });
            setStatus("Request failed");
        }
    }

    (bootstrap.sample_prompts || []).forEach((prompt) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "chip chip-strong assistant-prompt-chip";
        button.textContent = prompt;
        button.addEventListener("click", function () {
            input.value = prompt;
            input.focus();
        });
        promptGrid.appendChild(button);
    });

    form.addEventListener("submit", function (event) {
        event.preventDefault();
        const prompt = input.value.trim();
        if (!prompt) {
            return;
        }
        input.value = "";
        submitPrompt(prompt);
    });

    renderMessage("assistant", {
        answer: "Ask about a specific IOC, suspicious sources, clusters, enrichment, confidence, or what should be investigated first.",
        summary_mode: "analyst",
        provider: bootstrap.n8n_configured ? "n8n-wired" : "local-database",
        source_of_truth: "database",
        key_findings: [
            "The backend prefers IOC database context as source of truth.",
            "If the n8n webhook is configured, the backend can hand off the same analyst context to that workflow.",
        ],
        recommended_actions: [],
        uncertainty: [],
        supporting_records: [],
        supporting_data: {},
    });
})();
