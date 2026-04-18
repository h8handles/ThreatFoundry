(function () {
    const bootstrapEl = document.getElementById("analyst-chat-bootstrap");
    const form = document.getElementById("assistant-chat-form");
    const thread = document.getElementById("assistant-thread");
    const input = document.getElementById("assistant-chat-input");
    const modeSelect = document.getElementById("assistant-summary-mode");
    const statusEl = document.getElementById("assistant-chat-status");
    const promptGrid = document.getElementById("assistant-prompt-grid");
    const popoutButton = document.getElementById("assistant-popout-button");

    if (!bootstrapEl || !form || !thread || !input || !modeSelect || !statusEl || !promptGrid) {
        return;
    }

    const bootstrap = JSON.parse(bootstrapEl.textContent || "{}");
    const conversationContext = [];
    const maxConversationMessages = 8;

    function openPopoutChat() {
        const popoutUrl = String(bootstrap.popout_url || "");
        if (!popoutUrl.startsWith("/")) {
            setStatus("Pop out unavailable");
            return;
        }

        const popup = window.open(
            popoutUrl,
            "threatfoundry_analyst_chat_popout",
            "popup=yes,width=980,height=760,noopener,noreferrer"
        );
        if (popup) {
            try {
                popup.opener = null;
            } catch (error) {
                // Some browsers prevent changing opener after window.open with noopener.
            }
            popup.focus();
        } else {
            setStatus("Allow pop ups to open chat");
        }
    }

    function getCsrfToken() {
        const match = document.cookie.match(/(?:^|; )csrftoken=([^;]+)/);
        return match ? decodeURIComponent(match[1]) : "";
    }

    function setStatus(text) {
        statusEl.textContent = text;
    }

    function appendTextElement(parent, tagName, className, text) {
        const el = document.createElement(tagName);
        if (className) {
            el.className = className;
        }
        el.textContent = text == null ? "" : String(text);
        parent.appendChild(el);
        return el;
    }

    function renderList(title, items) {
        if (!items || !items.length) {
            return null;
        }
        const section = document.createElement("section");
        section.className = "assistant-response-section";
        appendTextElement(section, "h4", "", title);
        const list = document.createElement("ul");
        items.forEach((item) => appendTextElement(list, "li", "", item));
        section.appendChild(list);
        return section;
    }

    function renderRecords(records) {
        if (!records || !records.length) {
            return null;
        }

        const section = document.createElement("section");
        section.className = "assistant-response-section";
        appendTextElement(section, "h4", "", "Supporting records");

        const tableWrap = document.createElement("div");
        tableWrap.className = "table-wrap assistant-table-wrap";
        const table = document.createElement("table");
        table.className = "intel-table assistant-support-table";
        const thead = document.createElement("thead");
        const headerRow = document.createElement("tr");
        ["IOC", "Type", "Source", "Confidence", "Threat", "Cluster"].forEach((heading) => {
            appendTextElement(headerRow, "th", "", heading);
        });
        thead.appendChild(headerRow);
        table.appendChild(thead);

        const tbody = document.createElement("tbody");
        records.forEach((record) => {
            const row = document.createElement("tr");
            const valueCell = document.createElement("td");
            if (record.detail_url && String(record.detail_url).startsWith("/")) {
                const link = document.createElement("a");
                link.href = record.detail_url;
                link.textContent = record.value || "";
                valueCell.appendChild(link);
            } else {
                valueCell.textContent = record.value || "";
            }
            row.appendChild(valueCell);
            appendTextElement(row, "td", "", record.value_type);
            appendTextElement(row, "td", "", record.source_name);
            appendTextElement(row, "td", "", record.confidence_level ?? "N/A");
            appendTextElement(row, "td", "", record.threat_type);
            appendTextElement(row, "td", "", record.malware_family);
            tbody.appendChild(row);
        });
        table.appendChild(tbody);
        tableWrap.appendChild(table);
        section.appendChild(tableWrap);
        return section;
    }

    function renderMessage(role, payload) {
        const wrapper = document.createElement("article");
        wrapper.className = role === "user" ? "assistant-message assistant-message-user" : "assistant-message";

        if (role === "user") {
            appendTextElement(wrapper, "div", "assistant-message-heading", "You");
            appendTextElement(wrapper, "p", "assistant-message-text", payload);
            thread.appendChild(wrapper);
            thread.scrollTop = thread.scrollHeight;
            rememberMessage("user", payload);
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

        appendTextElement(wrapper, "div", "assistant-message-heading", "Analyst Chat");
        const metaParts = [];
        if (payload.summary_mode) {
            metaParts.push(`Mode: ${payload.summary_mode}`);
        }
        if (payload.provider) {
            metaParts.push(`Provider: ${payload.provider}`);
        }
        if (payload.source_of_truth) {
            metaParts.push(`Source of truth: ${payload.source_of_truth}`);
        }
        if (metaParts.length) {
            appendTextElement(wrapper, "div", "assistant-message-meta", metaParts.join(" | "));
        }
        appendTextElement(wrapper, "p", "assistant-message-text", payload.answer);
        if (payload.reasoning_summary) {
            appendTextElement(wrapper, "p", "assistant-support-copy", payload.reasoning_summary);
        }
        if (payload.confidence) {
            appendTextElement(wrapper, "p", "assistant-support-copy", `Confidence: ${payload.confidence}`);
        }

        responseSectionsFor(payload).forEach((node) => {
            if (node) {
                wrapper.appendChild(node);
            }
        });
        if (supportLines.length) {
            appendTextElement(wrapper, "p", "assistant-support-copy", supportLines.join(" | "));
        }
        const recordsNode = renderRecords(payload.supporting_records);
        if (recordsNode) {
            wrapper.appendChild(recordsNode);
        }

        thread.appendChild(wrapper);
        thread.scrollTop = thread.scrollHeight;
        rememberMessage("assistant", payload.answer || "");
    }

    function responseSectionsFor(payload) {
        const sections = [];
        const mode = String(payload.summary_mode || "").toLowerCase();
        const hasRecords = payload.supporting_records && payload.supporting_records.length;
        if (payload.key_findings && payload.key_findings.length && mode !== "brief") {
            sections.push(renderList(hasRecords ? "Supporting findings" : "Key findings", payload.key_findings));
        }
        if (payload.uncertainty && payload.uncertainty.length) {
            sections.push(renderList("Uncertainty", payload.uncertainty));
        }
        if (payload.recommended_actions && payload.recommended_actions.length && mode !== "executive") {
            sections.push(renderList("Next steps", payload.recommended_actions));
        }
        return sections;
    }

    function rememberMessage(role, content) {
        const text = String(content || "").trim();
        if (!text) {
            return;
        }
        conversationContext.push({
            role: role,
            content: text.slice(0, 900),
        });
        while (conversationContext.length > maxConversationMessages) {
            conversationContext.shift();
        }
    }

    async function submitPrompt(prompt) {
        renderMessage("user", prompt);
        setStatus(bootstrap.n8n_configured ? "Querying analyst workflow..." : "Querying IOC database...");

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
                    conversation_context: conversationContext.slice(0, -1),
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

    if (popoutButton && !bootstrap.is_popout) {
        popoutButton.addEventListener("click", openPopoutChat);
    }

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
    conversationContext.length = 0;
})();
