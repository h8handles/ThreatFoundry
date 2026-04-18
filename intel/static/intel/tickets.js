(function () {
    const storageKey = "threatfoundry.ticketWorkspace.v1";
    const collapseStorageKey = "threatfoundry.ticketPanels.v1";
    const noteFieldStoragePrefix = "threatfoundry.ticketNoteFieldState.";
    const maxTabs = 12;

    function parseState() {
        try {
            const parsed = JSON.parse(window.localStorage.getItem(storageKey) || "{}");
            if (!parsed || !Array.isArray(parsed.tabs)) {
                return { tabs: [], activeId: "" };
            }
            return {
                tabs: parsed.tabs.map(normalizeTab).filter(Boolean).slice(0, maxTabs),
                activeId: normalizeId(parsed.activeId),
            };
        } catch (error) {
            return { tabs: [], activeId: "" };
        }
    }

    function saveState(state) {
        const safeState = {
            tabs: state.tabs.map(normalizeTab).filter(Boolean).slice(0, maxTabs),
            activeId: normalizeId(state.activeId),
        };
        try {
            window.localStorage.setItem(storageKey, JSON.stringify(safeState));
        } catch (error) {
            // Storage can be unavailable in hardened browser modes; the page should still work.
        }
    }

    function parsePanelState() {
        try {
            const parsed = JSON.parse(window.localStorage.getItem(collapseStorageKey) || "{}");
            return parsed && typeof parsed === "object" ? parsed : {};
        } catch (error) {
            return {};
        }
    }

    function savePanelState(state) {
        try {
            window.localStorage.setItem(collapseStorageKey, JSON.stringify(state));
        } catch (error) {
            // Collapsible panels are progressive enhancement only.
        }
    }

    function normalizeId(value) {
        const text = String(value || "").trim();
        return /^\d+$/.test(text) ? text : "";
    }

    function normalizeUrl(value, id) {
        const url = String(value || "").trim();
        if (url.startsWith("/") && !url.startsWith("//")) {
            return url.split("#", 1)[0].split("?", 1)[0];
        }
        return id ? `/tickets/${id}/` : "";
    }

    function normalizeTitle(value, id) {
        const title = String(value || "").replace(/\s+/g, " ").trim();
        return (title || `Ticket ${id}`).slice(0, 80);
    }

    function normalizeTab(tab) {
        if (!tab || typeof tab !== "object") {
            return null;
        }
        const id = normalizeId(tab.id);
        if (!id) {
            return null;
        }
        return {
            id: id,
            title: normalizeTitle(tab.title, id),
            url: normalizeUrl(tab.url, id),
        };
    }

    function urlForMode(tab, isPopout) {
        const baseUrl = normalizeUrl(tab.url, tab.id);
        return isPopout ? `${baseUrl}?popout=1` : baseUrl;
    }

    function upsertTab(state, tab, activate) {
        const normalized = normalizeTab(tab);
        if (!normalized) {
            return state;
        }
        const tabs = state.tabs.filter((item) => item.id !== normalized.id);
        tabs.unshift(normalized);
        state.tabs = tabs.slice(0, maxTabs);
        if (activate) {
            state.activeId = normalized.id;
        }
        return state;
    }

    function closeTab(state, id) {
        const normalizedId = normalizeId(id);
        const nextTabs = state.tabs.filter((tab) => tab.id !== normalizedId);
        const wasActive = state.activeId === normalizedId;
        state.tabs = nextTabs;
        if (wasActive) {
            state.activeId = nextTabs.length ? nextTabs[0].id : "";
        }
        return state;
    }

    function renderTabs(root, state) {
        const tabBar = root.querySelector("#ticket-tab-bar");
        if (!tabBar) {
            return;
        }

        const isPopout = root.getAttribute("data-popout") === "1";
        const nodes = [];
        state.tabs.forEach((tab) => {
            const item = document.createElement("div");
            item.className = "ticket-tab";
            if (tab.id === state.activeId) {
                item.classList.add("is-active");
            }

            const link = document.createElement("a");
            link.className = "ticket-tab-link";
            link.href = urlForMode(tab, isPopout);
            link.textContent = tab.title;
            link.title = tab.title;
            link.addEventListener("click", function () {
                const nextState = parseState();
                nextState.activeId = tab.id;
                saveState(nextState);
            });

            const closeButton = document.createElement("button");
            closeButton.type = "button";
            closeButton.className = "ticket-tab-close";
            closeButton.setAttribute("aria-label", `Close ${tab.title}`);
            closeButton.textContent = "X";
            closeButton.addEventListener("click", function () {
                const nextState = closeTab(parseState(), tab.id);
                saveState(nextState);
                renderTabs(root, nextState);
            });

            item.appendChild(link);
            item.appendChild(closeButton);
            nodes.push(item);
        });

        if (!nodes.length) {
            const empty = document.createElement("p");
            empty.className = "muted ticket-tabs-empty";
            empty.textContent = "No open tickets yet. Select a ticket from the queue to pin it here.";
            nodes.push(empty);
        }
        tabBar.replaceChildren(...nodes);
    }

    function initializeTicketTabs() {
        const root = document.querySelector("[data-ticket-tabs]");
        if (!root) {
            return;
        }

        const currentId = normalizeId(root.getAttribute("data-current-ticket-id"));
        const currentTitle = root.getAttribute("data-current-ticket-title") || "";
        const currentUrl = root.getAttribute("data-current-ticket-url") || "";
        let state = parseState();
        if (currentId) {
            state = upsertTab(
                state,
                {
                    id: currentId,
                    title: currentTitle,
                    url: currentUrl,
                },
                true
            );
            saveState(state);
        }
        renderTabs(root, state);
    }

    function initializeOpenLinks() {
        document.querySelectorAll("[data-ticket-open-link]").forEach((link) => {
            link.addEventListener("click", function () {
                const state = upsertTab(
                    parseState(),
                    {
                        id: link.getAttribute("data-ticket-id"),
                        title: link.getAttribute("data-ticket-title"),
                        url: link.getAttribute("data-ticket-url"),
                    },
                    true
                );
                saveState(state);
            });
        });
    }

    function setPanelCollapsed(panel, collapsed) {
        const body = panel.querySelector(".ticket-panel-body");
        const toggle = panel.querySelector(".ticket-panel-toggle");
        panel.classList.toggle("is-collapsed", collapsed);
        if (body) {
            body.setAttribute("aria-hidden", collapsed ? "true" : "false");
            if (collapsed) {
                body.style.maxHeight = `${body.scrollHeight}px`;
                window.requestAnimationFrame(function () {
                    body.style.maxHeight = "0px";
                });
            } else {
                body.hidden = false;
                body.style.maxHeight = "0px";
                window.requestAnimationFrame(function () {
                    body.style.maxHeight = `${body.scrollHeight}px`;
                    body.querySelectorAll(".ticket-note-form textarea").forEach((textarea) => {
                        resizeTextarea(textarea);
                    });
                });
            }
        }
        if (toggle) {
            toggle.setAttribute("aria-expanded", collapsed ? "false" : "true");
            toggle.textContent = collapsed ? "Expand" : "Collapse";
        }
    }

    function initializeCollapsiblePanels() {
        const panelState = parsePanelState();
        document.querySelectorAll("[data-ticket-collapsible]").forEach((panel) => {
            const key = String(panel.getAttribute("data-ticket-collapse-key") || "").trim();
            const toggle = panel.querySelector(".ticket-panel-toggle");
            if (!key || !toggle) {
                return;
            }

            const body = panel.querySelector(".ticket-panel-body");
            if (body) {
                body.addEventListener("transitionend", function (event) {
                    if (event.propertyName !== "max-height") {
                        return;
                    }
                    if (panel.classList.contains("is-collapsed")) {
                        body.hidden = true;
                    } else {
                        body.style.maxHeight = "";
                    }
                });
            }
            setPanelCollapsed(panel, Boolean(panelState[key]));
            toggle.addEventListener("click", function () {
                const nextState = parsePanelState();
                nextState[key] = !panel.classList.contains("is-collapsed");
                savePanelState(nextState);
                setPanelCollapsed(panel, Boolean(nextState[key]));
            });
        });
    }

    function resizeTextarea(textarea) {
        const maxHeight = 520;
        textarea.style.height = "auto";
        const nextHeight = Math.min(textarea.scrollHeight, maxHeight);
        textarea.style.height = `${nextHeight}px`;
        textarea.style.overflowY = textarea.scrollHeight > maxHeight ? "auto" : "hidden";
    }

    function initializeAutoGrowTextareas() {
        document.querySelectorAll(".ticket-form textarea").forEach((textarea) => {
            resizeTextarea(textarea);
            textarea.addEventListener("input", function () {
                resizeTextarea(textarea);
            });
        });
    }

    function fieldStateStorageKey(ticketId) {
        const normalizedId = normalizeId(ticketId);
        return normalizedId ? `${noteFieldStoragePrefix}${normalizedId}` : "";
    }

    function initializeNoteFieldPreservation() {
        const noteForm = document.querySelector("[data-ticket-note-form]");
        const updateForm = document.getElementById("ticket-update-form");
        if (!noteForm || !updateForm) {
            return;
        }

        const key = fieldStateStorageKey(noteForm.getAttribute("data-ticket-id"));
        if (!key) {
            return;
        }

        try {
            const stored = JSON.parse(window.sessionStorage.getItem(key) || "{}");
            ["status", "priority", "assigned_to"].forEach((name) => {
                const field = updateForm.elements[name];
                if (field && Object.prototype.hasOwnProperty.call(stored, name)) {
                    field.value = String(stored[name] || "");
                }
            });
            window.sessionStorage.removeItem(key);
        } catch (error) {
            try {
                window.sessionStorage.removeItem(key);
            } catch (storageError) {
                // Ignore storage cleanup failures.
            }
        }

        noteForm.addEventListener("submit", function () {
            const state = {};
            ["status", "priority", "assigned_to"].forEach((name) => {
                const field = updateForm.elements[name];
                if (field) {
                    state[name] = field.value;
                }
            });
            try {
                window.sessionStorage.setItem(key, JSON.stringify(state));
            } catch (error) {
                // Field preservation is non-critical.
            }
        });
    }

    function openPopout(event) {
        const button = event.currentTarget;
        const popoutUrl = String(button.getAttribute("data-ticket-popout-url") || "");
        if (!popoutUrl.startsWith("/")) {
            return;
        }

        const popup = window.open(
            popoutUrl,
            "threatfoundry_ticket_popout",
            "popup=yes,width=1080,height=780,noopener,noreferrer"
        );
        if (popup) {
            try {
                popup.opener = null;
            } catch (error) {
                // Some browsers prevent changing opener after window.open with noopener.
            }
            popup.focus();
        }
    }

    document.querySelectorAll(".ticket-popout-button").forEach((button) => {
        button.addEventListener("click", openPopout);
    });
    initializeTicketTabs();
    initializeOpenLinks();
    initializeCollapsiblePanels();
    initializeAutoGrowTextareas();
    initializeNoteFieldPreservation();
})();
