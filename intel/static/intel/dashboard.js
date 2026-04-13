/**
 * Parse JSON chart payload from a Django json_script element.
 * Returns null if the script node is missing or invalid.
 */
function parseChartData(scriptId) {
    const script = document.getElementById(scriptId);
    if (!script) {
        return null;
    }

    try {
        return JSON.parse(script.textContent);
    } catch (error) {
        console.error("Failed to parse chart data", scriptId, error);
        return null;
    }
}

/**
 * Create a Chart.js instance for a target canvas and mark its frame ready.
 * Applies device pixel ratio tuning to improve text crispness.
 */
function buildChart(canvasId, config) {
    if (!window.Chart) {
        return null;
    }

    const canvas = document.getElementById(canvasId);
    if (!canvas) {
        return null;
    }

    const devicePixelRatio = Math.max(1, Math.ceil(window.devicePixelRatio || 1));
    config.options = {
        ...(config.options || {}),
        devicePixelRatio,
    };

    const chart = new window.Chart(canvas, config);
    canvas.closest(".chart-frame")?.classList.add("chart-frame-ready");
    return chart;
}

/**
 * Add confidence severity classes to metadata chips rendered in tables.
 */
function applyConfidenceChipStyles() {
    document.querySelectorAll(".data-chip").forEach((chip) => {
        const text = (chip.textContent || "").trim();
        if (!text.toLowerCase().startsWith("confidence")) {
            return;
        }

        const match = text.match(/(\d+)/);
        if (!match) {
            chip.classList.add("chip-confidence-unknown");
            return;
        }

        const score = Number.parseInt(match[1], 10);
        if (Number.isNaN(score)) {
            chip.classList.add("chip-confidence-unknown");
            return;
        }

        if (score >= 75) {
            chip.classList.add("chip-confidence-high");
            return;
        }
        if (score >= 40) {
            chip.classList.add("chip-confidence-medium");
            return;
        }
        chip.classList.add("chip-confidence-low");
    });
}

document.addEventListener("DOMContentLoaded", () => {
    const devicePixelRatio = Math.max(1, Math.ceil(window.devicePixelRatio || 1));
    const style = window.getComputedStyle(document.documentElement);
    const palette = {
        textMuted: style.getPropertyValue("--text-muted").trim() || "#9fb3cd",
        borderSoft: "rgba(151, 188, 228, 0.16)",
        borderGrid: "rgba(151, 188, 228, 0.12)",
        accent: style.getPropertyValue("--accent").trim() || "#4cc2ff",
        accentStrong: style.getPropertyValue("--accent-strong").trim() || "#2d9fff",
    };

    const chartDefaults = window.Chart?.defaults;
    if (chartDefaults) {
        chartDefaults.devicePixelRatio = devicePixelRatio;
        chartDefaults.color = palette.textMuted;
        chartDefaults.font.family = "\"IBM Plex Sans\", \"Segoe UI\", Tahoma, sans-serif";
        chartDefaults.borderColor = palette.borderSoft;
        chartDefaults.plugins.legend.labels.color = palette.textMuted;
        chartDefaults.plugins.tooltip.backgroundColor = "rgba(9, 18, 35, 0.94)";
        chartDefaults.plugins.tooltip.borderColor = "rgba(130, 188, 247, 0.32)";
        chartDefaults.plugins.tooltip.borderWidth = 1;
        chartDefaults.plugins.tooltip.titleColor = "#eef7ff";
        chartDefaults.plugins.tooltip.bodyColor = "#d6e8fb";
        chartDefaults.plugins.tooltip.padding = 10;
    }

    const timeSeries = parseChartData("time-series-data");
    const typeDistribution = parseChartData("type-distribution-data");
    const malwareDistribution = parseChartData("malware-distribution-data");
    const confidenceDistribution = parseChartData("confidence-distribution-data");
    const familyActivity = parseChartData("family-activity-data");
    const familyTypeDistribution = parseChartData("family-type-data");
    const familySourceDistribution = parseChartData("family-source-data");

    buildChart("time-series-chart", {
        type: "line",
        data: {
            labels: timeSeries?.labels ?? [],
            datasets: [
                {
                    label: "IOC volume",
                    data: timeSeries?.values ?? [],
                    borderColor: palette.accent,
                    backgroundColor: "rgba(76, 194, 255, 0.2)",
                    tension: 0.35,
                    fill: true,
                    pointRadius: 3,
                    pointHoverRadius: 5,
                },
            ],
        },
        options: {
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false,
                },
            },
            scales: {
                x: {
                    grid: {
                        color: palette.borderGrid,
                    },
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0,
                    },
                    grid: {
                        color: palette.borderGrid,
                    },
                },
            },
        },
    });

    buildChart("type-distribution-chart", {
        type: "doughnut",
        data: {
            labels: typeDistribution?.labels ?? [],
            datasets: [
                {
                    data: typeDistribution?.values ?? [],
                    backgroundColor: ["#4cc2ff", "#2d9fff", "#6dd2ff", "#5a8dca", "#7f95b3", "#3db0e9"],
                    borderColor: "#0b1425",
                    borderWidth: 2,
                    radius: "92%",
                },
            ],
        },
        options: {
            maintainAspectRatio: false,
            layout: {
                padding: {
                    top: 4,
                    right: 8,
                    bottom: 4,
                    left: 8,
                },
            },
            plugins: {
                legend: {
                    position: "bottom",
                    align: "center",
                },
            },
        },
    });

    buildChart("confidence-distribution-chart", {
        type: "bar",
        data: {
            labels: confidenceDistribution?.labels ?? [],
            datasets: [
                {
                    label: "Count",
                    data: confidenceDistribution?.values ?? [],
                    backgroundColor: ["#4f647f", "#3a72aa", "#4a8ece", "#3ca9de", "#4cc2ff"],
                    borderRadius: 10,
                },
            ],
        },
        options: {
            plugins: {
                legend: {
                    display: false,
                },
            },
            scales: {
                x: {
                    grid: {
                        display: false,
                    },
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0,
                    },
                    grid: {
                        color: palette.borderGrid,
                    },
                },
            },
        },
    });

    buildChart("malware-distribution-chart", {
        type: "bar",
        data: {
            labels: malwareDistribution?.labels ?? [],
            datasets: [
                {
                    label: "IOC count",
                    data: malwareDistribution?.values ?? [],
                    backgroundColor: "rgba(76, 194, 255, 0.72)",
                    borderColor: "#6dd2ff",
                    borderWidth: 1,
                    borderRadius: 10,
                },
            ],
        },
        options: {
            indexAxis: "y",
            plugins: {
                legend: {
                    display: false,
                },
            },
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0,
                    },
                    grid: {
                        color: palette.borderGrid,
                    },
                },
                y: {
                    grid: {
                        display: false,
                    },
                },
            },
        },
    });

    buildChart("family-activity-chart", {
        type: "line",
        data: {
            labels: familyActivity?.labels ?? [],
            datasets: [
                {
                    label: "Family activity",
                    data: familyActivity?.values ?? [],
                    borderColor: palette.accentStrong,
                    backgroundColor: "rgba(45, 159, 255, 0.18)",
                    tension: 0.3,
                    fill: true,
                    pointRadius: 3,
                },
            ],
        },
        options: {
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false,
                },
            },
            scales: {
                x: {
                    grid: {
                        color: palette.borderGrid,
                    },
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0,
                    },
                    grid: {
                        color: palette.borderGrid,
                    },
                },
            },
        },
    });

    buildChart("family-type-chart", {
        type: "doughnut",
        data: {
            labels: familyTypeDistribution?.labels ?? [],
            datasets: [
                {
                    data: familyTypeDistribution?.values ?? [],
                    backgroundColor: ["#4cc2ff", "#2d9fff", "#6dd2ff", "#5a8dca", "#7f95b3", "#3db0e9"],
                    borderColor: "#0b1425",
                    borderWidth: 2,
                    radius: "92%",
                },
            ],
        },
        options: {
            maintainAspectRatio: false,
            layout: {
                padding: {
                    top: 4,
                    right: 8,
                    bottom: 4,
                    left: 8,
                },
            },
            plugins: {
                legend: {
                    position: "bottom",
                    align: "center",
                },
            },
        },
    });

    buildChart("family-source-chart", {
        type: "polarArea",
        data: {
            labels: familySourceDistribution?.labels ?? [],
            datasets: [
                {
                    data: familySourceDistribution?.values ?? [],
                    backgroundColor: [
                        "rgba(76, 194, 255, 0.65)",
                        "rgba(45, 159, 255, 0.5)",
                        "rgba(109, 210, 255, 0.52)",
                        "rgba(127, 149, 179, 0.46)",
                    ],
                    borderColor: "#0b1425",
                    borderWidth: 2,
                },
            ],
        },
        options: {
            plugins: {
                legend: {
                    position: "bottom",
                },
            },
        },
    });

    applyConfidenceChipStyles();

    document.querySelectorAll(".table-row-link").forEach((row) => {
        row.tabIndex = 0;
        row.setAttribute("role", "link");

        row.addEventListener("click", (event) => {
            const interactiveTarget = event.target.closest("a, button, input, select, textarea");
            if (interactiveTarget) {
                return;
            }
            const href = row.dataset.href;
            if (href) {
                window.location.href = href;
            }
        });

        row.addEventListener("keydown", (event) => {
            if (event.key !== "Enter" && event.key !== " ") {
                return;
            }
            event.preventDefault();
            const href = row.dataset.href;
            if (href) {
                window.location.href = href;
            }
        });
    });
});
