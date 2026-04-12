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

function buildChart(canvasId, config) {
    if (!window.Chart) {
        return;
    }

    const canvas = document.getElementById(canvasId);
    if (!canvas) {
        return;
    }

    new window.Chart(canvas, config);
}

document.addEventListener("DOMContentLoaded", () => {
    const chartDefaults = window.Chart?.defaults;
    if (chartDefaults) {
        chartDefaults.color = "#9aaecc";
        chartDefaults.font.family = "\"IBM Plex Sans\", \"Segoe UI\", Tahoma, sans-serif";
        chartDefaults.borderColor = "rgba(255,255,255,0.08)";
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
                    borderColor: "#2fe0ff",
                    backgroundColor: "rgba(47, 224, 255, 0.18)",
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
                        color: "rgba(255,255,255,0.04)",
                    },
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0,
                    },
                    grid: {
                        color: "rgba(255,255,255,0.06)",
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
                    backgroundColor: ["#2fe0ff", "#63e9ff", "#7bc8ff", "#b8c6dc", "#4f8dff", "#14b5e6"],
                    borderColor: "#071122",
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

    buildChart("confidence-distribution-chart", {
        type: "bar",
        data: {
            labels: confidenceDistribution?.labels ?? [],
            datasets: [
                {
                    label: "Count",
                    data: confidenceDistribution?.values ?? [],
                    backgroundColor: ["#4f647f", "#2f6db2", "#4f8dff", "#2cc7ef", "#2fe0ff"],
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
                        color: "rgba(255,255,255,0.06)",
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
                    backgroundColor: "rgba(47, 224, 255, 0.72)",
                    borderColor: "#63e9ff",
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
                        color: "rgba(255,255,255,0.06)",
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
                    borderColor: "#63e9ff",
                    backgroundColor: "rgba(99, 233, 255, 0.16)",
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
                        color: "rgba(255,255,255,0.04)",
                    },
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0,
                    },
                    grid: {
                        color: "rgba(255,255,255,0.06)",
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
                    backgroundColor: ["#2fe0ff", "#63e9ff", "#7bc8ff", "#b8c6dc", "#4f8dff", "#14b5e6"],
                    borderColor: "#071122",
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

    buildChart("family-source-chart", {
        type: "polarArea",
        data: {
            labels: familySourceDistribution?.labels ?? [],
            datasets: [
                {
                    data: familySourceDistribution?.values ?? [],
                    backgroundColor: [
                        "rgba(47, 224, 255, 0.6)",
                        "rgba(99, 233, 255, 0.45)",
                        "rgba(79, 141, 255, 0.5)",
                        "rgba(184, 198, 220, 0.45)",
                    ],
                    borderColor: "#071122",
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

    // Domain enrichment panel
    const domainEnrichmentData = parseChartData("domain-enrichment-data");
    if (domainEnrichmentData) {
        const panel = document.getElementById("domain-enrichment-panel");
        if (panel) {
            panel.innerHTML = `
                <h3>Domain Enrichment</h3>
                <ul>
                    <li>Registrar: ${domainEnrichmentData.registrar || "N/A"}</li>
                    <li>Domain Age: ${domainEnrichmentData.domain_age_days !== undefined ? domainEnrichmentData.domain_age_days + " days" : "N/A"}</li>
                    <li>Nameservers: ${domainEnrichmentData.nameservers?.join(", ") || "N/A"}</li>
                    <li>Resolved IPs: ${domainEnrichmentData.resolved_ips?.join(", ") || "N/A"}</li>
                    <li>Reputation Sources: ${domainEnrichmentData.reputation_sources?.join(", ") || "N/A"}</li>
                    <li>Certificate SHA256: ${domainEnrichmentData.cert_sha256 || "N/A"}</li>
                </ul>
            `;
        }
    }

    document.querySelectorAll(".table-row-link").forEach((row) => {
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
    });
});
