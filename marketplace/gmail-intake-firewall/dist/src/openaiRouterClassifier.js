export function createOpenAiRouterClassifier(options) {
    const fetchImpl = options.fetch ?? fetch;
    return {
        async classify(input, tags) {
            if (tags.length === 0) {
                return {
                    tags: [],
                    wakeMode: "none",
                    sanitizedSummary: input.security.safeSummary || input.message.snippet || "Safe message with no routing tag.",
                    reasons: ["No routing tags are configured."],
                };
            }
            try {
                const response = await fetchImpl("https://api.openai.com/v1/responses", {
                    method: "POST",
                    headers: {
                        "Authorization": `Bearer ${options.apiKey}`,
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify(buildRequest(options.model, input.normalized, input.security.safeSummary, tags)),
                });
                if (!response.ok) {
                    return noRoute(`OpenAI router classifier failed with HTTP ${response.status}.`, input.security.safeSummary);
                }
                return normalizeRouting(parseOutputJson(await response.json()), tags, input.security.safeSummary);
            }
            catch (error) {
                return noRoute(error instanceof Error ? error.message : String(error), input.security.safeSummary);
            }
        },
    };
}
function buildRequest(model, normalizedMessage, securitySummary, tags) {
    return {
        model,
        input: [
            {
                role: "developer",
                content: [{
                        type: "input_text",
                        text: [
                            "You are the Gmail intake routing classifier for OpenClaw.",
                            "The message has already passed security classification.",
                            "Choose zero or more tag ids only from the configured tag list.",
                            "Do not invent tags, wake targets, or policies. Wake behavior is derived from tag config by the plugin.",
                            "Return only the requested structured routing result.",
                        ].join("\n"),
                    }],
            },
            {
                role: "user",
                content: [{
                        type: "input_text",
                        text: JSON.stringify({
                            tags: tags.map((tag) => ({
                                id: tag.id,
                                description: tag.description,
                                wakeMode: tag.wakeMode,
                                aggregateCadence: tag.aggregateCadence,
                                wakeTarget: tag.wakeTarget,
                            })),
                            securitySummary,
                            message: normalizedMessage,
                        }),
                    }],
            },
        ],
        text: {
            format: {
                type: "json_schema",
                name: "gmail_routing_classification",
                strict: true,
                schema: {
                    type: "object",
                    additionalProperties: false,
                    properties: {
                        tags: { type: "array", items: { type: "string" } },
                        sanitizedSummary: { type: "string" },
                        reasons: { type: "array", items: { type: "string" } },
                    },
                    required: ["tags", "sanitizedSummary", "reasons"],
                },
            },
        },
    };
}
function parseOutputJson(response) {
    const raw = response && typeof response === "object" ? response : {};
    if (typeof raw.output_text === "string") {
        return JSON.parse(raw.output_text);
    }
    const output = Array.isArray(raw.output) ? raw.output : [];
    for (const item of output) {
        const content = item && typeof item === "object" && Array.isArray(item.content)
            ? item.content
            : [];
        for (const contentItem of content) {
            if (contentItem && typeof contentItem === "object") {
                const text = contentItem.text;
                if (typeof text === "string") {
                    return JSON.parse(text);
                }
            }
        }
    }
    throw new Error("OpenAI response did not contain structured output text.");
}
function normalizeRouting(value, tags, fallbackSummary) {
    const raw = value && typeof value === "object" ? value : {};
    const validTagIds = new Set(tags.map((tag) => tag.id));
    const selectedTags = Array.isArray(raw.tags)
        ? raw.tags.filter((tag) => typeof tag === "string" && validTagIds.has(tag))
        : [];
    return {
        tags: selectedTags,
        wakeMode: deriveWakeMode(selectedTags, tags),
        sanitizedSummary: typeof raw.sanitizedSummary === "string" && raw.sanitizedSummary.trim()
            ? raw.sanitizedSummary.trim()
            : fallbackSummary,
        reasons: Array.isArray(raw.reasons) ? raw.reasons.filter((reason) => typeof reason === "string") : [],
    };
}
function deriveWakeMode(selectedTags, tags) {
    const selected = selectedTags.flatMap((id) => {
        const tag = tags.find((candidate) => candidate.id === id);
        return tag ? [tag] : [];
    });
    if (selected.some((tag) => tag.wakeMode === "wake_now")) {
        return "wake_now";
    }
    if (selected.some((tag) => tag.wakeMode === "aggregate")) {
        return "aggregate";
    }
    return "none";
}
function noRoute(reason, fallbackSummary) {
    return {
        tags: [],
        wakeMode: "none",
        sanitizedSummary: fallbackSummary,
        reasons: [reason],
    };
}
