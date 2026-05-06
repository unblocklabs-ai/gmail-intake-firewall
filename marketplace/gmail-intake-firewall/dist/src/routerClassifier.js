export function createNoopRouterClassifier() {
    return {
        async classify(input) {
            return {
                tags: [],
                wakeMode: "none",
                sanitizedSummary: input.security.safeSummary || input.message.snippet || input.message.subject || "Safe message with no routing tag.",
                reasons: ["No routing classifier has been configured."],
            };
        },
    };
}
