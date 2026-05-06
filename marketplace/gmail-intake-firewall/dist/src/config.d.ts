import type { PluginConfig } from "./types.js";
export declare function resolvePluginConfig(rawConfig: unknown): PluginConfig;
export type ConfigValidationFinding = {
    severity: "error" | "warning";
    path: string;
    message: string;
};
export declare function validatePluginConfig(config: PluginConfig): ConfigValidationFinding[];
//# sourceMappingURL=config.d.ts.map