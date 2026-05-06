import { registerGmailIntakeFirewallPlugin } from "./src/plugin.js";

export default {
  id: "gmail-intake-firewall",
  name: "Gmail Intake Firewall",
  version: "0.1.6",
  register(api: unknown) {
    registerGmailIntakeFirewallPlugin(api);
  },
};

export { registerGmailIntakeFirewallPlugin };
