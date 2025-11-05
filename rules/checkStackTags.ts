import { StackValidationPolicy } from "@pulumi/policy";

interface StackTagValidationConfig {
    requiredTags?: string[];
}

export const checkStackTags: StackValidationPolicy = {
    name: "check-required-stack-tags",
    description: "Ensure required tags are present on all stacks.",
    enforcementLevel: "advisory",
    configSchema: {
        properties: {
              requiredTags: {
                type: "array",
                items: { type: "string" },
            },
        },
    },
    validateStack: async (args, reportViolation) => {
        const requiredTags = args.getConfig<StackTagValidationConfig>().requiredTags;
        const actualTags = args.stackTags;
        for (const tag of requiredTags || []) {
            if (!actualTags.has(tag)) {
                reportViolation(`Missing required Stack Tag: ${tag}`);
            }
        }
    },
}
