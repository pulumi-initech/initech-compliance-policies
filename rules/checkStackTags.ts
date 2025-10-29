import { StackValidationPolicy } from "@pulumi/policy";

import { strict as assert } from "assert";

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
    validateStack: async (args, _) => {

        const requiredTags = args.getConfig<StackTagValidationConfig>().requiredTags;

        const actualTags = args.stackTags;

        for (const tag of requiredTags || []) {
            assert.ok(actualTags.has(tag), `Missing required Stack Tag: ${tag}`);
        }
    },
}
