import { ResourceValidationPolicy, validateResourceOfType } from "@pulumi/policy";
import * as esc from "@pulumi/esc-sdk";

const config = new esc.Configuration({ accessToken: process.env.PULUMI_ACCESS_TOKEN! });
const client = new esc.EscApi(config);

const orgName = "initech";
const projName = "shared";
const envName = "policy";

export interface AwsTagsPolicyConfig {
    requiredTags?: string[];
}

let taggableAwsResources: string[] | undefined = undefined;

export const checkStackTags: ResourceValidationPolicy = {
    name: "check-required-aws-tags",
    description: "Ensure required tags are present on all AWS resources.",
    configSchema: {
        properties: {
            requiredTags: {
                type: "array",
                items: { type: "string" },
            },
        },
    },
    enforcementLevel: "mandatory",
    validateResource: async (args, reportViolation) => {
        const config = args.getConfig<AwsTagsPolicyConfig>();
        const requiredTags = config.requiredTags;
        if (requiredTags && await isTaggable(args.type)) {
            const ts = args.props["tags"];
            const tsa = args.props["tagsAll"];

            for (const rt of requiredTags) {
                if (!ts || !ts[rt]) {
                    reportViolation(`Taggable resource '${args.urn}' is missing required tag '${rt}'`);
                }
            }
        }
    },
}

async function isTaggable(t: string): Promise<boolean> {
    
    if (!taggableAwsResources) {
        let openEnv = await client.openAndReadEnvironment(orgName, projName, envName);
        taggableAwsResources = openEnv!.values?.taggableAwsResources as string[];
    }

    return (taggableAwsResources.indexOf(t) !== -1);
}
