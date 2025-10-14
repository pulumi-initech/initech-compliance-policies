import { PolicyResource, StackValidationPolicy } from "@pulumi/policy";

export interface HitrustRegionConfig {
    requiredRegions?: string[];
    requiredTags?: string[];
}

const getAwsProviders = function(resources: PolicyResource[]): PolicyResource[] {
    return resources.filter(r => r.type === "pulumi:providers:aws");
}

const getDefaultAwsProviders = function(resources: PolicyResource[]): PolicyResource[] | undefined {
    return getAwsProviders(resources).filter(p => p.name.startsWith("default"));
}

/**
 * Helper function to safely deserialize defaultTags which may be a string or object
 */
const getDefaultTags = (props: Record<string, any>): Record<string, string> | undefined => {
    const defaultTags = props["defaultTags"];
    if (!defaultTags) {
        return undefined;
    }

    // If it's a string, parse it as JSON
    if (typeof defaultTags === "string") {
        try {
            const parsed = JSON.parse(defaultTags);
            return parsed.tags;
        } catch (e) {
            return undefined;
        }
    }

    // If it's already an object, return tags property
    if (typeof defaultTags === "object" && defaultTags.tags) {
        return defaultTags.tags;
    }

    return undefined;
}


export const validateHitrustAWSProvider: StackValidationPolicy = {
    name: "validate-hitrust-aws-provider",
    description: "Checks whether the AWS provider is configured in the stack.",
    configSchema: {
        properties: {
            requiredRegions: {
                type: "array",
                items: { type: "string" },
            },
            requiredTags: {
                type: "array",
                items: { type: "string" },
            },
        },
    },
    enforcementLevel: "mandatory",
    validateStack: (args, reportViolation) => {

        const hitrustProviders: PolicyResource[] = [];

        const config = args.getConfig<HitrustRegionConfig>();
        const requiredRegions = config.requiredRegions!;
        const requiredTags = config.requiredTags!;

        if(!requiredRegions || requiredRegions.length === 0) {
            reportViolation("No required regions configured for HITRUST compliance.");
            return;
        }

        const awsProviders = getDefaultAwsProviders(args.resources);

        // check if the default provider is configured for Hitrust
        if(awsProviders && awsProviders.length > 0) {
            for (const awsProvider of awsProviders) {
                const ts = getDefaultTags(awsProvider.props);
                if(ts) {
                    if (ts["Compliance"] && ts["Compliance"] === "HITRUST") {
                       hitrustProviders.push(awsProvider);
                    }
                }
            }
        }

        // check if there are any explicit providers with HITRUST tag
        const explicitAwsProviders = getAwsProviders(args.resources).filter(p => !p.name.startsWith("default"));
        for (const awsProvider of explicitAwsProviders) {
            const ts = getDefaultTags(awsProvider.props);
            if(ts) {
                if (ts["Compliance"] && ts["Compliance"] === "HITRUST") {
                   hitrustProviders.push(awsProvider);
                }
            }
        }

        if(hitrustProviders.length === 0) {
            reportViolation("No AWS provider configured for HITRUST compliance.");
            return;
        } else {
            console.log(`Found ${hitrustProviders.length} AWS Provider(s) configured for HITRUST compliance:`);
            hitrustProviders.forEach(p => {
                console.log(`  - ${p.urn} - ${JSON.stringify(p.props)}`);
            });
        }

        // Validate each HITRUST provider
        for (const hitrustProvider of hitrustProviders) {
            // validate region on the hitrust provider
            const region = hitrustProvider.props["region"];
            if(!region || requiredRegions.indexOf(region) === -1) {
                reportViolation(`AWS HITRUST provider '${hitrustProvider.urn}' is not in a required region. Must be one of [${requiredRegions}]`);
            }

            // check if all required tags are present
            const ts = getDefaultTags(hitrustProvider.props);
            if(ts) {
                for (const rt of requiredTags) {
                    if (!ts[rt]) {
                        reportViolation(`AWS provider '${hitrustProvider.urn}' is missing required default tag '${rt}'`);
                    }
                }
            } else {
                reportViolation(`AWS provider '${hitrustProvider.urn}' is missing required tags`);
            }
        }

        // Create a set of valid HITRUST provider URNs for fast lookup
        const hitrustProviderUrns = new Set(hitrustProviders.map(p => p.urn));

        // Check that all AWS resources use one of the HITRUST providers
        for (const r of args.resources.filter(r => r.type.startsWith("aws:"))) {
            const providerUrn = r.provider?.urn;

            if(!providerUrn || !hitrustProviderUrns.has(providerUrn)) {
                reportViolation(`AWS Resource ${r.urn} is not using a HITRUST-compliant AWS provider. Its currently configured to use provider '${providerUrn}'`);
                continue;  // Check next resource
            }

            const tsa = r.props["tagsAll"];
            const ts = r.props["tags"];

            const tags = {...tsa, ...ts};
            // aws provider is configured for hitrust, check required tags on the resource
            for (const rt of requiredTags) {
                if (!tags || !tags[rt]) {
                    reportViolation(`'${r.urn}' is missing required HITRUST tag '${rt}'`);
                }
            }
        }
    }
};