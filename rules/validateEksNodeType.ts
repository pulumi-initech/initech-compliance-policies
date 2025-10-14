import { ResourceValidationPolicy, validateResourceOfType } from "@pulumi/policy";
import * as eks from "@pulumi/eks";

export interface InstaceTypePolicyConfig {
    allowedInstanceTypes?: string[];
}

export const validateEksNodeType: ResourceValidationPolicy = {
    name: "validate-instance-types",
    description: "Validate node instance types in EKS Cluster",
    configSchema: {
        properties: {
            allowedInstanceTypes: {
                type: "array",
                items: { type: "string" },
            },
        },
    },
    validateResource: validateResourceOfType(eks.Cluster, (cluster, args, reportViolation) => {
        const config = args.getConfig<InstaceTypePolicyConfig>();

        const allowedInstanceTypes = config.allowedInstanceTypes!;

        if(!isAllowedInstanceType(cluster.instanceType, allowedInstanceTypes)) {
            reportViolation(`Instance type ${cluster.instanceType} is not allowed. Must be one of [${allowedInstanceTypes}]`);
        }
    }),
}

function isAllowedInstanceType(t: string | undefined, allowedInstanceTypes: string[]): boolean {
    return (t !== undefined && allowedInstanceTypes.indexOf(t) !== -1);
}
