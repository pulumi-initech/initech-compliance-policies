import { expect } from "chai";
import { describe, it } from "mocha";
import { validateHitrustAWSProvider } from "../rules/validateHitrustAWSProvider";
import { PolicyResource, StackValidationArgs } from "@pulumi/policy";

// Helper function to create a mock PolicyResource
function createMockPolicyResource(partial: Partial<PolicyResource>): PolicyResource {
    return {
        type: partial.type || "",
        name: partial.name || "",
        urn: partial.urn || "",
        props: partial.props || {},
        opts: {
            protect: false,
            ignoreChanges: [],
            aliases: [],
            customTimeouts: {},
            additionalSecretOutputs: [],
        },
        dependencies: [],
        propertyDependencies: {},
        provider: partial.provider,
        isType: () => false,
        asType: () => undefined,
    } as unknown as PolicyResource;
}

describe("validateHitrustAWSProvider", () => {
    describe("validateStack - multiple providers", () => {
        it("should pass when single AWS provider has HITRUST compliance", () => {
            const violations: string[] = [];
            const mockArgs: StackValidationArgs = {
                resources: [
                    createMockPolicyResource({
                        type: "pulumi:providers:aws",
                        name: "default_6_67_1",
                        urn: "urn:pulumi:dev::my-stack::pulumi:providers:aws::default_6_67_1",
                        props: {
                            region: "us-east-1",
                            defaultTags: {
                                tags: {
                                    Compliance: "HITRUST",
                                    Team: "Platform",
                                    Environment: "Production",
                                },
                            },
                        },
                    }),
                ],
                stackTags: new Map(),
                notApplicable: (reason?: string) => { throw new Error(reason || "Not applicable"); },
                getConfig: <T>(): T => {
                    return {
                        requiredRegions: ["us-east-1", "us-west-2"],
                        requiredTags: {
                            Team: undefined,
                            Environment: undefined,
                        },
                    } as T;
                },
            };

            validateHitrustAWSProvider.validateStack!(mockArgs, (msg: string) => {
                violations.push(msg);
            });

            expect(violations).to.be.empty;
        });

        it("should pass when multiple AWS providers are configured for HITRUST", () => {
            const violations: string[] = [];
            const mockArgs: StackValidationArgs = {
                resources: [
                    createMockPolicyResource({
                        type: "pulumi:providers:aws",
                        name: "hitrust-us-east-1",
                        urn: "urn:pulumi:dev::my-stack::pulumi:providers:aws::hitrust-us-east-1",
                        props: {
                            region: "us-east-1",
                            defaultTags: {
                                tags: {
                                    Compliance: "HITRUST",
                                    Team: "Platform",
                                    Environment: "Production",
                                },
                            },
                        },
                    }),
                    createMockPolicyResource({
                        type: "pulumi:providers:aws",
                        name: "hitrust-us-west-2",
                        urn: "urn:pulumi:dev::my-stack::pulumi:providers:aws::hitrust-us-west-2",
                        props: {
                            region: "us-west-2",
                            defaultTags: {
                                tags: {
                                    Compliance: "HITRUST",
                                    Team: "Platform",
                                    Environment: "Production",
                                },
                            },
                        },
                    }),
                ],
                stackTags: new Map(),
                notApplicable: (reason?: string) => { throw new Error(reason || "Not applicable"); },
                getConfig: <T>(): T => {
                    return {
                        requiredRegions: ["us-east-1", "us-west-2"],
                        requiredTags: {
                            Team: undefined,
                            Environment: undefined,
                        },
                    } as T;
                },
            };

            validateHitrustAWSProvider.validateStack!(mockArgs, (msg: string) => {
                violations.push(msg);
            });

            expect(violations).to.be.empty;
        });

        it("should allow AWS resources to use any HITRUST provider", () => {
            const violations: string[] = [];
            const provider1Urn = "urn:pulumi:dev::my-stack::pulumi:providers:aws::hitrust-us-east-1";
            const provider2Urn = "urn:pulumi:dev::my-stack::pulumi:providers:aws::hitrust-us-west-2";

            const mockArgs: StackValidationArgs = {
                resources: [
                    createMockPolicyResource({
                        type: "pulumi:providers:aws",
                        name: "hitrust-us-east-1",
                        urn: provider1Urn,
                        props: {
                            region: "us-east-1",
                            defaultTags: {
                                tags: {
                                    Compliance: "HITRUST",
                                    Team: "Platform",
                                    Environment: "Production",
                                },
                            },
                        },
                    }),
                    createMockPolicyResource({
                        type: "pulumi:providers:aws",
                        name: "hitrust-us-west-2",
                        urn: provider2Urn,
                        props: {
                            region: "us-west-2",
                            defaultTags: {
                                tags: {
                                    Compliance: "HITRUST",
                                    Team: "Platform",
                                    Environment: "Production",
                                },
                            },
                        },
                    }),
                    createMockPolicyResource({
                        type: "aws:s3/bucket:Bucket",
                        name: "bucket-east",
                        urn: "urn:pulumi:dev::my-stack::aws:s3/bucket:Bucket::bucket-east",
                        props: {
                            bucket: "bucket-east",
                            tags: { Team: "Platform", Environment: "Production" },
                            tagsAll: { Team: "Platform", Environment: "Production" },
                        },
                        provider: {
                            urn: provider1Urn,
                            type: "pulumi:providers:aws",
                            props: {},
                            name: "hitrust-us-east-1",
                        },
                    }),
                    createMockPolicyResource({
                        type: "aws:s3/bucket:Bucket",
                        name: "bucket-west",
                        urn: "urn:pulumi:dev::my-stack::aws:s3/bucket:Bucket::bucket-west",
                        props: {
                            bucket: "bucket-west",
                            tags: { Team: "Platform", Environment: "Production" },
                            tagsAll: { Team: "Platform", Environment: "Production" },
                        },
                        provider: {
                            urn: provider2Urn,
                            type: "pulumi:providers:aws",
                            props: {},
                            name: "hitrust-us-west-2",
                        },
                    }),
                ],
                stackTags: new Map(),
                notApplicable: (reason?: string) => { throw new Error(reason || "Not applicable"); },
                getConfig: <T>(): T => {
                    return {
                        requiredRegions: ["us-east-1", "us-west-2"],
                        requiredTags: {
                            Team: undefined,
                            Environment: undefined,
                        },
                    } as T;
                },
            };

            validateHitrustAWSProvider.validateStack!(mockArgs, (msg: string) => {
                violations.push(msg);
            });

            expect(violations).to.be.empty;
        });

        it("should fail when one of multiple providers is in invalid region", () => {
            const violations: string[] = [];
            const mockArgs: StackValidationArgs = {
                resources: [
                    createMockPolicyResource({
                        type: "pulumi:providers:aws",
                        name: "hitrust-us-east-1",
                        urn: "urn:pulumi:dev::my-stack::pulumi:providers:aws::hitrust-us-east-1",
                        props: {
                            region: "us-east-1",
                            defaultTags: {
                                tags: {
                                    Compliance: "HITRUST",
                                    Team: "Platform",
                                    Environment: "Production",
                                },
                            },
                        },
                    }),
                    createMockPolicyResource({
                        type: "pulumi:providers:aws",
                        name: "hitrust-eu-west-1",
                        urn: "urn:pulumi:dev::my-stack::pulumi:providers:aws::hitrust-eu-west-1",
                        props: {
                            region: "eu-west-1",
                            defaultTags: {
                                tags: {
                                    Compliance: "HITRUST",
                                    Team: "Platform",
                                    Environment: "Production",
                                },
                            },
                        },
                    }),
                ],
                stackTags: new Map(),
                notApplicable: (reason?: string) => { throw new Error(reason || "Not applicable"); },
                getConfig: <T>(): T => {
                    return {
                        requiredRegions: ["us-east-1", "us-west-2"],
                        requiredTags: {
                            Team: undefined,
                            Environment: undefined,
                        },
                    } as T;
                },
            };

            validateHitrustAWSProvider.validateStack!(mockArgs, (msg: string) => {
                violations.push(msg);
            });

            expect(violations).to.have.lengthOf(1);
            expect(violations[0]).to.include("hitrust-eu-west-1");
            expect(violations[0]).to.include("is not in a required region");
        });

        it("should fail when resource uses non-HITRUST provider alongside HITRUST providers", () => {
            const violations: string[] = [];
            const hitrustProviderUrn = "urn:pulumi:dev::my-stack::pulumi:providers:aws::hitrust-provider";
            const nonHitrustProviderUrn = "urn:pulumi:dev::my-stack::pulumi:providers:aws::regular-provider";

            const mockArgs: StackValidationArgs = {
                resources: [
                    createMockPolicyResource({
                        type: "pulumi:providers:aws",
                        name: "hitrust-provider",
                        urn: hitrustProviderUrn,
                        props: {
                            region: "us-east-1",
                            defaultTags: {
                                tags: {
                                    Compliance: "HITRUST",
                                    Team: "Platform",
                                    Environment: "Production",
                                },
                            },
                        },
                    }),
                    createMockPolicyResource({
                        type: "pulumi:providers:aws",
                        name: "regular-provider",
                        urn: nonHitrustProviderUrn,
                        props: {
                            region: "us-east-1",
                            defaultTags: {
                                tags: {
                                    Team: "Platform",
                                },
                            },
                        },
                    }),
                    createMockPolicyResource({
                        type: "aws:s3/bucket:Bucket",
                        name: "non-compliant-bucket",
                        urn: "urn:pulumi:dev::my-stack::aws:s3/bucket:Bucket::non-compliant-bucket",
                        props: {
                            bucket: "non-compliant-bucket",
                            tags: { Team: "Platform", Environment: "Production" },
                            tagsAll: { Team: "Platform", Environment: "Production" },
                        },
                        provider: {
                            urn: nonHitrustProviderUrn,
                            type: "pulumi:providers:aws",
                            props: {},
                            name: "regular-provider",
                        },
                    }),
                ],
                stackTags: new Map(),
                notApplicable: (reason?: string) => { throw new Error(reason || "Not applicable"); },
                getConfig: <T>(): T => {
                    return {
                        requiredRegions: ["us-east-1"],
                        requiredTags: {
                            Team: undefined,
                            Environment: undefined,
                        },
                    } as T;
                },
            };

            validateHitrustAWSProvider.validateStack!(mockArgs, (msg: string) => {
                violations.push(msg);
            });

            expect(violations.length).to.be.greaterThan(0);
            expect(violations[0]).to.include("non-compliant-bucket");
            expect(violations[0]).to.include("is not using a HITRUST-compliant AWS provider");
        });

        it("should fail when one of multiple providers is missing required tags", () => {
            const violations: string[] = [];
            const mockArgs: StackValidationArgs = {
                resources: [
                    createMockPolicyResource({
                        type: "pulumi:providers:aws",
                        name: "hitrust-complete",
                        urn: "urn:pulumi:dev::my-stack::pulumi:providers:aws::hitrust-complete",
                        props: {
                            region: "us-east-1",
                            defaultTags: {
                                tags: {
                                    Compliance: "HITRUST",
                                    Team: "Platform",
                                    Environment: "Production",
                                },
                            },
                        },
                    }),
                    createMockPolicyResource({
                        type: "pulumi:providers:aws",
                        name: "hitrust-incomplete",
                        urn: "urn:pulumi:dev::my-stack::pulumi:providers:aws::hitrust-incomplete",
                        props: {
                            region: "us-west-2",
                            defaultTags: {
                                tags: {
                                    Compliance: "HITRUST",
                                    Team: "Platform",
                                    // Missing Environment tag
                                },
                            },
                        },
                    }),
                ],
                stackTags: new Map(),
                notApplicable: (reason?: string) => { throw new Error(reason || "Not applicable"); },
                getConfig: <T>(): T => {
                    return {
                        requiredRegions: ["us-east-1", "us-west-2"],
                        requiredTags: {
                            Team: undefined,
                            Environment: undefined,
                        },
                    } as T;
                },
            };

            validateHitrustAWSProvider.validateStack!(mockArgs, (msg: string) => {
                violations.push(msg);
            });

            expect(violations).to.have.lengthOf(1);
            expect(violations[0]).to.include("hitrust-incomplete");
            expect(violations[0]).to.include("is missing required default tag 'Environment'");
        });

        it("should fail when Environment tag has invalid enum value on provider", () => {
            const violations: string[] = [];
            const mockArgs: StackValidationArgs = {
                resources: [
                    createMockPolicyResource({
                        type: "pulumi:providers:aws",
                        name: "hitrust-provider",
                        urn: "urn:pulumi:dev::my-stack::pulumi:providers:aws::hitrust-provider",
                        props: {
                            region: "us-east-1",
                            defaultTags: {
                                tags: {
                                    Compliance: "HITRUST",
                                    Team: "Platform",
                                    Environment: "prod",  // Invalid - should be production, staging, or development
                                },
                            },
                        },
                    }),
                ],
                stackTags: new Map(),
                notApplicable: (reason?: string) => { throw new Error(reason || "Not applicable"); },
                getConfig: <T>(): T => {
                    return {
                        requiredRegions: ["us-east-1"],
                        requiredTags: {
                            Team: undefined,
                            Environment: "production",
                        },
                    } as T;
                },
            };

            validateHitrustAWSProvider.validateStack!(mockArgs, (msg: string) => {
                violations.push(msg);
            });

            expect(violations).to.have.lengthOf(1);
            expect(violations[0]).to.include("Environment");
            expect(violations[0]).to.include("must be one of [production, staging, development]");
            expect(violations[0]).to.include("but got 'prod'");
        });

        it("should fail when ManagedBy tag is not 'pulumi' on provider", () => {
            const violations: string[] = [];
            const mockArgs: StackValidationArgs = {
                resources: [
                    createMockPolicyResource({
                        type: "pulumi:providers:aws",
                        name: "hitrust-provider",
                        urn: "urn:pulumi:dev::my-stack::pulumi:providers:aws::hitrust-provider",
                        props: {
                            region: "us-east-1",
                            defaultTags: {
                                tags: {
                                    Compliance: "HITRUST",
                                    Team: "Platform",
                                    ManagedBy: "terraform",  // Invalid - must be "pulumi"
                                },
                            },
                        },
                    }),
                ],
                stackTags: new Map(),
                notApplicable: (reason?: string) => { throw new Error(reason || "Not applicable"); },
                getConfig: <T>(): T => {
                    return {
                        requiredRegions: ["us-east-1"],
                        requiredTags: {
                            Team: undefined,
                            ManagedBy: "pulumi",
                        },
                    } as T;
                },
            };

            validateHitrustAWSProvider.validateStack!(mockArgs, (msg: string) => {
                violations.push(msg);
            });

            expect(violations).to.have.lengthOf(1);
            expect(violations[0]).to.include("ManagedBy");
            expect(violations[0]).to.include("must be 'pulumi'");
            expect(violations[0]).to.include("but got 'terraform'");
        });

        it("should fail when resource has invalid Environment tag value", () => {
            const violations: string[] = [];
            const providerUrn = "urn:pulumi:dev::my-stack::pulumi:providers:aws::hitrust-provider";
            const mockArgs: StackValidationArgs = {
                resources: [
                    createMockPolicyResource({
                        type: "pulumi:providers:aws",
                        name: "hitrust-provider",
                        urn: providerUrn,
                        props: {
                            region: "us-east-1",
                            defaultTags: {
                                tags: {
                                    Compliance: "HITRUST",
                                    Team: "Platform",
                                    Environment: "production",
                                },
                            },
                        },
                    }),
                    createMockPolicyResource({
                        type: "aws:s3/bucket:Bucket",
                        name: "test-bucket",
                        urn: "urn:pulumi:dev::my-stack::aws:s3/bucket:Bucket::test-bucket",
                        props: {
                            bucket: "test-bucket",
                            tags: { Team: "Platform", Environment: "dev" },  // Invalid enum value
                            tagsAll: { Team: "Platform", Environment: "dev" },
                        },
                        provider: {
                            urn: providerUrn,
                            type: "pulumi:providers:aws",
                            props: {},
                            name: "hitrust-provider",
                        },
                    }),
                ],
                stackTags: new Map(),
                notApplicable: (reason?: string) => { throw new Error(reason || "Not applicable"); },
                getConfig: <T>(): T => {
                    return {
                        requiredRegions: ["us-east-1"],
                        requiredTags: {
                            Team: undefined,
                            Environment: "production",
                        },
                    } as T;
                },
            };

            validateHitrustAWSProvider.validateStack!(mockArgs, (msg: string) => {
                violations.push(msg);
            });

            expect(violations).to.have.lengthOf(1);
            expect(violations[0]).to.include("test-bucket");
            expect(violations[0]).to.include("Environment");
            expect(violations[0]).to.include("must be one of [production, staging, development]");
        });
    });
});
