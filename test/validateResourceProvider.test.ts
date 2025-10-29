import { expect } from "chai";
import { describe, it } from "mocha";
import {validateHitrustAWSProvider } from "../rules/validateHitrustAWSProvider";
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
    describe("validateStack", () => {
        it("should pass when AWS provider has HITRUST compliance tags and valid region", () => {
            const violations: string[] = [];
            const mockArgs: StackValidationArgs = {
                stackTags: new Map<string, string>(),
                notApplicable: (reason?: string) => { throw new Error(reason || "notApplicable called"); },
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
                                    BusinessUnit: "Engineering",
                                    Environment: "Production",
                                    Project: "MyProject",
                                    ManagedBy: "Pulumi",
                                },
                            },
                        },
                    }),
                ],
                getConfig: <T>(): T => {
                    return {
                        requiredRegions: ["us-east-1", "us-west-2"],
                        requiredTags: {
                            Team: undefined,
                            BusinessUnit: undefined,
                            Environment: undefined,
                            Project: undefined,
                            ManagedBy: undefined,
                        },
                    } as T;
                },
            };

            validateHitrustAWSProvider.validateStack!(mockArgs, (msg: string) => {
                violations.push(msg);
            });

            expect(violations).to.be.empty;
        });

        it("should fail when no AWS provider exists", () => {
            const violations: string[] = [];
            const mockArgs: StackValidationArgs = {
                stackTags: new Map<string, string>(),
                notApplicable: (reason?: string) => { throw new Error(reason || "notApplicable called"); },
                resources: [],
                getConfig: <T>(): T => {
                    return {
                        requiredRegions: ["us-east-1"],
                        requiredTags: {
                            Team: undefined,
                            BusinessUnit: undefined,
                            Environment: undefined,
                            Project: undefined,
                            ManagedBy: undefined,
                        },
                    } as T;
                },
            };

            validateHitrustAWSProvider.validateStack!(mockArgs, (msg: string) => {
                violations.push(msg);
            });

            expect(violations).to.have.lengthOf(1);
            expect(violations[0]).to.equal("No AWS provider configured for HITRUST compliance.");
        });

        it("should fail when no required regions are configured", () => {
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
                                },
                            },
                        },
                    }),
                ],
                stackTags: new Map<string, string>(),
                notApplicable: (reason?: string) => { throw new Error(reason || "notApplicable called"); },
                getConfig: <T>(): T => {
                    return {
                        requiredRegions: [],
                        requiredTags: {
                            Team: undefined,
                            BusinessUnit: undefined,
                            Environment: undefined,
                            Project: undefined,
                            ManagedBy: undefined,
                        },
                    } as T;
                },
            };

            validateHitrustAWSProvider.validateStack!(mockArgs, (msg: string) => {
                violations.push(msg);
            });

            expect(violations).to.have.lengthOf(1);
            expect(violations[0]).to.equal("No required regions configured for HITRUST compliance.");
        });

        it("should fail when AWS provider is missing HITRUST compliance tag", () => {
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
                                    Team: "Platform",
                                },
                            },
                        },
                    }),
                ],
                stackTags: new Map<string, string>(),
                notApplicable: (reason?: string) => { throw new Error(reason || "notApplicable called"); },
                getConfig: <T>(): T => {
                    return {
                        requiredRegions: ["us-east-1"],
                        requiredTags: {
                            Team: undefined,
                            BusinessUnit: undefined,
                            Environment: undefined,
                            Project: undefined,
                            ManagedBy: undefined,
                        },
                    } as T;
                },
            };

            validateHitrustAWSProvider.validateStack!(mockArgs, (msg: string) => {
                violations.push(msg);
            });

            expect(violations).to.have.lengthOf(1);
            expect(violations[0]).to.equal("No AWS provider configured for HITRUST compliance.");
        });

        it("should fail when AWS provider is in invalid region", () => {
            const violations: string[] = [];
            const mockArgs: StackValidationArgs = {
                resources: [
                    createMockPolicyResource({
                        type: "pulumi:providers:aws",
                        name: "default_6_67_1",
                        urn: "urn:pulumi:dev::my-stack::pulumi:providers:aws::default_6_67_1",
                        props: {
                            region: "eu-west-1",
                            defaultTags: {
                                tags: {
                                    Compliance: "HITRUST",
                                    Team: "Platform",
                                    BusinessUnit: "Engineering",
                                    Environment: "Production",
                                    Project: "MyProject",
                                    ManagedBy: "Pulumi",
                                },
                            },
                        },
                    }),
                ],
                stackTags: new Map<string, string>(),
                notApplicable: (reason?: string) => { throw new Error(reason || "Not applicable"); },
                getConfig: <T>(): T => {
                    return {
                        requiredRegions: ["us-east-1", "us-west-2"],
                        requiredTags: {
                            Team: undefined,
                            BusinessUnit: undefined,
                            Environment: undefined,
                            Project: undefined,
                            ManagedBy: undefined,
                        },
                    } as T;
                },
            };

            validateHitrustAWSProvider.validateStack!(mockArgs, (msg: string) => {
                violations.push(msg);
            });

            expect(violations).to.have.lengthOf(1);
            expect(violations[0]).to.include("is not in a required region");
        });

        it("should fail when AWS provider is missing required tags", () => {
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
                                    // Missing: BusinessUnit, Environment, Project, ManagedBy
                                },
                            },
                        },
                    }),
                ],
                stackTags: new Map<string, string>(),
                notApplicable: (reason?: string) => { throw new Error(reason || "Not applicable"); },
                getConfig: <T>(): T => {
                    return {
                        requiredRegions: ["us-east-1"],
                        requiredTags: {
                            Team: undefined,
                            BusinessUnit: undefined,
                            Environment: undefined,
                            Project: undefined,
                            ManagedBy: undefined,
                        },
                    } as T;
                },
            };

            validateHitrustAWSProvider.validateStack!(mockArgs, (msg: string) => {
                violations.push(msg);
            });

            expect(violations).to.have.lengthOf(4);
            expect(violations[0]).to.include("is missing required default tag 'BusinessUnit'");
            expect(violations[1]).to.include("is missing required default tag 'Environment'");
            expect(violations[2]).to.include("is missing required default tag 'Project'");
            expect(violations[3]).to.include("is missing required default tag 'ManagedBy'");
        });

        it("should check explicit AWS provider when default provider lacks HITRUST tag", () => {
            const violations: string[] = [];
            const mockArgs: StackValidationArgs = {
                stackTags: new Map<string, string>(),
                notApplicable: (reason?: string) => { throw new Error(reason || "notApplicable called"); },
                resources: [
                    createMockPolicyResource({
                        type: "pulumi:providers:aws",
                        name: "default_6_67_1",
                        urn: "urn:pulumi:dev::my-stack::pulumi:providers:aws::default_6_67_1",
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
                        type: "pulumi:providers:aws",
                        name: "hitrust-provider",
                        urn: "urn:pulumi:dev::my-stack::pulumi:providers:aws::hitrust-provider",
                        props: {
                            region: "us-east-1",
                            defaultTags: {
                                tags: {
                                    Compliance: "HITRUST",
                                    Team: "Platform",
                                    BusinessUnit: "Engineering",
                                    Environment: "Production",
                                    Project: "MyProject",
                                    ManagedBy: "Pulumi",
                                },
                            },
                        },
                    }),
                ],
                getConfig: <T>(): T => {
                    return {
                        requiredRegions: ["us-east-1"],
                        requiredTags: {
                            Team: undefined,
                            BusinessUnit: undefined,
                            Environment: undefined,
                            Project: undefined,
                            ManagedBy: undefined,
                        },
                    } as T;
                },
            };

            validateHitrustAWSProvider.validateStack!(mockArgs, (msg: string) => {
                violations.push(msg);
            });

            expect(violations).to.be.empty;
        });

        it("should fail when AWS resources don't use HITRUST provider", () => {
            const violations: string[] = [];
            const hitrustProviderUrn = "urn:pulumi:dev::my-stack::pulumi:providers:aws::default_6_67_1";
            const mockArgs: StackValidationArgs = {
                resources: [
                    createMockPolicyResource({
                        type: "pulumi:providers:aws",
                        name: "default_6_67_1",
                        urn: hitrustProviderUrn,
                        props: {
                            region: "us-east-1",
                            defaultTags: {
                                tags: {
                                    Compliance: "HITRUST",
                                    Team: "Platform",
                                    BusinessUnit: "Engineering",
                                    Environment: "Production",
                                    Project: "MyProject",
                                    ManagedBy: "Pulumi",
                                },
                            },
                        },
                    }),
                    createMockPolicyResource({
                        type: "aws:s3/bucket:Bucket",
                        name: "my-bucket",
                        urn: "urn:pulumi:dev::my-stack::aws:s3/bucket:Bucket::my-bucket",
                        props: {
                            bucket: "my-bucket",
                            tags: {},
                            tagsAll: {},
                        },
                        provider: {
                            urn: "urn:pulumi:dev::my-stack::pulumi:providers:aws::other-provider",
                            type: "pulumi:providers:aws",
                            props: {},
                            name: "other-provider",
                        },
                    }),
                ],
                stackTags: new Map<string, string>(),
                notApplicable: (reason?: string) => { throw new Error(reason || "Not applicable"); },
                getConfig: <T>(): T => {
                    return {
                        requiredRegions: ["us-east-1"],
                        requiredTags: {
                            Team: undefined,
                            BusinessUnit: undefined,
                            Environment: undefined,
                            Project: undefined,
                            ManagedBy: undefined,
                        },
                    } as T;
                },
            };

            validateHitrustAWSProvider.validateStack!(mockArgs, (msg: string) => {
                violations.push(msg);
            });

            expect(violations.length).to.be.greaterThan(0);
            expect(violations[0]).to.include("is not using a HITRUST-compliant AWS provider");
        });

        it("should correctly deserialize defaultTags when it is a JSON string", () => {
            const violations: string[] = [];
            const mockArgs: StackValidationArgs = {
                resources: [
                    createMockPolicyResource({
                        type: "pulumi:providers:aws",
                        name: "default_6_67_1",
                        urn: "urn:pulumi:dev::my-stack::pulumi:providers:aws::default_6_67_1",
                        props: {
                            region: "us-east-1",
                            // Simulate defaultTags as a JSON string (as seen in real Pulumi output)
                            defaultTags: '{"tags":{"Compliance":"HITRUST","Team":"Platform","BusinessUnit":"Engineering","Environment":"Production","Project":"MyProject","ManagedBy":"Pulumi"}}',
                            skipCredentialsValidation: "false",
                            skipRegionValidation: "true",
                            version: "7.8.0",
                        },
                    }),
                ],
                stackTags: new Map<string, string>(),
                notApplicable: (reason?: string) => { throw new Error(reason || "Not applicable"); },
                getConfig: <T>(): T => {
                    return {
                        requiredRegions: ["us-east-1", "us-west-2"],
                        requiredTags: {
                            Team: undefined,
                            BusinessUnit: undefined,
                            Environment: undefined,
                            Project: undefined,
                            ManagedBy: undefined,
                        },
                    } as T;
                },
            };

            validateHitrustAWSProvider.validateStack!(mockArgs, (msg: string) => {
                violations.push(msg);
            });

            expect(violations).to.be.empty;
        });

        it("should fail when defaultTags JSON string is missing HITRUST tag", () => {
            const violations: string[] = [];
            const mockArgs: StackValidationArgs = {
                resources: [
                    createMockPolicyResource({
                        type: "pulumi:providers:aws",
                        name: "default_6_67_1",
                        urn: "urn:pulumi:dev::my-stack::pulumi:providers:aws::default_6_67_1",
                        props: {
                            region: "us-east-1",
                            // Simulate defaultTags as a JSON string without HITRUST
                            defaultTags: '{"tags":{"Team":"Platform","Environment":"Production"}}',
                        },
                    }),
                ],
                stackTags: new Map<string, string>(),
                notApplicable: (reason?: string) => { throw new Error(reason || "Not applicable"); },
                getConfig: <T>(): T => {
                    return {
                        requiredRegions: ["us-east-1"],
                        requiredTags: {
                            Team: undefined,
                            BusinessUnit: undefined,
                            Environment: undefined,
                            Project: undefined,
                            ManagedBy: undefined,
                        },
                    } as T;
                },
            };

            validateHitrustAWSProvider.validateStack!(mockArgs, (msg: string) => {
                violations.push(msg);
            });

            expect(violations).to.have.lengthOf(1);
            expect(violations[0]).to.equal("No AWS provider configured for HITRUST compliance.");
        });

        it("should fail when defaultTags JSON string has HITRUST but missing required tags", () => {
            const violations: string[] = [];
            const mockArgs: StackValidationArgs = {
                resources: [
                    createMockPolicyResource({
                        type: "pulumi:providers:aws",
                        name: "default_6_67_1",
                        urn: "urn:pulumi:dev::my-stack::pulumi:providers:aws::default_6_67_1",
                        props: {
                            region: "us-west-2",
                            // JSON string with HITRUST but missing some required tags
                            defaultTags: '{"tags":{"Compliance":"HITRUST","Team":"Platform"}}',
                        },
                    }),
                ],
                stackTags: new Map<string, string>(),
                notApplicable: (reason?: string) => { throw new Error(reason || "Not applicable"); },
                getConfig: <T>(): T => {
                    return {
                        requiredRegions: ["us-east-1", "us-west-2"],
                        requiredTags: {
                            Team: undefined,
                            BusinessUnit: undefined,
                            Environment: undefined,
                            Project: undefined,
                            ManagedBy: undefined,
                        },
                    } as T;
                },
            };

            validateHitrustAWSProvider.validateStack!(mockArgs, (msg: string) => {
                violations.push(msg);
            });

            expect(violations).to.have.lengthOf(4);
            expect(violations[0]).to.include("is missing required default tag 'BusinessUnit'");
            expect(violations[1]).to.include("is missing required default tag 'Environment'");
            expect(violations[2]).to.include("is missing required default tag 'Project'");
            expect(violations[3]).to.include("is missing required default tag 'ManagedBy'");
        });
    });
});
