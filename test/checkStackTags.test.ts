import { expect } from "chai";
import { describe, it } from "mocha";
import { checkStackTags } from "../rules/checkStackTags";
import { StackValidationArgs } from "@pulumi/policy";

interface StackTagValidationConfig {
    requiredTags?: string[];
}

describe("checkStackTags", () => {
    describe("validateStack", () => {
        it("should pass when all required tags are present", async () => {
            let threwError = false;
            const mockArgs: StackValidationArgs = {
                resources: [],
                stackTags: new Map([
                    ["Owner", "platform-team"],
                ]),
                notApplicable: (reason?: string) => { throw new Error(reason || "Not applicable"); },
                getConfig: <T>(): T => {
                    return {
                        requiredTags: ["Owner"],
                    } as T;
                },
            };

            try {
                await checkStackTags.validateStack!(mockArgs, (msg: string) => {
                    throw new Error(msg);
                });
            } catch (e) {
                threwError = true;
            }

            expect(threwError).to.be.false;
        });

        it("should fail when required Owner tag is missing", async () => {
            let errorMessage = "";
            const mockArgs: StackValidationArgs = {
                resources: [],
                stackTags: new Map([
                    ["Project", "my-project"],
                ]),
                notApplicable: (reason?: string) => { throw new Error(reason || "Not applicable"); },
                getConfig: <T>(): T => {
                    return {
                        requiredTags: ["Owner"],
                    } as T;
                },
            };

            try {
                await checkStackTags.validateStack!(mockArgs, (msg: string) => {
                    throw new Error(msg);
                });
            } catch (e: any) {
                errorMessage = e.message;
            }

            expect(errorMessage).to.include("Missing required Stack Tag: Owner");
        });

        it("should pass when stack has Owner tag", async () => {
            let threwError = false;
            const mockArgs: StackValidationArgs = {
                resources: [],
                stackTags: new Map([
                    ["Owner", "john.doe@example.com"],
                    ["Environment", "production"],
                    ["Project", "my-project"],
                ]),
                notApplicable: (reason?: string) => { throw new Error(reason || "Not applicable"); },
                getConfig: <T>(): T => {
                    return {
                        requiredTags: ["Owner"],
                    } as T;
                },
            };

            try {
                await checkStackTags.validateStack!(mockArgs, (msg: string) => {
                    throw new Error(msg);
                });
            } catch (e) {
                threwError = true;
            }

            expect(threwError).to.be.false;
        });

        it("should fail when stack tags are empty", async () => {
            let errorMessage = "";
            const mockArgs: StackValidationArgs = {
                resources: [],
                stackTags: new Map(),
                notApplicable: (reason?: string) => { throw new Error(reason || "Not applicable"); },
                getConfig: <T>(): T => {
                    return {
                        requiredTags: ["Owner"],
                    } as T;
                },
            };

            try {
                await checkStackTags.validateStack!(mockArgs, (msg: string) => {
                    throw new Error(msg);
                });
            } catch (e: any) {
                errorMessage = e.message;
            }

            expect(errorMessage).to.include("Missing required Stack Tag: Owner");
        });

        it("should pass when Owner tag exists with any value", async () => {
            let threwError = false;
            const mockArgs: StackValidationArgs = {
                resources: [],
                stackTags: new Map([
                    ["Owner", ""],  // Empty string should still be considered present
                ]),
                notApplicable: (reason?: string) => { throw new Error(reason || "Not applicable"); },
                getConfig: <T>(): T => {
                    return {
                        requiredTags: ["Owner"],
                    } as T;
                },
            };

            try {
                await checkStackTags.validateStack!(mockArgs, (msg: string) => {
                    throw new Error(msg);
                });
            } catch (e) {
                threwError = true;
            }

            expect(threwError).to.be.false;
        });

        it("should handle multiple stack tags correctly when Owner is present", async () => {
            let threwError = false;
            const mockArgs: StackValidationArgs = {
                resources: [],
                stackTags: new Map([
                    ["Team", "platform"],
                    ["Owner", "platform-team@example.com"],
                    ["Environment", "staging"],
                    ["Cost-Center", "engineering"],
                ]),
                notApplicable: (reason?: string) => { throw new Error(reason || "Not applicable"); },
                getConfig: <T>(): T => {
                    return {
                        requiredTags: ["Owner"],
                    } as T;
                },
            };

            try {
                await checkStackTags.validateStack!(mockArgs, (msg: string) => {
                    throw new Error(msg);
                });
            } catch (e) {
                threwError = true;
            }

            expect(threwError).to.be.false;
        });
    });
});
