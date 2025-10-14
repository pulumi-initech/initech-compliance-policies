# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a Pulumi Policy Pack for enforcing AWS and Kubernetes compliance policies. It uses the Pulumi Compliance Policy Manager to select and enforce policies from compliance frameworks (CIS, ISO 27001, PCI-DSS, HITRUST) alongside custom organizational policies.

The policy pack name is `initech-org-compliance-policies-aws` and is configured for the "initech" organization.

## Key Commands

**Testing:**
```bash
npm test  # Run unit tests with Mocha
```

**Publishing policy updates:**
```bash
npm run release:patch  # Bump patch version and publish
npm run release:minor  # Bump minor version and publish
npm run release:major  # Bump major version and publish
```

Publishing happens automatically via the `postversion` script which runs `pulumi policy publish`.

**Manual publishing:**
```bash
pulumi policy publish
```

## Architecture

### Policy Configuration ([index.ts:9](index.ts#L9))

The PolicyPack is defined in [index.ts](index.ts) with:
- **Enforcement level**: `advisory` (default)
- **Policy selection** via `policyManager.selectPolicies()` with configurable:
  - `vendors`: Cloud providers (aws, kubernetes)
  - `services`: AWS services (iam, kms, s3, ec2, eks, etc.)
  - `severities`: critical, high, medium, low
  - `frameworks`: cis, iso27001, pcidss, hitrust
  - Per-policy enforcement levels (mandatory, advisory)

### Custom Policies

Custom policies are located in the `rules/` directory:

1. **checkStackTags** ([rules/checkStackTags.ts](rules/checkStackTags.ts)): Validates required tags on AWS resources
   - Fetches list of taggable AWS resource types from Pulumi ESC environment (`initech/shared/policy`)
   - Configured via [policy-config.json](policy-config.json) with `requiredTags` array
   - Uses Pulumi ESC SDK to dynamically load taggable resource types

2. **validateEksNodeType** ([rules/validateEksNodeType.ts](rules/validateEksNodeType.ts)): Validates EKS cluster instance types
   - Checks EKS Cluster node instance types against an allowed list
   - Configurable via policy config with `allowedInstanceTypes`

3. **securityGroupOpenIngresses** ([rules/validateSecurityGroups.ts](rules/validateSecurityGroups.ts)): Validates security group ingress rules

4. **s3BucketLoggingEnabled** ([rules/validateS3.ts](rules/validateS3.ts)): Ensures S3 buckets have logging enabled

5. **hasAwsProvider** ([rules/validateResourceProvider.ts](rules/validateResourceProvider.ts)): Stack-level validation for HITRUST compliance (legacy)
   - Ensures AWS provider is configured with required region and tags for HITRUST
   - Validates all AWS resources use the HITRUST-compliant provider
   - Checks for required tags: Team, BusinessUnit, Environment, Project, ManagedBy
   - Validates resources are in approved regions

6. **validateHitrustAWSProvider** ([rules/validateHitrustAWSProvider.ts](rules/validateHitrustAWSProvider.ts)): Stack-level validation with multiple provider support
   - **Supports multiple HITRUST-compliant AWS providers** in a single stack
   - Each provider can be configured for different regions (e.g., us-east-1, us-west-2)
   - Validates that each HITRUST provider has required region and tags
   - Allows AWS resources to use any of the HITRUST-compliant providers
   - Configurable `requiredRegions` and `requiredTags` via policy config
   - Handles both object and JSON string formats for `defaultTags` deserialization

### Helper Utilities

- **[tagging.ts](tagging.ts)**: Contains static list of 237+ taggable AWS resource types as fallback
- **Policy config** ([policy-config.json](policy-config.json)): JSON configuration for policy parameters

### Policy Manager Integration

The codebase uses `@pulumi/compliance-policy-manager` to:
- Select pre-built compliance policies from multiple frameworks
- Display selection statistics via `displaySelectionStats()` ([index.ts:54](index.ts#L54))
- Combine framework policies with custom organizational rules

### TypeScript Configuration

Compiled to CommonJS (ES6 target) with strict type checking enabled. Output goes to `bin/` directory. Only explicitly listed files in [tsconfig.json](tsconfig.json) are compiled (not all files in `rules/` are currently included).

## Important Implementation Details

**Pulumi ESC Integration**: The `checkStackTags` policy dynamically loads taggable resource types from Pulumi ESC (Environment, Secrets, and Configuration) at runtime. It connects to `initech/shared/policy` environment and expects a `taggableAwsResources` array.

**Stack vs Resource Policies**:
- Stack-level policies (`StackValidationPolicy`) validate entire stacks (e.g., `hasAwsProvider`)
- Resource-level policies (`ResourceValidationPolicy`) validate individual resources (e.g., `checkStackTags`)

**Enforcement Levels**: Policies can be set to `mandatory` (blocks deployment) or `advisory` (warns only). The pack default is advisory, but individual policies can override this.

**Required Environment Variable**: `PULUMI_ACCESS_TOKEN` must be set for ESC integration to work in the tagging policy.

## Testing

Unit tests are written with Mocha and Chai, located in the `test/` directory. Tests use TypeScript via ts-node.

**Writing Tests for Policies**:
- Use the `createMockPolicyResource` helper to create mock `PolicyResource` objects
- Mock `StackValidationArgs` with test resources and config
- Collect violations in an array passed to the `reportViolation` callback
- Test files should follow the pattern `test/**/*.test.ts`

**Example test structure** ([test/validateResourceProvider.test.ts](test/validateResourceProvider.test.ts)):
```typescript
const violations: string[] = [];
const mockArgs: StackValidationArgs = {
    resources: [createMockPolicyResource({...})],
    getConfig: <T>(): T => ({ requiredRegions: ["us-east-1"] } as T),
};
policyToTest.validateStack!(mockArgs, (msg: string) => violations.push(msg));
expect(violations).to.have.lengthOf(1);
```
