#!/usr/bin/env bash
# Commands used for the two Prowler runs in this assessment.
# Profile "lab" = dedicated read-only assessment identity (ViewOnlyAccess + SecurityAudit).
set -euo pipefail

# Run 1 - baseline (31 Oct 2026)
prowler aws --profile lab --compliance cis_3.0_aws \
  --output-formats html \
  --output-directory ./prowler-run-1

# Run 2 - verification after Terraform remediation (3 Nov 2026)
prowler aws --profile lab --compliance cis_3.0_aws \
  --output-formats html json-ocsf csv \
  --output-directory ./prowler-run-2 \
  --mutelist-file ./mutelist.yaml
