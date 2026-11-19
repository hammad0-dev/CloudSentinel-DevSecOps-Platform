-- Module 10 FE-4/FE-5: admission policy (Kyverno) server dry-run evidence per deployment.
-- Additive: {engine, namespace, checkedAt, passed, blockedByPolicy, violations[{policy,rule,message}], output}.
ALTER TABLE deployment_history ADD COLUMN IF NOT EXISTS policy_validation JSONB;
