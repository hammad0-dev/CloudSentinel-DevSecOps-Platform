// OWASP Top 10 card on the Compliance page. A project-category slot is FAIL when at least one open finding of
// any severity is mapped to that category; no adapter can prove a whole category clean, so PASS never occurs
// and a "pass rate" is always 0% or empty. Shown as "categories with findings" instead.
export const OWASP_EXPLANATION = "Categories with findings counts OWASP Top 10 categories that have at least one open finding of any severity mapped to them. It is not a pass/fail result: the pipeline gates block only CRITICAL/HIGH, so a run can pass its gates and still show MEDIUM/LOW findings here.";

export function owaspCardText(compliance) {
  const m = compliance?.owaspMetrics || {}, matched = compliance?.matching?.owasp?.matched || 0;
  const withFindings = Number(m.FAIL || 0), notAssessed = Number(m.NOT_ASSESSED || 0);
  return {
    description: `${matched}/10 categories matched · ${withFindings} categor${withFindings === 1 ? "y" : "ies"} with findings · ${notAssessed} without findings (not assessed) — project-category slots`,
    note: OWASP_EXPLANATION,
  };
}
