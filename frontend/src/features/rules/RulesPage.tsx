import { StatusBanner } from "../../shared/ui/StatusBanner";
import type { PageStatus, RuleView } from "../../shared/api/types";

export function RulesPage({ status, rules, detail }: { status: PageStatus; rules: RuleView[]; detail: string }) {
  return (
    <section>
      <h1>Rules</h1>
      <StatusBanner status={status} detail={detail} />
      {rules.map((rule) => (
        <p key={rule.rule_id}>
          {rule.rule_id}: {rule.outcome} ({rule.reason_code})
        </p>
      ))}
    </section>
  );
}
