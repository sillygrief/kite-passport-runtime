# Changes

## 0.2.0 — 2026-10-28

request_session returns AllowanceAvailable, ReuseCandidate, ExistingSessionReview, HumanActionRequired or Blocked instead of treating every create as an approval request. use_allowance(operation_id, confirmed_allowance=True) binds an already selected allowance, without silently switching from a separate session. separate_session previews first; confirmed=True requires a stored preview. accept_reuse supports the documented reuse_candidates array and requires an explicit same-goal decision. Discovery uses service list --query / service get with JSON output; legacy service search is still documented upstream.

This evaluation update retains explicit blocked real-payment, public-hosting and official-listing gates. Prior releases remain available.
