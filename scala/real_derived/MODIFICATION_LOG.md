# Reference set: provenance and record of modifications

Source: real playbooks from the public playbook collection of Schlette et al. (2024),
folders `playbooks/xsoar/` (Cortex XSOAR) and `playbooks/ms_azure/` (Microsoft Sentinel).
Three playbooks were modified on 15 August 2026 by documented structural edits; the
originals are untouched. Convention for every modification: only safeguards (decision
gates, manual paths) are REMOVED; nothing is added.

Labels for every playbook, with a written reason per decision, are in `ground_truth.json`
(conventions listed in its `_note`). Totals: 10 playbooks x 12 constraints
= 120 decisions; 53 labelled as violated (5 introduced by modification, 48 present in the originals).

## rd1_tim_manual_review_unmodified.yml
- Source: TIM_-_Process_Indicators_-_Manual_Review.yml (8 tasks)
- Modification: NONE (control playbook; a feed-processing job with no incident context)

## rd2_eradication_plan_no_gates.yml
- Source: Eradication_Plan.yml (23 tasks reduced to 15)
- Removed: decision conditions 14 ("Should delete the file?"), 15 ("Should terminate the
  process?"), 21 ("Should reset the user's password?"); analyst collection tasks 26, 31, 32;
  manual-path tasks 28, 30
- Rewired: start to automatic file deletion (27) and automatic process termination (29);
  references to 21 to automatic password reset (20)
- Introduces: C01 (all three destructive actions now run unconditionally)

## rd3_search_delete_auto_all_mailboxes.yml
- Source: Search_And_Delete_Emails_-_Generic_v2.yml (17 tasks reduced to 16)
- Removed: manual condition 6 ("Manually decide where to search & delete")
- Rewired: references to 6 to task 7 ("Set all mailboxes to be searched")
- Introduces: C01 (no human decision before mass deletion); C08 (widest scope, all
  mailboxes, by default without stronger gating)

## rd4_handle_fp_full_auto.yml
- Source: Handle_False_Positive_Alerts.yml (17 tasks reduced to 14)
- Removed: condition 2 ("Add the file to the allowed list automatically?"), manual
  exception task 4, condition 9 ("Should close alert automatically?")
- Rewired: references to 2 and 4 to automatic allow-listing (14); references to 9 to
  automatic closure (10)
- Introduces: C01 (protection-weakening allow-list action without approval); C07 (alerts
  always closed automatically; no analyst review path)

## rd5_Block_Account_-_Generic.yml
- Source: xsoar/Block_Account_-_Generic.yml (9 tasks)
- Modification: NONE.

## rd6_Active_Directory_Investigation.yml
- Source: xsoar/Active_Directory_Investigation.yml (10 tasks)
- Modification: NONE

## rd7_Block_IP_-_Generic_v2.yml
- Source: xsoar/Block_IP_-_Generic_v2.yml (24 tasks)
- Modification: NONE

## rd8_BlockADOnPremUser.json
- Source: ms_azure/Block-OnPremADUser/azuredeploy.json (11 tasks)
- Modification: NONE

## rd9_Forcepoint-Block-IP-Nested-Remediation.json
- Source: ms_azure/Remediation-IP/ForcepointNGFW-BlockIP-Nested-Remediation/azuredeploy.json (40 tasks)
- Modification: NONE

## rd10_CiscoASA-CreateInboundAccessRuleOnInterf.json
- Source: ms_azure/CiscoASA/CiscoASA-CreateInboundAccessRuleOnInterface/azuredeploy.json (27 tasks)
- Modification: NONE
