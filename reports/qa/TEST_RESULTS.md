# PhishLens Automated Test Results

## Test Execution Summary
- **Python Runtime**: Python 3.12.10 (AMD64)
- **Framework**: `pytest 9.2.0`, `FastAPI TestClient`, `HTTPX 0.28.1`
- **Execution Mode**: Isolated in-memory SQLite database, ephemeral storage, and clean rate limiter fixtures.

---

## 1. Pytest Suite Execution
```text
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.2.0, pluggy-1.7.0 -- C:\Users\PMLS\Downloads\is_proj\.venv\Scripts\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\PMLS\Downloads\is_proj
plugins: anyio-4.16.0
collecting ... collected 82 items

tests/test_api.py::test_health PASSED                                    [  1%]
tests/test_api.py::test_unauthenticated_request_rejected PASSED          [  2%]
tests/test_api.py::test_wrong_password_generic_error PASSED              [  3%]
tests/test_api.py::test_login_rate_limited PASSED                        [  4%]
tests/test_api.py::test_session_cookie_flags PASSED                      [  6%]
tests/test_api.py::test_logout_invalidates_session PASSED                [  7%]
tests/test_api.py::test_csrf_required_on_state_change PASSED             [  8%]
tests/test_api.py::test_viewer_cannot_upload_and_is_logged PASSED        [  9%]
tests/test_api.py::test_analyst_cannot_access_admin PASSED               [ 10%]
tests/test_api.py::test_malformed_and_oversized_input_rejected PASSED    [ 12%]
tests/test_api.py::test_errors_never_leak_internals PASSED               [ 13%]
tests/test_api.py::test_full_workflow_and_repeated_submission PASSED     [ 14%]
tests/test_api.py::test_viewer_gets_restricted_view PASSED               [ 15%]
tests/test_api.py::test_admin_threshold_change_is_traceable PASSED       [ 17%]
tests/test_api.py::test_dataset_import PASSED                            [ 18%]
tests/test_api.py::test_audit_chain_valid_and_append_only PASSED         [ 19%]
tests/test_api.py::test_audit_redacts_secrets PASSED                     [ 20%]
tests/test_api.py::test_security_headers PASSED                          [ 21%]
tests/test_api.py::test_recovery_after_restart PASSED                    [ 23%]
tests/test_api.py::test_dashboard_for_all_roles PASSED                   [ 24%]
tests/test_api.py::test_password_change_flow PASSED                      [ 25%]
tests/test_engine.py::test_rejects_wrong_extension PASSED                [ 26%]
tests/test_engine.py::test_rejects_oversized_page PASSED                 [ 28%]
tests/test_engine.py::test_rejects_binary_and_non_html PASSED            [ 29%]
tests/test_engine.py::test_rejects_empty_file PASSED                     [ 30%]
tests/test_engine.py::test_safe_filename_strips_paths[../../etc/passwd.html-passwd.html] PASSED [ 31%]
tests/test_engine.py::test_safe_filename_strips_paths[C:\\temp\\a b.html-a_b.html] PASSED [ 32%]
tests/test_engine.py::test_safe_filename_strips_paths[-page.html] PASSED [ 34%]
tests/test_engine.py::test_rejects_bad_urls[javascript:alert(1)] PASSED  [ 35%]
tests/test_engine.py::test_rejects_bad_urls[ftp://x.test/] PASSED        [ 36%]
tests/test_engine.py::test_rejects_bad_urls[http://] PASSED              [ 37%]
tests/test_engine.py::test_rejects_bad_urls[http://a.test/\x00] PASSED   [ 39%]
tests/test_engine.py::test_rejects_bad_urls[url4] PASSED                 [ 40%]
tests/test_engine.py::test_zip_slip_and_labels PASSED                    [ 41%]
tests/test_engine.py::test_zip_bomb_declared_size_rejected PASSED        [ 42%]
tests/test_engine.py::test_registrable_domain PASSED                     [ 43%]
tests/test_engine.py::test_all_features_present_and_numeric PASSED       [ 45%]
tests/test_engine.py::test_external_password_form_detected PASSED        [ 46%]
tests/test_engine.py::test_legit_brand_on_own_domain_not_mismatch PASSED [ 47%]
tests/test_engine.py::test_malformed_html_does_not_crash PASSED          [ 48%]
tests/test_engine.py::test_scripts_are_not_executed PASSED               [ 50%]
tests/test_engine.py::test_rules_fire_with_reasons_and_respect_disable PASSED [ 51%]
tests/test_engine.py::test_benign_page_has_no_critical_warning PASSED    [ 52%]
tests/test_engine.py::test_rules_only_mode_when_no_model PASSED          [ 53%]
tests/test_engine.py::test_r04_no_longer_flags_articles_that_mention_brands PASSED [ 54%]
tests/test_engine.py::test_threshold_change_changes_decision PASSED      [ 56%]
tests/test_engine.py::test_lookalike_and_subdomain_brand[http://paypa1-login.com/x-lookalike_brand_host] PASSED [ 57%]
tests/test_engine.py::test_lookalike_and_subdomain_brand[http://rnicrosoft-support.net/-lookalike_brand_host] PASSED [ 58%]
tests/test_engine.py::test_lookalike_and_subdomain_brand[http://paypal.com.account-check.info/login-brand_in_subdomain] PASSED [ 59%]
tests/test_engine.py::test_real_brand_domains_not_lookalike PASSED       [ 60%]
tests/test_engine.py::test_form_to_ip_and_data_uri PASSED                [ 62%]
tests/test_engine.py::test_forest_explanations_are_exact PASSED          [ 63%]
tests/test_engine.py::test_shipped_model_loads_and_explains PASSED       [ 64%]
tests/test_qa_e2e.py::test_qa_authentication_flows PASSED                [ 65%]
tests/test_qa_e2e.py::test_qa_dashboard_stats PASSED                     [ 67%]
tests/test_qa_e2e.py::test_qa_dataset_import_workflow PASSED             [ 68%]
tests/test_qa_e2e.py::test_qa_html_upload_fixtures PASSED                [ 69%]
tests/test_qa_e2e.py::test_qa_engine_known_cases PASSED                  [ 70%]
tests/test_qa_e2e.py::test_qa_explainability_fields PASSED               [ 71%]
tests/test_qa_e2e.py::test_qa_analyst_feedback PASSED                    [ 73%]
tests/test_qa_e2e.py::test_qa_history_search_and_filter PASSED           [ 74%]
tests/test_qa_e2e.py::test_qa_exports_and_sanitization PASSED            [ 75%]
tests/test_qa_e2e.py::test_qa_admin_capabilities PASSED                  [ 76%]
tests/test_qa_e2e.py::test_qa_viewer_role_restrictions PASSED            [ 78%]
tests/test_security.py::test_xss_payload_is_only_data PASSED             [ 79%]
tests/test_security.py::test_malicious_filename_is_sanitised PASSED      [ 80%]
tests/test_security.py::test_sql_injection_in_filters_is_inert PASSED    [ 81%]
tests/test_security.py::test_csv_formula_injection_neutralised PASSED    [ 82%]
tests/test_security.py::test_brute_force_locks_out_even_correct_password PASSED [ 84%]
tests/test_security.py::test_forged_or_fixated_session_rejected PASSED   [ 85%]
tests/test_security.py::test_csrf_token_from_other_session_rejected PASSED [ 86%]
tests/test_security.py::test_viewer_cannot_export_or_read_raw_samples PASSED [ 87%]
tests/test_security.py::test_unknown_ids_return_generic_404 PASSED       [ 89%]
tests/test_security.py::test_oversized_fields_rejected PASSED            [ 90%]
tests/test_security.py::test_zip_with_too_many_files_rejected PASSED     [ 91%]
tests/test_security.py::test_disabled_user_loses_access_immediately PASSED [ 92%]
tests/test_security.py::test_audit_chain_survives_concurrent_requests PASSED [ 93%]
tests/test_security.py::test_audit_chain_is_keyed PASSED                 [ 95%]
tests/test_security.py::test_malformed_url_is_a_validation_error PASSED  [ 96%]
tests/test_security.py::test_duplicate_upload_uses_new_declared_url PASSED [ 97%]
tests/test_security.py::test_import_with_analysis_respects_rate_limit PASSED [ 98%]
tests/test_security.py::test_corrupt_model_metadata_falls_back_to_rules PASSED [100%]

======================= 82 passed, 1 warning in 19.78s ========================
```

---

## 2. ML Reproduction & Evaluation Results
- **Script**: `scripts/train_from_features.py`
- **Dataset**: `reports/features.csv` (1,400 training samples)
- **Output**:
  ```text
  retrained random_forest on 1400 pages; max |Δp| vs recorded test predictions = 5.00e-06
  saved C:\Users\PMLS\Downloads\is_proj\models\model.joblib (rf-20261115123403)
  ```
- **Holdout Test Set Alignment**: Recorded predictions strictly match within $5 \times 10^{-6}$ numerical tolerance, proving model determinism.
