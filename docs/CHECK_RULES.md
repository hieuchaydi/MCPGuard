# MCPGuard Check Rules Reference

Tai lieu nay la "rule catalog" de doc report nhanh va biet cach fix.

## Severity Levels

- `critical`: risk cao nhat, can xu ly ngay
- `high`: risk nghiem trong, nen fix truoc khi cho agent goi tool
- `medium`: quality issue co the gay hanh vi khong on dinh
- `low`: quality gap nho nhung nen harden
- `warning`: canh bao, chua phai fail nghiem trong

## Rule Catalog

## A. Schema Quality Rules

`missing_tool_name` (`medium`)
- Dieu kien: tool khong co ten.
- Goi y fix: dat ten tool ro rang, on dinh.

`missing_description` (`high`)
- Dieu kien: tool khong co description.
- Goi y fix: bo sung mo ta muc dich, dau vao, gioi han.

`description_too_short` (`medium`)
- Dieu kien: description ngan hon `min_description_length`.
- Goi y fix: viet description day du hon.

`missing_input_schema` (`high`)
- Dieu kien: khong co `inputSchema`.
- Goi y fix: khai bao schema day du cho tool.

`no_properties_defined` (`medium`)
- Dieu kien: `inputSchema.properties` thieu/invalid.
- Goi y fix: khai bao properties ro rang.

`missing_required_declaration` (`high`)
- Dieu kien: thieu `inputSchema.required`.
- Goi y fix: danh dau cac field bat buoc trong `required`.

`property_missing_type` (`medium`)
- Dieu kien: property thieu `type` hoac schema property invalid.
- Goi y fix: bo sung `type` cho moi field.

`number_missing_maximum` (`high`)
- Dieu kien: field `number|integer` thieu `maximum` (khi policy yeu cau).
- Goi y fix: dat upper bound.

`number_missing_minimum` (`low`)
- Dieu kien: field `number|integer` thieu `minimum`.
- Goi y fix: dat lower bound.

`string_missing_maxlength` (`low`)
- Dieu kien: field `string` thieu `maxLength`.
- Goi y fix: dat max length phu hop.

`bounded_field_missing_maximum` (`high`)
- Dieu kien: field ten `limit|count|page_size|max` thieu `maximum`.
- Goi y fix: bound cac field de tranh abuse.

`allows_additional_properties` (`warning`)
- Dieu kien: `additionalProperties` khac `false`.
- Goi y fix: set `additionalProperties: false`.

## B. Timeout Rules

`timeout_exceeded` (`high`)
- Dieu kien: tool call vuot `timeout_ms`.
- Goi y fix: toi uu tool logic, I/O, va fallback strategy.

`slow_response` (`warning`)
- Dieu kien: elapsed > `warn_after_ms` nhung chua timeout.
- Goi y fix: profile va cai thien performance.

## C. Fuzz/Runtime Robustness Rules

`fuzz_server_crash` (`critical`)
- Dieu kien: response cho thay server disconnect/crash khi fuzz.
- Goi y fix: validate input va handle exception an toan.

`stack_trace_exposed` (`high`)
- Dieu kien: output/error co dau hieu stack trace noi bo.
- Goi y fix: sanitize error message tra ve cho client.

`poor_error_message` (`medium`)
- Dieu kien: loi qua mo ho/qua ngan/empty.
- Goi y fix: tra ve validation error co nghia, de debug duoc.

`fuzz_timeout` (`high`)
- Dieu kien: fuzz call bi timeout.
- Goi y fix: reject malformed input nhanh hon.

## D. Secret Rules

`secret_leaked` (`critical`)
- Dieu kien: response match secret pattern.
- Goi y fix: mask/redact secret, khong tra raw token/key.

## E. Server-Level Warning Rules

`no_tools_discovered` (`warning`)
- Dieu kien: discovery thanh cong nhung tool list rong.
- Goi y fix: kiem tra register tool va startup logic.

`tool_not_found` (`warning`)
- Dieu kien: dung `--tool` nhung ten tool khong ton tai.
- Goi y fix: doi ten tool cho dung hoac bo `--tool`.

## How to Prioritize Fixing

1. Fix toan bo `critical`.
2. Fix `high` lien quan schema/input bounds/timeout.
3. Giam `medium` de nang do on dinh.
4. Hardening them qua `low` va `warning`.

## Notes

- Rule catalog nay phan anh behavior hien tai cua code.
- Severity + threshold se anh huong truc tiep den exit code khi dung `--fail-on`.
