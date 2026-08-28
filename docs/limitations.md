# Giới hạn của công cụ nhận dạng hash

## 1. Giới hạn về độ dài trùng lặp

`HEX_LENGTH_RULES` ánh xạ độ dài 32 ký tự hex tới danh sách `["MD5", "NTLM", "MD4", "LM"]`. Khi gặp đầu vào là hex 32 ký tự, hàm `identify()` duyệt danh sách này và trả về toàn bộ các thuật toán với độ tin cậy giảm dần (lần lượt `0.55`, `0.27`, `0.18`, `0.13`).

Ví dụ: chuỗi `"5f4dcc3b5aa765d61d8327deb882cf99"` (32 ký tự hex):

- Khớp với độ dài 32 trong `HEX_LENGTH_RULES`.
- Không có prefix, salt hay dấu hiệu đặc trưng nào khác để phân biệt.

Do đó, chương trình phải dựa trên tần suất xuất hiện thực tế để sắp xếp thứ tự ưu tiên, chứ không có cơ sở toán học nào để loại trừ các thuật toán còn lại. Nguyên nhân không thể phân biệt tuyệt đối: cả bốn thuật toán đều sinh ra digest có độ dài là 128 bit.

---

## 2. Xung đột giữa Base32 và Base58

`_is_base32()` và `_is_base58()` đều chỉ kiểm tra charset (tập ký tự hợp lệ), không có cơ chế nào phân biệt sâu hơn — như checksum hay cấu trúc đặc trưng của từng chuẩn mã hóa thật.

Ví dụ: chuỗi `"ABCDEFGHJKLMNPQRSTUVWXYZ234567"` (30 ký tự):

- Không phải hex (chứa `G`, `H`, `J`, `K`...) → không bị loại bởi điều kiện `not _is_hex`.
- Nằm trong khoảng 25–34 ký tự, toàn bộ ký tự thuộc bảng chữ Base58 → thỏa điều kiện Base58.
- Đồng thời toàn bộ ký tự cũng thuộc bảng chữ Base32 (chữ hoa + số 2-7) → thỏa điều kiện Base32.

Vì bước 8 (`identify()`) gộp **tất cả** các nhánh encoding khớp (không dừng ở nhánh đầu tiên như các bước khác), công cụ trả về **cả 2** candidate: Base32 và Base58, cùng confidence `0.30` — không có cách nào phân biệt dứt khoát nếu chỉ dựa vào charset thuần túy.

Đây là giới hạn cố hữu: bảng chữ Base32 (không `0`, `1`, `8`, `9`) và bảng chữ Base58 (không `0`, `O`, `I`, `l`) có phần **giao nhau rất lớn** — bất kỳ chuỗi nào chỉ dùng chữ hoa A-Z và số 2-7 sẽ tự động khớp cả hai.

---

## 3. Giới hạn về phân biệt chữ hoa/thường

Hàm `_is_hex()` sử dụng `HEX_CHARACTERS = "0123456789abcdefABCDEF"` (bao gồm cả hoa và thường) và không lưu trữ trạng thái viết hoa của chuỗi gốc.

Ví dụ: chuỗi `"5f4dcc3b"` và `"5F4DCC3B"`:

- Cả hai đều được `_is_hex()` chấp nhận.
- Công cụ trả về cùng một danh sách `HashCandidate` với các giá trị `algorithm`, `confidence`, `reason` giống hệt nhau.

Dù các hàm băm không phân biệt chữ hoa thường, thực tế một số hệ thống có quy ước riêng (ví dụ: NTLM thường được viết hoa trong môi trường Windows, MySQL thường viết thường). Việc bỏ qua tín hiệu này khiến công cụ bỏ lỡ một gợi ý yếu nhưng có giá trị để điều chỉnh mức độ tin cậy (ví dụ: tăng nhẹ cho NTLM nếu toàn chữ hoa). Hiện tại, công cụ coi cả hai dạng như nhau, dẫn đến việc không tối ưu hóa được độ chính xác dựa trên ngữ cảnh cú pháp.

---

## 4. Giới hạn về Hash bị cắt ngắn

Người dùng nhập 32 ký tự đầu tiên của một SHA-256 hợp lệ: `5e884898da28047151d0e56f8dc62927` (bỏ đi 32 ký tự còn lại).

Ví dụ: đầu vào `"5e884898da28047151d0e56f8dc62927"` (32 ký tự đầu của SHA-256):

- Bước 1 (Prefix): Không khớp.
- Bước 2 (MySQL/DES): Không khớp.
- Bước 3 (Hex length rules): `_is_hex()` = Đúng, `len()` = 32 → Khớp với khóa `32`. Trả về ứng viên `MD5 (0.55)`, `NTLM (0.27)`, `MD4 (0.18)`, `LM (0.13)`.

Công cụ sẽ nhận nhầm một phần của SHA-256 thành một trong các hash 32 ký tự mà không hề đưa ra cảnh báo nào về việc dữ liệu bị cắt ngắn (truncated). Điều này xuất phát từ việc `identify()` phụ thuộc hoàn toàn vào độ dài chính xác để ánh xạ, mà không có cơ chế kiểm tra tính toàn vẹn hoặc ngưỡng độ dài tối thiểu.
